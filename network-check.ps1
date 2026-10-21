# Standalone read-only adaptation of vpn-leak-audit.ps1.
# Copyright (c) 2026 Mr-Salticidae. MIT license: see LICENSE.
[CmdletBinding()]
param([switch]$Interactive, [switch]$NoDnsTest,
      [string]$ReportDirectory = '',
      [switch]$LibraryOnly)

$ErrorActionPreference = 'Stop'
if (-not $ReportDirectory) { $ReportDirectory = Join-Path $PSScriptRoot '.network-check/reports' }

function New-Observation([string]$Check, [string]$Status, [string]$Evidence) {
    [pscustomobject]@{ Check = $Check; Status = $Status; Evidence = $Evidence }
}

function Compare-ObservedIp([string]$First, [string]$Second) {
    if (-not $First -or -not $Second) {
        return New-Observation 'Request paths' 'UNKNOWN' 'Incomplete IP observations; no path comparison possible.'
    }
    if ($First -eq $Second) {
        return New-Observation 'Request paths' 'PASS' 'The two requests observed the same IP. This does not establish tunnel coverage or application behaviour.'
    }
    New-Observation 'Request paths' 'WARNING' 'The two requests observed different IPs. Rules, address rotation or bypass are possible; leakage is not established.'
}

function Get-DnsObservation([string]$ExitCountry, [object[]]$Resolvers) {
    if (-not $Resolvers -or $Resolvers.Count -eq 0) {
        return New-Observation 'DNS test' 'UNKNOWN' 'No resolver observations returned. Timeout, caching or test failure are possible; this is not proof of protection.'
    }
    foreach ($resolver in $Resolvers) {
        $status = 'UNKNOWN'
        $comparison = 'Country comparison unavailable.'
        if ($ExitCountry -and $resolver.country) {
            if ($ExitCountry -eq $resolver.country) {
                $comparison = 'Country matches exit observation; this does not prove DNS used the tunnel.'
            } else {
                $status = 'WARNING'
                $comparison = 'Country differs from exit observation; geography alone does not establish a leak.'
            }
        }
        New-Observation 'DNS resolver' $status ("{0}; country={1}; ASN={2}. {3}" -f $resolver.ip, $resolver.country, $resolver.asn, $comparison)
    }
}

function Get-RouteObservation([string]$Interface, [bool]$TunnelLike) {
    if (-not $Interface) { return New-Observation 'Route to 1.1.1.1' 'UNKNOWN' 'Route lookup failed or returned no interface.' }
    New-Observation 'Route to 1.1.1.1' 'PASS' ("Selected interface: {0}; tunnel-like name: {1}. Only this destination was queried; no claim about other routes, UDP, WebRTC or running applications." -f $Interface, $TunnelLike)
}

function Get-HttpObservation([string]$Name, [int]$Code) {
    if ($Code -ge 200 -and $Code -lt 400) {
        return New-Observation $Name 'PASS' "HTTP $Code received. Unauthenticated reachability only; account access and health are untested."
    }
    if ($Code -ge 400 -and $Code -le 599) {
        return New-Observation $Name 'FAILURE' "HTTP $Code received: request denied or server error. HTTP transport responded; this is not an account-health verdict."
    }
    New-Observation $Name 'UNKNOWN' 'No valid HTTP response. Transport failure, timeout or probe failure; account access is unknown.'
}

function Get-ValidIp([object]$Value, [int]$Family = 0) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$Value, [ref]$parsed)) { return '' }
    if ($Family -eq 4 -and $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return '' }
    if ($Family -eq 6 -and $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return '' }
    return $parsed.ToString()
}

function Invoke-CheckJson([string]$Uri) {
    try { Invoke-RestMethod -Uri $Uri -TimeoutSec 8 -ErrorAction Stop } catch { return $null }
}

function Invoke-DirectIp([int]$Family) {
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { return '' }
    $endpoint = 'https://api.ipify.org?format=json'
    if ($Family -eq 6) { $endpoint = 'https://api6.ipify.org?format=json' }
    try {
        # Ignore curl config and explicit proxies, but retain the OS routes (including any tunnel).
        $raw = & curl.exe -q "-$Family" --silent --fail --max-time 8 --noproxy '*' $endpoint 2>$null
        if ($LASTEXITCODE -ne 0) { return '' }
        $data = ($raw -join '') | ConvertFrom-Json -ErrorAction Stop
        Get-ValidIp $data.ip $Family
    } catch { return '' }
}

function Invoke-ResolverCheck([string]$ExitCountry) {
    # Same bash.ws mechanism as the upstream audit, bounded and without child processes.
    $id = Invoke-CheckJson 'https://bash.ws/id'
    if ("$id" -notmatch '^\d{1,20}$') { return Get-DnsObservation $ExitCountry @() }
    foreach ($number in 1..6) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://$number.$id.bash.ws" -TimeoutSec 2 -ErrorAction Stop | Out-Null
        } catch { }
    }
    $response = Invoke-CheckJson "https://bash.ws/dnsleak/test/$id`?json"
    $resolvers = @($response | Where-Object { $_.type -eq 'dns' -and (Get-ValidIp $_.ip) })
    Get-DnsObservation $ExitCountry $resolvers
}

function Invoke-NetworkCheck {
    # Each local read has its own error boundary so missing cmdlets never become a clean bill of health.
    try {
        $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        New-Observation 'Windows proxy' 'PASS' ("Settings read: enabled={0}; server configured={1}; PAC configured={2}. Values omitted to avoid credentials; applications may use different settings." -f ($proxy.ProxyEnable -eq 1), [bool]$proxy.ProxyServer, [bool]$proxy.AutoConfigURL)
    } catch { New-Observation 'Windows proxy' 'UNKNOWN' 'Settings could not be read.' }
    foreach ($scope in 'Process','User','Machine') {
        $names = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY' | Where-Object { [Environment]::GetEnvironmentVariable($_, $scope) })
        New-Observation "Proxy environment ($scope)" 'PASS' ("Configured variable names: {0}. Values omitted; no inference about existing processes." -f ($names -join ', '))
    }
    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
        if ($adapters.Count -eq 0) { New-Observation 'Adapters' 'UNKNOWN' 'No up adapters returned.' }
        foreach ($adapter in $adapters) {
            New-Observation 'Up adapter' 'PASS' ("{0}; {1}" -f $adapter.Name, $adapter.InterfaceDescription)
        }
    } catch { New-Observation 'Adapters' 'UNKNOWN' 'Adapter enumeration failed.' }
    $route = ''
    try { $route = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction Stop | Select-Object -ExpandProperty InterfaceAlias -First 1 } catch { }
    $tunnels = @($adapters | Where-Object { $_.Name -match 'tun|tap|wireguard|meta|mihomo|sing-?box' -or $_.InterfaceDescription -match 'tun|tap|wireguard|meta|mihomo|sing-?box' })
    Get-RouteObservation $route ($route -in $tunnels.Name)
    try {
        $routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') })
        if (-not $routes) { New-Observation 'Default routes' 'UNKNOWN' 'No default routes returned; split routes may still exist.' }
        foreach ($r in $routes) { New-Observation 'Default route' 'PASS' ("{0} via {1}; interface={2}; route metric={3}" -f $r.DestinationPrefix, $r.NextHop, $r.InterfaceAlias, $r.RouteMetric) }
    } catch { New-Observation 'Default routes' 'UNKNOWN' 'Route enumeration failed.' }

    $normal = Invoke-CheckJson 'https://api.ipify.org?format=json'
    $normalIp = Get-ValidIp $normal.ip 4
    if ($normalIp) { New-Observation 'PowerShell HTTP IPv4' 'PASS' "Observed $normalIp from api.ipify.org using this PowerShell request path." }
    else { New-Observation 'PowerShell HTTP IPv4' 'UNKNOWN' 'No valid IPv4 response; failed, malformed or timed out.' }
    $country = ''
    if ($normalIp) {
        # Reuse ip-api metadata from the audit. Its free HTTP endpoint is unauthenticated evidence.
        $geo = Invoke-CheckJson "http://ip-api.com/json/$normalIp`?fields=status,query,country,countryCode,isp,as,hosting,proxy"
        if ($geo.status -eq 'success' -and $geo.query -eq $normalIp) {
            $country = $geo.countryCode
            New-Observation 'IP metadata' 'UNKNOWN' ("Provider reports country={0}; ISP={1}; ASN={2}; hosting={3}; proxy={4}. HTTP metadata may be inaccurate; ASN and provider flags do not establish residential status or safety." -f $geo.country, $geo.isp, $geo.as, $geo.hosting, $geo.proxy)
        } else { New-Observation 'IP metadata' 'UNKNOWN' 'Metadata lookup failed or returned a different IP.' }
    } else { New-Observation 'IP metadata' 'UNKNOWN' 'No IPv4 reference for metadata lookup.' }
    $direct = Invoke-DirectIp 4
    if ($direct) { New-Observation 'Proxy-bypassed curl IPv4' 'PASS' "Observed $direct. Explicit proxies bypassed; OS routing retained. This is not a probe of a running agent or browser." }
    else { New-Observation 'Proxy-bypassed curl IPv4' 'UNKNOWN' 'No valid IPv4 result (curl unavailable, failed or timed out).' }
    Compare-ObservedIp $normalIp $direct
    $v6 = Invoke-DirectIp 6
    if ($v6) { New-Observation 'Proxy-bypassed curl IPv6' 'PASS' "Observed $v6 on a forced IPv6 request. Tunnel coverage and leakage remain unknown." }
    else { New-Observation 'Proxy-bypassed curl IPv6' 'UNKNOWN' 'No valid IPv6 result. This does not prove IPv6 is disabled or protected.' }

    New-Observation 'Locale (information)' 'PASS' ("System timezone={0}; culture={1}. No account-suspension prediction; browser settings may differ." -f [TimeZoneInfo]::Local.Id, (Get-Culture).Name)
    try {
        $dns = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses.Count -gt 0 })
        if (-not $dns) { New-Observation 'Configured DNS' 'UNKNOWN' 'No DNS server addresses returned.' }
        foreach ($d in $dns) { New-Observation 'Configured DNS' 'PASS' ("{0}: {1}. Configuration only, not proof these resolvers handled a query." -f $d.InterfaceAlias, ($d.ServerAddresses -join ', ')) }
    } catch { New-Observation 'Configured DNS' 'UNKNOWN' 'DNS configuration could not be read.' }
    if ($NoDnsTest) { New-Observation 'DNS test' 'UNKNOWN' 'Active resolver test skipped by request.' }
    else { Invoke-ResolverCheck $country }
    foreach ($endpoint in @('https://api.openai.com/v1/models','https://api.anthropic.com/v1/messages')) {
        $code = 0
        try {
            $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 0 -ErrorAction Stop
            $code = [int]$response.StatusCode
        } catch {
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        }
        Get-HttpObservation $endpoint $code
    }
    New-Observation 'Browser WebRTC' 'UNKNOWN' 'Not tested by this shell. Open the separate browser check in the browser/profile you intend to use.'
}

function Format-NetworkReport([object[]]$Observations) {
    $lines = @('Standalone network check', ('Generated: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')),
        'One-shot observations, not a safety certification. PASS means the stated observation succeeded.',
        'FAILURE = HTTP denial/server error; WARNING = discrepancy; UNKNOWN = inconclusive or untested.',
        'Local report contains IPs, DNS addresses and adapter names. Review before sharing.',
        'Requests contact ipify, ip-api, bash.ws (unless skipped), OpenAI and Anthropic. No credentials sent.',
        'Bandwidth test omitted. No settings changed. Browser and running application behaviour are separately scoped.', '')
    foreach ($o in $Observations) { $lines += '[{0}] {1}: {2}' -f $o.Status, $o.Check, $o.Evidence }
    $lines -join [Environment]::NewLine
}

if ($LibraryOnly) { return }
do {
    Write-Host 'Checking network (one shot, bounded requests; usually under two minutes)...'
    $observations = @(Invoke-NetworkCheck)
    $report = Format-NetworkReport $observations
    Write-Host $report
    try {
        [void][IO.Directory]::CreateDirectory($ReportDirectory)
        $path = Join-Path $ReportDirectory ('network-check-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.txt')
        [IO.File]::WriteAllText($path, $report, (New-Object Text.UTF8Encoding($true)))
        Write-Host "Report saved: $path"
    } catch { Write-Warning 'Report could not be saved. The results remain in this window; copy is available.' }
    if (-not $Interactive) { break }
    do {
        $choice = Read-Host '[R]erun / [C]opy full report / [W]ebRTC browser check / [Q]uit'
        if ($choice -eq 'c') {
            try { Set-Clipboard -Value $report -ErrorAction Stop; Write-Host 'Copied full local report (includes IP/DNS details).' }
            catch { Write-Warning 'Clipboard unavailable; use the saved report.' }
        }
        if ($choice -eq 'w') {
            try { Start-Process (Join-Path $PSScriptRoot 'webrtc-leak-test.html') -ErrorAction Stop }
            catch { Write-Warning 'Could not open browser check; open webrtc-leak-test.html manually.' }
        }
    } while ($choice -notin @('r','q'))
} while ($choice -eq 'r')
