# Synthetic regression tests; no real network or system changes.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'network-check.ps1') -LibraryOnly
$script:count = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:count++
}
Assert ((Compare-ObservedIp '' '192.0.2.1').Status -eq 'UNKNOWN') 'Missing IP must be unknown'
Assert ((Compare-ObservedIp '192.0.2.1' '192.0.2.2').Status -eq 'WARNING') 'Different IPs are not proof of leakage'
Assert ((Compare-ObservedIp '192.0.2.1' '192.0.2.1').Evidence -match 'does not establish') 'Same IP is not coverage'
Assert ((Get-DnsObservation 'US' @()).Status -eq 'UNKNOWN') 'Empty DNS must be unknown'
$resolver = [pscustomobject]@{ ip='192.0.2.53'; country='DE'; asn='AS64500' }
Assert ((Get-DnsObservation 'US' @($resolver)).Status -eq 'WARNING') 'Country disagreement must not be failure'
Assert ((Get-DnsObservation 'DE' @($resolver)).Status -eq 'UNKNOWN') 'Country match is not proof of protection'
Assert ((Get-DnsObservation '' @($resolver)).Status -eq 'UNKNOWN') 'Missing exit country'
$resolver.country = ''
Assert ((Get-DnsObservation 'US' @($resolver)).Status -eq 'UNKNOWN') 'Missing resolver country'
Assert ((Get-RouteObservation '' $false).Status -eq 'UNKNOWN') 'Missing route'
Assert ((Get-RouteObservation 'TestTunnel' $true).Evidence -match 'Only this destination') 'Tunnel scope'
foreach ($code in @(0, 100, 600)) { Assert ((Get-HttpObservation 'test' $code).Status -eq 'UNKNOWN') 'No valid HTTP response' }
foreach ($code in @(200, 302)) { Assert ((Get-HttpObservation 'test' $code).Status -eq 'PASS') 'HTTP response' }
foreach ($code in @(401, 403, 429, 500)) { Assert ((Get-HttpObservation 'test' $code).Status -eq 'FAILURE') 'HTTP denial/error' }
Assert ((Get-ValidIp 'garbage') -eq '') 'Malformed IP'
Assert ((Get-ValidIp '2001:db8::1' 4) -eq '') 'Wrong family'
Assert ((Get-ValidIp '2001:db8::1' 6) -eq '2001:db8::1') 'IPv6 fixture'
# A fresh -File invocation catches PS5.1 parameter-default/PSScriptRoot differences
# that dot-sourcing from this test script cannot reveal.
$entry = Join-Path (Split-Path $PSScriptRoot -Parent) 'network-check.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entry -LibraryOnly
Assert ($LASTEXITCODE -eq 0) 'Fresh PS5.1 entry point must initialize without network access'

# Exercise the full collector with failed network probes and missing Windows APIs.
function Invoke-CheckJson { return $null }
function Invoke-DirectIp { return '' }
function Get-NetAdapter { throw 'fixture unavailable' }
function Find-NetRoute { throw 'fixture unavailable' }
function Get-NetRoute { throw 'fixture unavailable' }
function Get-DnsClientServerAddress { throw 'fixture unavailable' }
function Get-ItemProperty { throw 'fixture unavailable' }
function Invoke-WebRequest { throw 'fixture timeout' }
$observations = @(Invoke-NetworkCheck)
foreach ($name in @('Windows proxy','Adapters','Route to 1.1.1.1','Default routes','PowerShell HTTP IPv4','IP metadata','Proxy-bypassed curl IPv4','Proxy-bypassed curl IPv6','Configured DNS','DNS test','https://api.openai.com/v1/models','https://api.anthropic.com/v1/messages')) {
    $row = @($observations | Where-Object { $_.Check -eq $name })
    Assert ($row.Count -eq 1 -and $row[0].Status -eq 'UNKNOWN') "Failed probe must be unknown: $name"
}
$report = Format-NetworkReport $observations
Assert ($report -match 'Generated:' -and $report -match 'not a safety certification') 'Timestamp and scope in report'
foreach ($file in @('network-check.ps1','tests/verify-network-check.ps1','install-network-check-shortcut.ps1')) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path (Split-Path $PSScriptRoot -Parent) $file))
    Assert ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) "BOM required: $file"
}
Write-Host "network-check: $script:count assertions passed (PowerShell $($PSVersionTable.PSVersion))"
