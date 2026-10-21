# Creates only a desktop shortcut; no network or system settings are changed.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$desktop = [Environment]::GetFolderPath('Desktop')
if (-not $desktop -or -not (Test-Path -LiteralPath $desktop)) { throw 'Desktop folder unavailable.' }
$path = Join-Path $desktop 'Network Check.lnk'
if (Test-Path -LiteralPath $path) { throw 'Network Check.lnk already exists; leave it intact.' }
$shell = New-Object -ComObject WScript.Shell
try {
    $shortcut = $shell.CreateShortcut($path)
    $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'network-check.ps1') + '" -Interactive'
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = 'One-shot read-only network observations'
    $shortcut.Save()
} finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
Write-Host 'Created Network Check desktop shortcut. Keep the repository at its current location.'
