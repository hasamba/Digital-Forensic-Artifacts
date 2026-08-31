#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\PhosphorusSim-utilities.ps1"
Assert-PhosphorusSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-PhosphorusSimEnvironment

$shellTwo = Join-Path $paths.WebRoot 'aspx_dyukbdcxjfi.aspx'
Write-PhosphorusSimFile $shellTwo '<%-- INERT SECOND WEB-SHELL-NAME CANARY. Contains no executable server code. --%>' 'second web shell name canary'
Write-PhosphorusSimFile (Join-Path $paths.WebRoot 'dhvqx.aspx') '<%-- INERT PUBLISHED WEB-SHELL-NAME CANARY. Contains no executable server code. --%>' 'published web shell name canary'
Write-PhosphorusSimFile (Join-Path $paths.Evidence 'second-automated-burst.json') (@{
    offsetHours = 48
    durationMinutes = 2
    subjectMarker = 'aspx_dyukbdcxjfi'
    reportedPath = '\\localhost\c$\inetpub\wwwroot\aspnet_client\system_web\aspx_dyukbdcxjfi.aspx'
    mailboxExportRequestExecuted = $false
    webShellCreated = $false
    postRequestsSent = 0
    conclusion = 'Actor evicted before further impact; report assesses likely ransomware outcome with medium-high confidence.'
} | ConvertTo-Json -Depth 5) 'second automated burst record'

$dllhost = Join-Path $paths.Windows 'dllhost.exe'
if (-not (Test-Path -LiteralPath $dllhost)) { New-PhosphorusSimDecoy $dllhost 'modified-Go-FRP stand-in' '1604e69d17c0f26182a3e3ff65694a49450aafd56a7e8b21697a932409dfd81e' }
Invoke-PhosphorusSimDecoy $dllhost 'Second automated two-minute ProxyShell/web-shell/FRP sequence' 'w3wp.exe'
Invoke-PhosphorusSimLoopback 443 'tcp443.msupdate.us / 107.173.231.114 (second burst)' 'reported FRP C2'
Write-PhosphorusSimFile (Join-Path $paths.Evidence 'second-burst-negative-record.json') (@{
    exploitRequestsSent = 0
    exchangeOperations = 0
    webShellsCreated = 0
    remoteConnections = 0
    ransomwareExecuted = $false
    userDataModified = 0
    impactOccurred = $false
} | ConvertTo-Json) 'phase safety record'
Add-PhosphorusSimTimeline 48 'initial-access' 'Nearly identical second automated ProxyShell and web-shell burst represented two days later' @{ durationMinutes = 2; exploitRequestsSent = 0; webShellsCreated = 0 }
Add-PhosphorusSimTimeline 72 'impact' 'Eviction before impact; probable ransomware outcome remains an assessment only' @{ ransomwareExecuted = $false; impactOccurred = $false }
