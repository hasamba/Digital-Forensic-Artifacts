#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ZeroQbotSim-utilities.ps1"
Assert-ZeroQbotSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-ZeroQbotSimEnvironment

Write-ZeroQbotSimFile (Join-Path $paths.Payloads 'initial-qbot.dll') 'INERT INITIAL QBOT DLL-NAME CANARY. Not a PE file.' 'initial Qbot canary'
Write-ZeroQbotSimFile (Join-Path $paths.Payloads 'Fdopitcu\Terfrtghygine.dll') 'INERT REGISTRY-EXTRACTED QBOT DLL-NAME CANARY. Not a PE file.' 'second Qbot canary'
Write-ZeroQbotSimFile (Join-Path $paths.Registry 'HKCU_SOFTWARE_Pvoeooxf.json') (@{
    reportedValues = @('base64 Qbot DLL', 'semicolon-delimited Qbot C2 IPs', 'obfuscated PowerShell loader', 'first-execution date checked against four-hour threshold')
    valuesWritten = 0
    payloadDecoded = $false
    payloadFetched = $false
} | ConvertTo-Json -Depth 5) 'registry persistence canary'
Write-ZeroQbotSimFile (Join-Path $paths.Registry 'HKCU_Software_Microsoft_Yerqbqokc.json') (@{ reportedValues = 'eight-character encrypted configuration strings'; valuesWritten = 0 } | ConvertTo-Json) 'Qbot configuration canary'
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'scheduled-task.json') (@{
    name = '{97F2F70B-10D1-4447-A2F3-9B070C86E261}'
    intervalMinutes = 30
    reportedAction = 'cmd /c start /min powershell -Command IEX(ASCII.GetString(FromBase64String(Get-ItemProperty HKCU:\SOFTWARE\Pvoeooxf)))'
    taskCreated = $false
} | ConvertTo-Json) 'scheduled task telemetry'

$regsvr32 = Join-Path $paths.Payloads 'regsvr32.exe'
New-ZeroQbotSimDecoy $regsvr32 'Qbot DLL execution stand-in' '4d3b10b338912e7e1cbade226a1e344b2b4aebc1aa2297ce495e27b2b0b5c92b'
Invoke-ZeroQbotSimDecoy $regsvr32 'regsvr32.exe /s %APPDATA%\Roaming\Microsoft\Fdopitcu\<unsigned-Qbot>.dll' 'powershell.exe'
foreach ($target in @('24.229.150.54:995 / avlhestito.us', '41.228.22.180:443 / xrhm.info')) { Invoke-ZeroQbotSimLoopback 443 $target 'Qbot C2 marker' }
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'qbot-negative-record.json') (@{ registryValuesWritten = 0; scheduledTasksCreated = 0; webRequestsSent = 0; malwareExecuted = $false; processesInjected = 0; remoteConnections = 0; bytesTransferred = 0 } | ConvertTo-Json) 'phase safety record'
Add-ZeroQbotSimTimeline 0 'initial-access' 'Initial malicious Qbot DLL execution represented' @{ malwareExecuted = $false }
Add-ZeroQbotSimTimeline 0.0833 'execution' 'First Qbot activity and automated system/network/share/privilege discovery represented five minutes later' @{ discoveryCommandsExecuted = 0 }
Add-ZeroQbotSimTimeline 0.15 'persistence' 'Registry-backed Qbot DLL, PowerShell loader, and 30-minute scheduled task represented' @{ registryWrites = 0; tasksCreated = 0 }
Add-ZeroQbotSimTimeline 0.2 'defense-evasion' 'Qbot explorer.exe process hollowing and subsequent Cobalt injection represented' @{ processesInjected = 0 }
