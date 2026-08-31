#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ZeroQbotSim-utilities.ps1"
Assert-ZeroQbotSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-ZeroQbotSimEnvironment

$serviceTool = Join-Path $paths.Payloads 'psexec_psh.exe'
New-ZeroQbotSimDecoy $serviceTool 'Cobalt psexec_psh stand-in'
foreach ($hostName in @('DOMAIN-CONTROLLER-01', 'FILE-SERVER-01', 'DOMAIN-CONTROLLER-02')) {
    $hostRoot = Join-Path $paths.Hosts $hostName
    New-Item -Path $hostRoot -ItemType Directory -Force | Out-Null
    Write-ZeroQbotSimFile (Join-Path $hostRoot 'service-7045.json') (@{ serviceNames = @('3141131', 'af5ff02', 'c46234f'); reportedImagePath = '%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand <redacted>'; serviceCreated = $false } | ConvertTo-Json) 'remote service telemetry'
    Write-ZeroQbotSimFile (Join-Path $hostRoot 'rdp-4624-type10.json') (@{ logonType = 10; interactiveSessionEstablished = $false; registryOrServiceChanges = 0 } | ConvertTo-Json) 'RDP telemetry'
}
foreach ($command in @(
    'OpenSCManagerW + StartServiceA; psexec_psh service beacon on multiple hosts',
    'REG ADD Terminal Server RDP values; sc config termservice start= auto; net start termservice',
    'interactive administrative RDP logon type 10',
    'SMB beacon named pipe dce_3d'
)) { Invoke-ZeroQbotSimDecoy $serviceTool $command 'Cobalt Strike beacon' }
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'dce_3d.named-pipe-marker') 'NAMED-PIPE NAME CANARY ONLY. No named pipe was created.' 'SMB beacon canary'

foreach ($name in @('Financial Statements.xlsx', 'Ransomware Reports.docx', 'Salary Data.xlsx')) {
    Write-ZeroQbotSimFile (Join-Path $paths.Staging $name) "GENERATED CANARY DOCUMENT: $name. Contains no real or sensitive data." 'collection canary'
}
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'canary-open-alerts.json') (@{ alertCount = 3; reportedSource = '91.193.182.165'; realExternalOpens = 0; documentContents = 'generated canary only' } | ConvertTo-Json) 'reported canary alerts'
foreach ($target in @('5.255.98.144:8888 / dxabt.com', '5.255.98.144:443 / dxabt.com', '5.255.98.144:8080 / dxabt.com', '91.193.182.165 canary-open source')) { Invoke-ZeroQbotSimLoopback 443 $target 'Cobalt/exfiltration marker' }
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'pivot-exfil-negative-record.json') (@{ servicesCreated = 0; RdpRegistryValuesChanged = 0; servicesChanged = 0; rdpSessions = 0; namedPipesCreated = 0; remoteHostsTouched = 0; realDocumentsCollected = 0; bytesExfiltrated = 0 } | ConvertTo-Json) 'phase safety record'
Add-ZeroQbotSimTimeline 4 'lateral-movement' 'Cobalt psexec_psh service beacons deployed to a file server and two DCs represented on generated hosts' @{ servicesCreated = 0; remoteHostsTouched = 0 }
Add-ZeroQbotSimTimeline 8 'lateral-movement' 'RDP registry/service enablement, type-10 sessions, and dce_3d SMB pipe represented' @{ systemChanges = 0; sessions = 0; namedPipes = 0 }
Add-ZeroQbotSimTimeline 17.5833 'collection' 'File-server beacon at reported 17:35 point and interest in financial/ransomware/salary documents represented' @{ realDocumentsCollected = 0 }
Add-ZeroQbotSimTimeline 17.8667 'exfiltration' 'Encrypted Cobalt C2 exfiltration window begins at reported 17:52 point' @{ bytesTransferred = 0 }
Add-ZeroQbotSimTimeline 18 'exfiltration' 'Reported exfiltration window ends at 18:00; actor later evicted before further objectives' @{ bytesTransferred = 0; remoteConnections = 0 }
