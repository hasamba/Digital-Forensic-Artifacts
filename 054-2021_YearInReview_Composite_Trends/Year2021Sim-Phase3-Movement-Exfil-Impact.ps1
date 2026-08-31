#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Year2021Sim-utilities.ps1"
Assert-Year2021SimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-Year2021SimEnvironment

$psexec = Join-Path $paths.Tooling 'PsExec.exe'
$rclone = Join-Path $paths.Tooling 'rclone.exe'
New-Year2021SimDecoy $psexec 'lateral-movement telemetry stand-in'
New-Year2021SimDecoy $rclone 'exfiltration telemetry stand-in'
foreach ($command in @(
    'Remote Desktop movement toward domain controllers and file servers',
    'WMIC /node:<remote> process call create <transferred-binary>',
    'PsExec remote service execution',
    'Cobalt Strike beacon-to-beacon lateral movement'
)) { Invoke-Year2021SimDecoy $psexec $command 'Cobalt Strike beacon' }
foreach ($command in @(
    'Rclone transfer of staged data',
    'FileZilla or WinSCP transfer to actor-controlled server',
    'Cobalt Strike download of sensitive data',
    'ufile.io upload of a domain-controller LSASS dump in the Diavol case'
)) { Invoke-Year2021SimDecoy $rclone $command 'hands-on-keyboard operator' }

for ($case = 1; $case -le 6; $case++) {
    $lane = Join-Path $paths.Cases ('case-{0:d2}' -f $case)
    Write-Year2021SimFile (Join-Path $lane 'exfiltration-observation.json') (@{ syntheticLane = $case; aggregateExfiltrationCase = $true; realCollection = $false; bytesExfiltrated = 0; mappingIsObservedCaseCorrelation = $false } | ConvertTo-Json) 'aggregate exfiltration marker'
}
foreach ($hostName in @('WORKSTATION-01', 'SERVER-01', 'FILE-01', 'DOMAIN-CONTROLLER-CANARY')) {
    $hostRoot = Join-Path $paths.Impact $hostName
    foreach ($name in @('Finance.xlsx', 'Operations.docx')) {
        $original = Join-Path $hostRoot $name
        Write-Year2021SimFile $original "GENERATED ORIGINAL $hostName/$name remains intact." 'impact source canary'
        Write-Year2021SimFile "$original.ransomware-marker" 'RANSOMWARE OUTCOME MARKER ONLY. The generated original is unchanged.' 'impact marker'
    }
    Write-Year2021SimFile (Join-Path $hostRoot 'xmrig-miner.marker') 'CRYPTOMINER OUTCOME MARKER ONLY. No miner or computation.' 'miner marker'
}
Invoke-Year2021SimLoopback 3389 'aggregate Remote Desktop targets' 'lateral movement marker'
Invoke-Year2021SimLoopback 445 'aggregate WMI/PsExec/SMB targets' 'lateral movement marker'
Invoke-Year2021SimLoopback 443 'ufile.io and aggregate Rclone/FileZilla/WinSCP/Cobalt Strike destinations' 'exfiltration marker'
Write-Year2021SimFile (Join-Path $paths.Evidence 'movement-exfil-impact-negative-record.json') (@{
    aggregateExfiltrationCases = 6
    rdpSessions = 0
    remoteWmiExecutions = 0
    psexecServicesCreated = 0
    remoteHostsTouched = 0
    realFilesCollected = 0
    archivesCreated = 0
    bytesExfiltrated = 0
    minersExecuted = 0
    filesEncrypted = 0
    ransomNotesDeployed = 0
} | ConvertTo-Json) 'phase safety record'
Add-Year2021SimTimeline 18 'lateral-movement' 'Cobalt Strike, RDP, remote WMI, and PsExec movement trends represented' @{ remoteHostsTouched = 0; remoteExecutions = 0 }
Add-Year2021SimTimeline 21 'exfiltration' 'Six-of-twenty exfiltration trend using Rclone, FileZilla, WinSCP, Cobalt Strike, and ufile.io represented' @{ aggregateCases = 6; filesCollected = 0; bytesTransferred = 0 }
Add-Year2021SimTimeline 24 'impact' 'Domain-wide ransomware and two cryptominer outcomes represented with intact generated canaries' @{ malwareExecuted = $false; filesEncrypted = 0 }
