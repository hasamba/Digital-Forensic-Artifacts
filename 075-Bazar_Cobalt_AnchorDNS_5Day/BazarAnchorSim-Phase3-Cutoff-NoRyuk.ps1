#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarAnchorSim-utilities.ps1"
Assert-BASafety -LabConfirmed:$LabConfirmed
$paths = Initialize-BAEnvironment

Write-BAFile (Join-Path $paths.Evidence 'access-cutoff.json') (@{reportedDay=5;event='Threat actor access cut off before final objectives';bazarC2Available=$false;cobaltC2Available=$false;anchorDnsAvailable=$false;simulationNetworkStateChanged=$false;externalConnections=0} | ConvertTo-Json) containment
Write-BAFile (Join-Path $paths.Evidence 'assessed-final-objective.json') (@{assessment='Likely domain-wide Ryuk ransomware based on Get-DataInfo and observed TTPs';ransomwareObservedInReport=$false;ransomwareCanaryCreated=$false;ransomwareExecuted=$false;payloadStaged=$false;userFilesRead=0;userFilesEncrypted=0;ransomNotesCreated=0;hostsImpaired=0} | ConvertTo-Json) impact
Write-BAFile (Join-Path $paths.Evidence 'phase3-negative.json') (@{securityControlsChanged=$false;networkControlsChanged=$false;malwareRemovedByScenario=$false;logsCleared=0;payloadsDeleted=0;ransomwarePresent=$false;userFilesRead=0;userFilesEncrypted=0;hostsImpaired=0} | ConvertTo-Json) safety
Add-BATimeline 120 containment 'Access is cut off on day five before final objectives' @{reportRelativeTiming=$true;simulationNetworkStateChanged=$false}
Add-BATimeline 120 impact 'Assessed Ryuk objective remains an explicit non-event' @{ransomwareObserved=$false;ransomwareExecuted=$false;userFilesEncrypted=0;hostsImpaired=0}
