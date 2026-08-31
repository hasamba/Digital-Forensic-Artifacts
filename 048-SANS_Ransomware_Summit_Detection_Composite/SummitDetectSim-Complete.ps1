#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SummitDetectSim-utilities.ps1"
Assert-SummitDetectSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SummitDetectSim-Phase1-Delivery-Persistence.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SummitDetectSim-Phase2-Credentials-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SummitDetectSim-Phase3-Movement-Exfil-BYOT.ps1" -LabConfirmed:$LabConfirmed
$p = Get-SummitDetectPaths
Write-SummitDetectSummary $p
Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
