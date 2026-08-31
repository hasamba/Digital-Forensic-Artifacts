#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BlackSuitSim-utilities.ps1";Assert-BlackSuitSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlackSuitSim-Phase1-BeaconCredentialDiscovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlackSuitSim-Phase2-LateralSystemBCC2.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlackSuitSim-Phase3-CollectionBlackSuit.ps1" -LabConfirmed:$LabConfirmed
$p=Get-BlackSuitPaths;Write-BlackSuitSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
