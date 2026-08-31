#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\OpenDirActorSim-utilities.ps1";Assert-OpenDirSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OpenDirActorSim-Phase1-ReconInfrastructure.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OpenDirActorSim-Phase2-ExploitationFrameworks.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OpenDirActorSim-Phase3-PostExPersistence.ps1" -LabConfirmed:$LabConfirmed
$p=Get-OpenDirPaths;Write-OpenDirSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
