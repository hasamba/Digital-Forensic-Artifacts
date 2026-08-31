#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\NitrogenSim-utilities.ps1"
Assert-NitrogenSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NitrogenSim-Phase1-InitialC2Persistence.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NitrogenSim-Phase2-CredentialLateralExfil.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NitrogenSim-Phase3-BlackCatImpact.ps1" -LabConfirmed:$LabConfirmed
$p = Get-NitrogenPaths
Write-NitrogenSummary $p
Write-Host "Scenario complete. Evidence remains at $($p.Root). Run Cleanup-NitrogenSim.ps1 separately when investigation is finished."
