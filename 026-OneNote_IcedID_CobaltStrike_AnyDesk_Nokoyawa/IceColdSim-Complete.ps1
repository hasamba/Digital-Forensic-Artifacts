#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IceColdSim-utilities.ps1";Assert-IceColdSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IceColdSim-Phase1-OneNoteIcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IceColdSim-Phase2-HandsOnExfil.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IceColdSim-Phase3-NokoyawaImpact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-IceColdPaths;Write-IceColdSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
