#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ContiBazarSim-utilities.ps1";Assert-ContiBazarSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ContiBazarSim-Phase1-Bazar-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ContiBazarSim-Phase2-RDP-Rclone.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ContiBazarSim-Phase3-Conti-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ContiBazarPaths;Write-ContiBazarSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
