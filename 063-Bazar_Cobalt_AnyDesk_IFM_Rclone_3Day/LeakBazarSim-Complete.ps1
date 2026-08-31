#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\LeakBazarSim-utilities.ps1";Assert-LeakBazarSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LeakBazarSim-Phase1-Bazar-Cobalt-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LeakBazarSim-Phase2-RDP-Accounts-IFM.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LeakBazarSim-Phase3-Rclone-Eviction.ps1" -LabConfirmed:$LabConfirmed;$p=Get-LeakBazarPaths;Write-LeakBazarSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
