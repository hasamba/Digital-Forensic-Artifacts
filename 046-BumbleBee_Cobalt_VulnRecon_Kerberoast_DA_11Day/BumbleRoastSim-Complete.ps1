#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BumbleRoastSim-utilities.ps1";Assert-BumbleRoastSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BumbleRoastSim-Phase1-ISO-Cobalt-RDP.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BumbleRoastSim-Phase2-Recon-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BumbleRoastSim-Phase3-Day11-DomainAdmin.ps1" -LabConfirmed:$LabConfirmed;$p=Get-BumbleRoastPaths;Write-BumbleRoastSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
