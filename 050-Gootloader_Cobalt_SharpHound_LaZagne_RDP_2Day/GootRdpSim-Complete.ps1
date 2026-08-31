#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GootRdpSim-utilities.ps1";Assert-GootRdpSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GootRdpSim-Phase1-SEO-Gootloader.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GootRdpSim-Phase2-Discovery-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GootRdpSim-Phase3-RDP-WMI-Collection.ps1" -LabConfirmed:$LabConfirmed;$p=Get-GootRdpPaths;Write-GootRdpSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
