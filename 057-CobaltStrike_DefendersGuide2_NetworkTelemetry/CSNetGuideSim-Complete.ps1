#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\CSNetGuideSim-utilities.ps1";Assert-CSNetGuideSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSNetGuideSim-Phase1-Profiles-Fronting.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSNetGuideSim-Phase2-Socks-DNS-SMB.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSNetGuideSim-Phase3-Detection-Evidence.ps1" -LabConfirmed:$LabConfirmed;$p=Get-CSNetGuidePaths;Write-CSNetGuideSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
