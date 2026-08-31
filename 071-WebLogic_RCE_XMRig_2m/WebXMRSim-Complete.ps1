#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\WebXMRSim-utilities.ps1";Assert-WXSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebXMRSim-Phase1-WebLogic-RCE-PowerShell.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebXMRSim-Phase2-Loader-Persistence-Defense.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebXMRSim-Phase3-XMRig-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-WXPaths;Write-WXSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
