#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\RdpMinerSim-utilities.ps1";Assert-RMSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\RdpMinerSim-Phase1-RDP-Account.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\RdpMinerSim-Phase2-Credentials-Discovery-RDP.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\RdpMinerSim-Phase3-XMRig-Logout.ps1" -LabConfirmed:$LabConfirmed;$p=Get-RMPaths;Write-RMSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
