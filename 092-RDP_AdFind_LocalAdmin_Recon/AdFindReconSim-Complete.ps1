#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\AdFindReconSim-utilities.ps1";Assert-ARSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\AdFindReconSim-Phase1-RDP-Sessions.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\AdFindReconSim-Phase2-AdFind-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\AdFindReconSim-Phase3-LocalAdmin-Exit.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ARPaths;Write-ARSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
