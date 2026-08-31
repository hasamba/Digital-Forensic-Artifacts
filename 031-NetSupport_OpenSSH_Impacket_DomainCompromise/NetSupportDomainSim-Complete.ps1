#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\NetSupportDomainSim-utilities.ps1";Assert-NSDomainSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\NetSupportDomainSim-Phase1-LureDeployment.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\NetSupportDomainSim-Phase2-SSH-Lateral.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\NetSupportDomainSim-Phase3-CredentialCollection.ps1" -LabConfirmed:$LabConfirmed;$p=Get-NSDomainPaths;Write-NSDomainSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
