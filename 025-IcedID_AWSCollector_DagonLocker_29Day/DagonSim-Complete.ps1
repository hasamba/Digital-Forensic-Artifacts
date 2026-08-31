#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DagonSim-utilities.ps1";Assert-DagonSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DagonSim-Phase1-PhishIcedIDCobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DagonSim-Phase2-AWSCollectorPersistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DagonSim-Phase3-LockerImpact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-DagonPaths;Write-DagonSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
