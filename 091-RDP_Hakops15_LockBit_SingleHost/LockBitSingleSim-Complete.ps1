#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\LockBitSingleSim-utilities.ps1";Assert-LBSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LockBitSingleSim-Phase1-RDP-Defense.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LockBitSingleSim-Phase2-LockBit-Prep.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LockBitSingleSim-Phase3-No-Spread.ps1" -LabConfirmed:$LabConfirmed;$p=Get-LBPaths;Write-LBSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
