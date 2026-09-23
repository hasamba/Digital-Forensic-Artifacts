#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SettraSim-utilities.ps1";Assert-SxSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SettraSim-Phase1-Access-MeshAgent-Persistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SettraSim-Phase2-DefenseEvasion-BYOVD.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SettraSim-Phase3-Impact-Ransomware.ps1" -LabConfirmed:$LabConfirmed;$p=Get-SxPaths;Write-SxSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
