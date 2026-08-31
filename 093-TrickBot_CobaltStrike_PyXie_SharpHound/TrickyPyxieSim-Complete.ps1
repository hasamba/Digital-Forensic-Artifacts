#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\TrickyPyxieSim-utilities.ps1";Assert-TPSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickyPyxieSim-Phase1-TrickBot-Dormancy.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickyPyxieSim-Phase2-Cobalt-Recon.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickyPyxieSim-Phase3-PyXie-SharpHound.ps1" -LabConfirmed:$LabConfirmed;$p=Get-TPPaths;Write-TPSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
