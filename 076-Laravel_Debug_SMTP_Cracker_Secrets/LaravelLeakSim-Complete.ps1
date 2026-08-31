#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\LaravelLeakSim-utilities.ps1";Assert-LLSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LaravelLeakSim-Phase1-RDP-Python.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LaravelLeakSim-Phase2-Generated-Laravel.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\LaravelLeakSim-Phase3-Results.ps1" -LabConfirmed:$LabConfirmed;$p=Get-LLPaths;Write-LLSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
