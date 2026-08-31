#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Conti19Sim-utilities.ps1";Assert-Conti19Safety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Conti19Sim-Phase1-IcedID-RMM.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Conti19Sim-Phase2-DC-Handoffs.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Conti19Sim-Phase3-Conti-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-Conti19Paths;Write-Conti19Summary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
