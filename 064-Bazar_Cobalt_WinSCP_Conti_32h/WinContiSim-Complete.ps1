#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\WinContiSim-utilities.ps1";Assert-WinContiSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WinContiSim-Phase1-Bazar-Cobalt-PTH.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WinContiSim-Phase2-WMIC-Discovery-WinSCP.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WinContiSim-Phase3-Conti-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-WinContiPaths;Write-WinContiSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
