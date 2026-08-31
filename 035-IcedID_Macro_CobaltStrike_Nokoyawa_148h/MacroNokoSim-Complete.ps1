#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\MacroNokoSim-utilities.ps1";Assert-MacroNokoSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\MacroNokoSim-Phase1-Excel-IcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\MacroNokoSim-Phase2-Cobalt-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\MacroNokoSim-Phase3-Nokoyawa.ps1" -LabConfirmed:$LabConfirmed;$p=Get-MacroNokoPaths;Write-MacroNokoSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
