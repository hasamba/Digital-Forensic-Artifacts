#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DiavolSim-utilities.ps1";Assert-DiavolSimSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DiavolSim-Phase1-Bazar-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DiavolSim-Phase2-Day2-Access-Exfil.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DiavolSim-Phase3-Diavol-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-DiavolSimPaths;Write-DiavolSimSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
