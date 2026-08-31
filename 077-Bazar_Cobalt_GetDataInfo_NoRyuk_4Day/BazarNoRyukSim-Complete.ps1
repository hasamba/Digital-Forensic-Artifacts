#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarNoRyukSim-utilities.ps1";Assert-BNSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarNoRyukSim-Phase1-Bazar-Dwell.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarNoRyukSim-Phase2-Cobalt-Domain.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarNoRyukSim-Phase3-DataInfo-Cutoff.ps1" -LabConfirmed:$LabConfirmed;$p=Get-BNPaths;Write-BNSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
