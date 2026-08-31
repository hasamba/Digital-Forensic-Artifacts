#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ZeroDASim-utilities.ps1";Assert-ZeroDASafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ZeroDASim-Phase1-Hancitor-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ZeroDASim-Phase2-Discovery-Lateral.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ZeroDASim-Phase3-Zerologon-Eviction.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ZeroDAPaths;Write-ZeroDASummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
