#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarContiSim-utilities.ps1";Assert-BazarContiSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarContiSim-Phase1-XLSB-Trickbot-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarContiSim-Phase2-Discovery-Credentials-DC.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BazarContiSim-Phase3-Conti-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-BazarContiPaths;Write-BazarContiSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
