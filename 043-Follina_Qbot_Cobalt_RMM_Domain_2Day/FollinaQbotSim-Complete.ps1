#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\FollinaQbotSim-utilities.ps1";Assert-FollinaQbotSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\FollinaQbotSim-Phase1-Follina-Qbot.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\FollinaQbotSim-Phase2-Movement-RMM.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\FollinaQbotSim-Phase3-Scan-Documents.ps1" -LabConfirmed:$LabConfirmed;$p=Get-FollinaQbotPaths;Write-FollinaQbotSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
