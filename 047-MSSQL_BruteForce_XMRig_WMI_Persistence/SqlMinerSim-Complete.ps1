#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SqlMinerSim-utilities.ps1";Assert-SqlMinerSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerSim-Phase1-SQL-BruteForce.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerSim-Phase2-Batch-Persistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerSim-Phase3-WMI-XMRig.ps1" -LabConfirmed:$LabConfirmed;$p=Get-SqlMinerPaths;Write-SqlMinerSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
