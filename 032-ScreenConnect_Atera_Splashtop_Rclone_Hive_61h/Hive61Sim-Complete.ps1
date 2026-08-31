#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Hive61Sim-utilities.ps1";Assert-Hive61Safety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hive61Sim-Phase1-MultiRMM-C2.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hive61Sim-Phase2-Lateral-Exfil.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hive61Sim-Phase3-HiveImpact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-Hive61Paths;Write-Hive61Summary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
