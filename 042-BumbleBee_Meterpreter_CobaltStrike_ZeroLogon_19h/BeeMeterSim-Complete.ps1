#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BeeMeterSim-utilities.ps1";Assert-BeeMeterSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeMeterSim-Phase1-ISO-BumbleBee.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeMeterSim-Phase2-Meterpreter-Cobalt-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeMeterSim-Phase3-ZeroLogon-Movement.ps1" -LabConfirmed:$LabConfirmed;$p=Get-BeeMeterPaths;Write-BeeMeterSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
