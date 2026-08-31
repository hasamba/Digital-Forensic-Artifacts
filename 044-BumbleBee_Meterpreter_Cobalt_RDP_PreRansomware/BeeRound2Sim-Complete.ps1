#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BeeRound2Sim-utilities.ps1";Assert-BeeRound2Safety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeRound2Sim-Phase1-ISO-BumbleBee.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeRound2Sim-Phase2-Meterpreter-Cobalt-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\BeeRound2Sim-Phase3-RDP-AnyDesk-Outcome.ps1" -LabConfirmed:$LabConfirmed;$p=Get-BeeRound2Paths;Write-BeeRound2Summary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
