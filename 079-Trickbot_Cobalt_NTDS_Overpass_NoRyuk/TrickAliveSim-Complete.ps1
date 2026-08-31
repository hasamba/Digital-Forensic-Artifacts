#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\TrickAliveSim-utilities.ps1";Assert-TASafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickAliveSim-Phase1-Trickbot-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickAliveSim-Phase2-Credentials-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickAliveSim-Phase3-Movement-Cutoff.ps1" -LabConfirmed:$LabConfirmed;$p=Get-TAPaths;Write-TASummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
