#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\UrsnifGiftSim-utilities.ps1";Assert-UrsnifGiftSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifGiftSim-Phase1-ISO-Ursnif.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifGiftSim-Phase2-Cobalt-Credential-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifGiftSim-Phase3-WMI-RDP-Outcome.ps1" -LabConfirmed:$LabConfirmed;$p=Get-UrsnifGiftPaths;Write-UrsnifGiftSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
