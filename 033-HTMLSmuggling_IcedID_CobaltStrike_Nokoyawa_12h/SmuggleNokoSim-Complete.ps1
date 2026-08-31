#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SmuggleNokoSim-utilities.ps1";Assert-SmuggleNokoSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SmuggleNokoSim-Phase1-Smuggling-IcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SmuggleNokoSim-Phase2-Cobalt-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SmuggleNokoSim-Phase3-Nokoyawa.ps1" -LabConfirmed:$LabConfirmed;$p=Get-SmuggleNokoPaths;Write-SmuggleNokoSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
