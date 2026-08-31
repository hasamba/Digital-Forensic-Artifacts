#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\TrickPassSim-utilities.ps1";Assert-TrickPassSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickPassSim-Phase1-Trickbot-Persistence-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickPassSim-Phase2-WDigest-ProcDump-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickPassSim-Phase3-Fake1Password-WMIC-Cobalt.ps1" -LabConfirmed:$LabConfirmed;$p=Get-TrickPassPaths;Write-TrickPassSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
