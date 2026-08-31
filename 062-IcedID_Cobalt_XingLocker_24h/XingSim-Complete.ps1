#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\XingSim-utilities.ps1";Assert-XingSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\XingSim-Phase1-IcedID-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\XingSim-Phase2-Persistence-Discovery-Movement.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\XingSim-Phase3-XingLocker-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-XingPaths;Write-XingSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
