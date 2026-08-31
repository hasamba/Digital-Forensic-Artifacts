#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DharmaSingleSim-utilities.ps1";Assert-DSSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\DharmaSingleSim-Phase1-RDP-NS.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DharmaSingleSim-Phase2-Destructive-Prep.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DharmaSingleSim-Phase3-SingleHost-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-DSPaths;Write-DSSummary -Paths $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
