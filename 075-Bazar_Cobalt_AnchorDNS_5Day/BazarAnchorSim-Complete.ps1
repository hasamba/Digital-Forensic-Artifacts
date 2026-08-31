#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarAnchorSim-utilities.ps1"
Assert-BASafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BazarAnchorSim-Phase1-Entry-Domain.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BazarAnchorSim-Phase2-Dwell-Collection.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BazarAnchorSim-Phase3-Cutoff-NoRyuk.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-BAPaths
Write-BASummary $paths
Write-Host "Complete. Evidence remains at $($paths.Root); cleanup is separate."
