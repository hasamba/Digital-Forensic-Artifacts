#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukSpeedSim-utilities.ps1"
Assert-RSSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukSpeedSim-Phase1-Bazar-Persistence.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukSpeedSim-Phase2-Cobalt-Zerologon.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukSpeedSim-Phase3-Ryuk-Impact.ps1" -LabConfirmed:$LabConfirmed
$p = Get-RSPaths
Write-RSSummary -Paths $p
Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
