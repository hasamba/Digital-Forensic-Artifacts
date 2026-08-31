#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukFiveHourSim-utilities.ps1"
Assert-R5Safety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukFiveHourSim-Phase1-Bazar-Zerologon.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukFiveHourSim-Phase2-WMI-DC-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukFiveHourSim-Phase3-RDP-Ryuk-Impact.ps1" -LabConfirmed:$LabConfirmed
$p = Get-R5Paths
Write-R5Summary -Paths $p
Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
