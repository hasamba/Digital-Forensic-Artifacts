#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedRevilSim-utilities.ps1"
Assert-IRSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\IcedRevilSim-Phase1-IcedID-Entry.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\IcedRevilSim-Phase2-Cobalt-Domain.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\IcedRevilSim-Phase3-Rclone-REvil.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-IRPaths
Write-IRSummary $paths
Write-Host "Complete. Evidence remains at $($paths.Root); cleanup is separate."
