#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetRcloneSim-utilities.ps1"
Assert-EmotetRcloneSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\EmotetRcloneSim-Phase1-XLS-Emotet.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\EmotetRcloneSim-Phase2-Cobalt-Movement.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\EmotetRcloneSim-Phase3-RMM-Rclone.ps1" -LabConfirmed:$LabConfirmed
$p = Get-EmotetRclonePaths
Write-EmotetRcloneSummary $p
Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
