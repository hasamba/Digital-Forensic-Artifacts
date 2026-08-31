#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\OilKeySim-utilities.ps1"
Assert-OilKeySafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OilKeySim-Phase1-Docm-PowerShell.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OilKeySim-Phase2-Keylogger-Collection.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\OilKeySim-Phase3-Repeat-Exfil.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-OilKeyPaths
Write-OilKeySummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
