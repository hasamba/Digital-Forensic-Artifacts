#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GraceWipeSim-utilities.ps1"
Assert-GraceWipeSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GraceWipeSim-Phase1-Truebot-FlawedGrace.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GraceWipeSim-Phase2-Credential-Lateral.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GraceWipeSim-Phase3-Exfil-MBRKiller.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-GraceWipePaths
Write-GraceWipeSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
