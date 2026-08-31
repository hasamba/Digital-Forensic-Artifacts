#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\QbotMoveSim-utilities.ps1"; Assert-QbotMoveSimSafety -LabConfirmed:$LabConfirmed; & "$PSScriptRoot\QbotMoveSim-Phase1-Access-Persistence.ps1" -LabConfirmed:$LabConfirmed; & "$PSScriptRoot\QbotMoveSim-Phase2-Discovery-Collection.ps1" -LabConfirmed:$LabConfirmed; & "$PSScriptRoot\QbotMoveSim-Phase3-Workstation-Spread.ps1" -LabConfirmed:$LabConfirmed; $paths=Get-QbotMoveSimPaths; Write-QbotMoveSimSummary $paths; Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
