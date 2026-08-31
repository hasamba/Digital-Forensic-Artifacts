#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ZeroQbotSim-utilities.ps1"
Assert-ZeroQbotSimSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ZeroQbotSim-Phase1-Qbot-Persistence.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ZeroQbotSim-Phase2-Zerologon-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ZeroQbotSim-Phase3-Pivot-Exfil.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-ZeroQbotSimPaths
Write-ZeroQbotSimSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
