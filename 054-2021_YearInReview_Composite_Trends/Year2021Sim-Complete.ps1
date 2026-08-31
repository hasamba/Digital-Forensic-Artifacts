#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Year2021Sim-utilities.ps1"
Assert-Year2021SimSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Year2021Sim-Phase1-Access-C2.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Year2021Sim-Phase2-Persistence-Credential-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Year2021Sim-Phase3-Movement-Exfil-Impact.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-Year2021SimPaths
Write-Year2021SimSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
