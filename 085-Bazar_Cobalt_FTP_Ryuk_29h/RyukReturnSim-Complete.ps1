#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukReturnSim-utilities.ps1"
Assert-RRSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukReturnSim-Phase1-Day1-Bazar-Recon.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukReturnSim-Phase2-Day2-FTP-Cobalt.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\RyukReturnSim-Phase3-Ryuk-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-RRPaths;Write-RRSummary -Paths $p
Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
