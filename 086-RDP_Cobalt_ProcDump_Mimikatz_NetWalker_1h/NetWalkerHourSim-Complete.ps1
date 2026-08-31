#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\NetWalkerHourSim-utilities.ps1";Assert-NWSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NetWalkerHourSim-Phase1-RDP-Cobalt-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NetWalkerHourSim-Phase2-Credential-DC-Pivot.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\NetWalkerHourSim-Phase3-PsExec-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-NWPaths;Write-NWSummary -Paths $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
