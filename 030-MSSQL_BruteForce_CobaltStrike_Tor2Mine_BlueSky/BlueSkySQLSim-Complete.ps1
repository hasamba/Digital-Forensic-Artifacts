#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BlueSkySQLSim-utilities.ps1";Assert-BlueSkySafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlueSkySQLSim-Phase1-MSSQL-Cobalt.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlueSkySQLSim-Phase2-Tor2Mine-Lateral.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\BlueSkySQLSim-Phase3-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-BlueSkyPaths;Write-BlueSkySummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
