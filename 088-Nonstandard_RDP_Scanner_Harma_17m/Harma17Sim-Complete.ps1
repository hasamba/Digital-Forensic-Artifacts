#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Harma17Sim-utilities.ps1";Assert-H17Safety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Harma17Sim-Phase1-Entry-Scanner.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Harma17Sim-Phase2-DC-Pivot.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\Harma17Sim-Phase3-Harma-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-H17Paths;Write-H17Summary -Paths $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
