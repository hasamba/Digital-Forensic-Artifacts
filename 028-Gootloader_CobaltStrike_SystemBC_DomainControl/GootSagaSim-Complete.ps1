#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GootSagaSim-utilities.ps1";Assert-GootSagaSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GootSagaSim-Phase1-SEO-Gootloader.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GootSagaSim-Phase2-Cobalt-SystemBC.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\GootSagaSim-Phase3-RDP-Collection.ps1" -LabConfirmed:$LabConfirmed
$p=Get-GootSagaPaths;Write-GootSagaSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
