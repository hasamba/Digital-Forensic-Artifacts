#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ToolkitSim-utilities.ps1";Assert-ToolkitSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ToolkitSim-Phase1-OpenDirectoryInventory.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ToolkitSim-Phase2-BatchCapabilities.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ToolkitSim-Phase3-C2RemoteAccess.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ToolkitPaths;Write-ToolkitSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
