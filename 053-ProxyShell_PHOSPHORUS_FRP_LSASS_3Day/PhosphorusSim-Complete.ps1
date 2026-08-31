#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\PhosphorusSim-utilities.ps1"
Assert-PhosphorusSimSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\PhosphorusSim-Phase1-ProxyShell-WebShell.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\PhosphorusSim-Phase2-Persistence-Credentials.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\PhosphorusSim-Phase3-Repeat-Eviction.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-PhosphorusSimPaths
Write-PhosphorusSimSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
