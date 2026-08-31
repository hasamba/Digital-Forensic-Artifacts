#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()] param([switch]$LabConfirmed)
. "$PSScriptRoot\WordPressGodzillaSim-utilities.ps1"
Assert-WordPressGodzillaSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\WordPressGodzillaSim-Phase1-ExploitWebShell.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\WordPressGodzillaSim-Phase2-DiscoveryScripts.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\WordPressGodzillaSim-Phase3-DirtyPipeTimestomp.ps1" -LabConfirmed:$LabConfirmed
$paths = Get-WordPressGodzillaPaths
Write-WordPressGodzillaSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
