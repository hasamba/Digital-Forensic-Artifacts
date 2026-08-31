#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShareFinderSim-utilities.ps1"
Assert-ShareFinderSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ShareFinderSim-Phase1-PowerShell.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ShareFinderSim-Phase2-LDAP-SMB-ICMP.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\ShareFinderSim-Phase3-Detection.ps1" -LabConfirmed:$LabConfirmed
$paths=Get-ShareFinderPaths
Write-ShareFinderSummary $paths
Write-Host "Scenario complete. Evidence remains at $($paths.Root). Cleanup is separate."
