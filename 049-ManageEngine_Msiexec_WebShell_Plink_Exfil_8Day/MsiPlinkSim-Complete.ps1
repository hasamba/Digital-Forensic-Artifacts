#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\MsiPlinkSim-utilities.ps1"
Assert-MsiPlinkSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\MsiPlinkSim-Phase1-Exploit-WebShell.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\MsiPlinkSim-Phase2-WDigest-LSASS-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\MsiPlinkSim-Phase3-Plink-RDP-Exfil.ps1" -LabConfirmed:$LabConfirmed
$p = Get-MsiPlinkPaths
Write-MsiPlinkSummary $p
Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
