#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ISOQuantumSim-utilities.ps1";Assert-ISOQuantumSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ISOQuantumSim-Phase1-ISO-IcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ISOQuantumSim-Phase2-Cobalt-Domain.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ISOQuantumSim-Phase3-Rclone-Quantum.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ISOQuantumPaths;Write-ISOQuantumSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
