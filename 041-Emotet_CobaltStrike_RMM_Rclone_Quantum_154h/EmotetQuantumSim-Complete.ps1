#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetQuantumSim-utilities.ps1";Assert-EmotetQuantumSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\EmotetQuantumSim-Phase1-LNK-Emotet.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\EmotetQuantumSim-Phase2-Cobalt-Movement.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\EmotetQuantumSim-Phase3-RMM-Rclone-Quantum.ps1" -LabConfirmed:$LabConfirmed;$p=Get-EmotetQuantumPaths;Write-EmotetQuantumSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
