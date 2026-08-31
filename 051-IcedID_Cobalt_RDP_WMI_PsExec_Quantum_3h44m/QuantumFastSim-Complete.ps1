#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\QuantumFastSim-utilities.ps1";Assert-QuantumFastSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\QuantumFastSim-Phase1-ISO-IcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\QuantumFastSim-Phase2-Cobalt-Credentials-RDP.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\QuantumFastSim-Phase3-Quantum-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-QuantumFastPaths;Write-QuantumFastSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
