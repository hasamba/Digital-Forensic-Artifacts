#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SqlMinerBasementSim-utilities.ps1";Assert-SMSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerBasementSim-Phase1-RDP-Artifacts.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerBasementSim-Phase2-Install-Persistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\SqlMinerBasementSim-Phase3-Tasks-Mining.ps1" -LabConfirmed:$LabConfirmed;$p=Get-SMPaths;Write-SMSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
