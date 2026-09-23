#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShaiHuludSim-utilities.ps1";Assert-ShSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ShaiHuludSim-Phase1-Session-Hijack-Poisoned-Package.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ShaiHuludSim-Phase2-Token-Theft-Worm-Propagation.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ShaiHuludSim-Phase3-Namespace-Poisoning-Downstream.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ShPaths;Write-ShSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
