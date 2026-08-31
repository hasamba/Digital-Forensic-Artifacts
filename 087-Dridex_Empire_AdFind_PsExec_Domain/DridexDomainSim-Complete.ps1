#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DridexDomainSim-utilities.ps1";Assert-DDSafety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\DridexDomainSim-Phase1-Word-Dridex.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\DridexDomainSim-Phase2-Empire-Discovery.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\DridexDomainSim-Phase3-PsExec-Spread.ps1" -LabConfirmed:$LabConfirmed
$p=Get-DDPaths;Write-DDSummary -Paths $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
