#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedContiSim-utilities.ps1";Assert-ICSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedContiSim-Phase1-IcedID-Dormancy.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedContiSim-Phase2-Cobalt-Domain-Movement.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedContiSim-Phase3-Conti-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ICPaths;Write-ICSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
