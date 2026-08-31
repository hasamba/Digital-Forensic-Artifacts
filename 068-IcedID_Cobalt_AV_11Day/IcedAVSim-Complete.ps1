#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedAVSim-utilities.ps1";Assert-IcedAVSafety $LabConfirmed;& "$PSScriptRoot\IcedAVSim-Phase1-Word-HTA-IcedID.ps1" $LabConfirmed;& "$PSScriptRoot\IcedAVSim-Phase2-Credentials-Discovery-AV.ps1" $LabConfirmed;& "$PSScriptRoot\IcedAVSim-Phase3-Day11-NewCobalt-WMI.ps1" $LabConfirmed;$p=Get-IcedAVPaths;Write-IcedAVSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
