#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\WebLogicMinerSim-utilities.ps1";Assert-WMSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebLogicMinerSim-Phase1-Exploit-XML.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebLogicMinerSim-Phase2-Stage-Task.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\WebLogicMinerSim-Phase3-Miner-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-WMPaths;Write-WMSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
