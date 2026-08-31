#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DefenderControlSim-utilities.ps1";Assert-DCSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DefenderControlSim-Phase1-Context-Stage.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DefenderControlSim-Phase2-Disable-Markers.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DefenderControlSim-Phase3-Analyst-State.ps1" -LabConfirmed:$LabConfirmed;$p=Get-DCPaths;Write-DCSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
