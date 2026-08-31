#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GoGoogleHourSim-utilities.ps1";Assert-GGSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GoGoogleHourSim-Phase1-Entry-Credential-Toolkit.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GoGoogleHourSim-Phase2-Recon-Lateral.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\GoGoogleHourSim-Phase3-GoGoogle-Impact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-GGPaths;Write-GGSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
