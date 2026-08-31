#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DharmaTenMinuteSim-utilities.ps1";Assert-DTSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DharmaTenMinuteSim-Phase1-Entry-Credentials-Scan.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DharmaTenMinuteSim-Phase2-Manual-RDP-Deploy.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\DharmaTenMinuteSim-Phase3-Impact-Persistence.ps1" -LabConfirmed:$LabConfirmed;$p=Get-DTPaths;Write-DTSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
