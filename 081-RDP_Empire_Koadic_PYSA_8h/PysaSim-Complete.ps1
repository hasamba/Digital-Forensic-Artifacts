#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\PysaSim-utilities.ps1";Assert-PSSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\PysaSim-Phase1-RDP-Empire.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\PysaSim-Phase2-Koadic-Credentials-Movement.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\PysaSim-Phase3-Exfil-PYSA.ps1" -LabConfirmed:$LabConfirmed;$p=Get-PSPaths;Write-PSSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
