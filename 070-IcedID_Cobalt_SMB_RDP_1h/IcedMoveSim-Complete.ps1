#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedMoveSim-utilities.ps1";Assert-IMSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedMoveSim-Phase1-Word-IcedID-Persistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedMoveSim-Phase2-Cobalt-LSASS-AdFind.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedMoveSim-Phase3-SMB-Service-RDP.ps1" -LabConfirmed:$LabConfirmed;$p=Get-IMPaths;Write-IMSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
