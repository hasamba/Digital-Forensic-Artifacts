#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\UrsnifLolbinSim-utilities.ps1";Assert-URSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifLolbinSim-Phase1-Phish-Regsvr32.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifLolbinSim-Phase2-Registry-VNC.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\UrsnifLolbinSim-Phase3-Cobalt-TVRat.ps1" -LabConfirmed:$LabConfirmed;$p=Get-URPaths;Write-URSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
