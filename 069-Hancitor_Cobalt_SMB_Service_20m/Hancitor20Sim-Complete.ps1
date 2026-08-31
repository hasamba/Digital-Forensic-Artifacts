#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Hancitor20Sim-utilities.ps1";Assert-H20Safety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hancitor20Sim-Phase1-Maldoc-Hancitor-Cobalt.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hancitor20Sim-Phase2-ICMP-SMB-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\Hancitor20Sim-Phase3-Service-LSASS-Eviction.ps1" -LabConfirmed:$LabConfirmed;$p=Get-H20Paths;Write-H20Summary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
