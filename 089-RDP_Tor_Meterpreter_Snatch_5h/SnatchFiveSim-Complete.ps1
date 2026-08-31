#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SnatchFiveSim-utilities.ps1";Assert-S5Safety -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SnatchFiveSim-Phase1-RDP-DC-Tor.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SnatchFiveSim-Phase2-C2-Persistence-NTDS.ps1" -LabConfirmed:$LabConfirmed
& "$PSScriptRoot\SnatchFiveSim-Phase3-Safe-Impact.ps1" -LabConfirmed:$LabConfirmed
$p=Get-S5Paths;Write-S5Summary -Paths $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
