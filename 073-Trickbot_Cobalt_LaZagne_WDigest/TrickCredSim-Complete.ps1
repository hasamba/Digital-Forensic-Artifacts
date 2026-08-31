#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\TrickCredSim-utilities.ps1";Assert-TCSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickCredSim-Phase1-Trickbot-Cobalt-Persistence.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickCredSim-Phase2-Discovery-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\TrickCredSim-Phase3-Beaconing-NoMovement.ps1" -LabConfirmed:$LabConfirmed;$p=Get-TCPaths;Write-TCSummary $p;Write-Host "Complete. Evidence remains at $($p.Root); cleanup is separate."
