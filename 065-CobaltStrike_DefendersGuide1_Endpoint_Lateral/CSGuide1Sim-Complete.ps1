#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\CSGuide1Sim-utilities.ps1";Assert-CSGuide1Safety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSGuide1Sim-Phase1-Delivery-C2-Pipes.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSGuide1Sim-Phase2-Injection-Privilege-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\CSGuide1Sim-Phase3-Movement-Aggressor-Detection.ps1" -LabConfirmed:$LabConfirmed;$p=Get-CSGuide1Paths;Write-CSGuide1Summary $p;Write-Host "Guide exercise complete. Evidence remains at $($p.Root). Cleanup is separate."
