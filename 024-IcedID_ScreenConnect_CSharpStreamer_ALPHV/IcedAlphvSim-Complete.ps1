#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedAlphvSim-utilities.ps1";Assert-IcedAlphvSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedAlphvSim-Phase1-PhishIcedID.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedAlphvSim-Phase2-RMMCredentialLateral.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\IcedAlphvSim-Phase3-CollectionExfilImpact.ps1" -LabConfirmed:$LabConfirmed;$p=Get-IcedAlphvPaths;Write-IcedAlphvSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
