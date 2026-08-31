#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\AdFindReconSim-utilities.ps1";Assert-ARSafety -LabConfirmed:$LabConfirmed;$p=Get-ARPaths;$x=Join-Path $env:PUBLIC 'AdFindReconSim';if($p.Root-ne$x){throw 'Cleanup root mismatch'};if(-not(Test-Path $p.Root)){return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:ARId){throw 'Refusing unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
