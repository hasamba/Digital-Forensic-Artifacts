#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\SettraSim-utilities.ps1";Assert-SxSafety -LabConfirmed:$LabConfirmed;$p=Get-SxPaths;$x=Join-Path $env:PUBLIC 'SettraSim';if($p.Root-ne$x){throw 'Cleanup root mismatch'};if(-not(Test-Path $p.Root)){return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:SxId){throw 'Refusing unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
