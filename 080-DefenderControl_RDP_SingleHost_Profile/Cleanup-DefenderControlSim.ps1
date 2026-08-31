#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\DefenderControlSim-utilities.ps1";Assert-DCSafety -LabConfirmed:$LabConfirmed;$p=Get-DCPaths;$x=Join-Path $env:PUBLIC 'DefenderControlSim';if($p.Root-ne$x){throw 'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:DCId){throw 'Refusing unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
