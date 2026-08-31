#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\DridexDomainSim-utilities.ps1";Assert-DDSafety -LabConfirmed:$LabConfirmed;$p=Get-DDPaths;$expected=Join-Path $env:PUBLIC 'DridexDomainSim'
if($p.Root-ne$expected){throw 'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:DDId){throw 'Refusing unowned root'}
if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
