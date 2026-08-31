#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukReturnSim-utilities.ps1"
Assert-RRSafety -LabConfirmed:$LabConfirmed;$p=Get-RRPaths;$expected=Join-Path $env:PUBLIC 'RyukReturnSim'
if($p.Root-ne$expected){throw 'Cleanup root mismatch'}
if(-not(Test-Path -LiteralPath $p.Root)){return}
if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:RRId){throw 'Refusing unowned root'}
if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
