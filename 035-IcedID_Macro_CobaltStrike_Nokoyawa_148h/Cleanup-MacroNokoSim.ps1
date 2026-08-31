#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\MacroNokoSim-utilities.ps1";Assert-MacroNokoSafety -LabConfirmed:$LabConfirmed;$p=Get-MacroNokoPaths;$expected=Join-Path $env:PUBLIC 'MacroNokoSim';if($p.Root-ne$expected){throw'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){Write-Host'Nothing to clean.';return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:MacroNokoId){throw'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
