#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\TrickPassSim-utilities.ps1";Assert-TrickPassSafety -LabConfirmed:$LabConfirmed;$p=Get-TrickPassPaths;$expected=Join-Path $env:PUBLIC 'TrickPassSim';if($p.Root-ne$expected){throw 'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){Write-Host 'Nothing to clean.';return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:TrickPassId){throw 'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
