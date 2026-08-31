#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\IceColdSim-utilities.ps1";Assert-IceColdSafety -LabConfirmed:$LabConfirmed;$p=Get-IceColdPaths;$expected=Join-Path $env:PUBLIC 'OneNoteIceColdSim';if($p.Root-ne$expected){throw'Cleanup root mismatch'};if(-not(Test-Path $p.Root)){Write-Host'Nothing to clean.';return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:IceColdId){throw'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
