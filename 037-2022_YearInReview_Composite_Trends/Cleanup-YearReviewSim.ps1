#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\YearReviewSim-utilities.ps1";Assert-YearReviewSafety -LabConfirmed:$LabConfirmed;$p=Get-YearReviewPaths;$expected=Join-Path $env:PUBLIC 'YearReview2022Sim';if($p.Root-ne$expected){throw'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){Write-Host'Nothing to clean.';return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:YearReviewId){throw'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
