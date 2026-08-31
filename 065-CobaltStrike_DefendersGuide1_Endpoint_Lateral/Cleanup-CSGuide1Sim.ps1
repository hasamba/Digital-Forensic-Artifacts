#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\CSGuide1Sim-utilities.ps1";Assert-CSGuide1Safety -LabConfirmed:$LabConfirmed;$p=Get-CSGuide1Paths;$expected=Join-Path $env:PUBLIC 'CSGuide1Sim';if($p.Root-ne$expected){throw 'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){Write-Host 'Nothing to clean.';return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:CSGuide1Id){throw 'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
