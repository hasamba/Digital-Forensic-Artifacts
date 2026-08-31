#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\BlueSkySQLSim-utilities.ps1";Assert-BlueSkySafety -LabConfirmed:$LabConfirmed;$p=Get-BlueSkyPaths;$expected=Join-Path $env:PUBLIC 'BlueSkySQLSim';if($p.Root-ne$expected){throw'Cleanup root mismatch'};if(-not(Test-Path $p.Root)){Write-Host'Nothing to clean.';return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:BlueSkyId){throw'Refusing cleanup of unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed scenario-owned artifacts: $($p.Root)"}
