#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedContiSim-utilities.ps1";Assert-ICSafety -LabConfirmed:$LabConfirmed;$p=Get-ICPaths;$x=Join-Path $env:PUBLIC 'IcedContiSim';if($p.Root-ne$x){throw 'Cleanup root mismatch'};if(-not(Test-Path -LiteralPath $p.Root)){return};if(-not(Test-Path -LiteralPath $p.Owner)-or(Get-Content -LiteralPath $p.Owner -Raw).Trim()-ne$script:ICId){throw 'Refusing unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item -LiteralPath $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
