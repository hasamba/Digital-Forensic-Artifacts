#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShaiHuludSim-utilities.ps1";Assert-ShSafety -LabConfirmed:$LabConfirmed;$p=Get-ShPaths;$x=Join-Path $env:PUBLIC 'ShaiHuludSim';if($p.Root-ne$x){throw 'Cleanup root mismatch'};if(-not(Test-Path $p.Root)){return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:ShId){throw 'Refusing unowned root'};if($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')){Remove-Item $p.Root -Recurse -Force;Write-Host "Removed $($p.Root)"}
