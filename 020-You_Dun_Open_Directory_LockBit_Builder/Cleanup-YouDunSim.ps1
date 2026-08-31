#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([Parameter(Mandatory)][switch]$LabConfirmed)
$d=Split-Path -Parent $MyInvocation.MyCommand.Path;. (Join-Path $d 'YouDunSim-utilities.ps1');Assert-YouDunSafety -LabConfirmed:$LabConfirmed;$p=Get-YouDunPaths;if(-not(Test-Path $p.Root)){return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:YouDunId){throw'Ownership mismatch'};$e=Join-Path $env:PUBLIC 'YouDunOpenDirectorySim';if([IO.Path]::GetFullPath($p.Root).TrimEnd('\')-ne[IO.Path]::GetFullPath($e).TrimEnd('\')){throw'Unexpected path'};if($PSCmdlet.ShouldProcess($p.Root,'Remove owned YouDunOpenDirectorySim artifacts')){Remove-Item -LiteralPath $p.Root -Recurse -Force}
