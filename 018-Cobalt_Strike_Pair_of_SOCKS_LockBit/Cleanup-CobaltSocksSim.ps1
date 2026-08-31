#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([Parameter(Mandatory)][switch]$LabConfirmed)
$d=Split-Path -Parent $MyInvocation.MyCommand.Path;. (Join-Path $d 'CobaltSocksSim-utilities.ps1');Assert-CobaltSocksSafety -LabConfirmed:$LabConfirmed;$p=Get-CobaltSocksPaths;if(-not(Test-Path $p.Root)){return};if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:CobaltSocksId){throw 'Ownership mismatch.'};$e=Join-Path $env:PUBLIC 'CobaltSocksLockBitSim';if([IO.Path]::GetFullPath($p.Root).TrimEnd('\')-ne[IO.Path]::GetFullPath($e).TrimEnd('\')){throw 'Unexpected path.'};if($PSCmdlet.ShouldProcess($p.Root,'Remove owned CobaltSocksLockBitSim artifacts')){Remove-Item -LiteralPath $p.Root -Recurse -Force}
