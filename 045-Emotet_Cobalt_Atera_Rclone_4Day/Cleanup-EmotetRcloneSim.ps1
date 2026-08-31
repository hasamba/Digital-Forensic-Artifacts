#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetRcloneSim-utilities.ps1"
Assert-EmotetRcloneSafety -LabConfirmed:$LabConfirmed
$p = Get-EmotetRclonePaths
$expected = Join-Path $env:PUBLIC 'EmotetRcloneSim'
if ($p.Root -ne $expected) { throw 'Cleanup root mismatch' }
if (-not (Test-Path -LiteralPath $p.Root)) { Write-Host 'Nothing to clean.'; return }
if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:EmotetRcloneId) { throw 'Refusing cleanup of unowned root' }
if ($PSCmdlet.ShouldProcess($p.Root,'Remove scenario-owned artifact tree')) { Remove-Item -LiteralPath $p.Root -Recurse -Force; Write-Host "Removed scenario-owned artifacts: $($p.Root)" }
