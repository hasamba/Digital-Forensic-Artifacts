#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\PhosphorusSim-utilities.ps1"
Assert-PhosphorusSimSafety -LabConfirmed:$LabConfirmed
$paths = Get-PhosphorusSimPaths
$expected = Join-Path $env:PUBLIC 'PhosphorusSim'
if ($paths.Root -ne $expected) { throw 'Cleanup root mismatch' }
if (-not (Test-Path -LiteralPath $paths.Root)) { Write-Host 'Nothing to clean.'; return }
if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:PhosphorusSimId) { throw 'Refusing cleanup of unowned root' }
if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove scenario-owned artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed scenario-owned artifacts: $($paths.Root)"
}
