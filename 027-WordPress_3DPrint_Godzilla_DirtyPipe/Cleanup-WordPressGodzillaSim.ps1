#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')] param([switch]$LabConfirmed)
. "$PSScriptRoot\WordPressGodzillaSim-utilities.ps1"
Assert-WordPressGodzillaSafety -LabConfirmed:$LabConfirmed
$paths = Get-WordPressGodzillaPaths
$expected = Join-Path $env:PUBLIC 'WordPressGodzillaSim'
if ($paths.Root -ne $expected) { throw 'Cleanup root mismatch' }
if (-not (Test-Path $paths.Root)) { Write-Host 'Nothing to clean.'; return }
if (-not (Test-Path $paths.Owner) -or (Get-Content $paths.Owner -Raw).Trim() -ne $script:WordPressGodzillaId) { throw 'Refusing cleanup of unowned root' }
if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove scenario-owned artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed scenario-owned artifacts: $($paths.Root)"
}
