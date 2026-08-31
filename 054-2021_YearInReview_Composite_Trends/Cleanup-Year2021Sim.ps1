#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\Year2021Sim-utilities.ps1"
Assert-Year2021SimSafety -LabConfirmed:$LabConfirmed
$paths = Get-Year2021SimPaths
$expected = Join-Path $env:PUBLIC 'YearReview2021Sim'
if ($paths.Root -ne $expected) { throw 'Cleanup root mismatch' }
if (-not (Test-Path -LiteralPath $paths.Root)) { Write-Host 'Nothing to clean.'; return }
if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:Year2021SimId) { throw 'Refusing cleanup of unowned root' }
if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove scenario-owned artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed scenario-owned artifacts: $($paths.Root)"
}
