#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedRevilSim-utilities.ps1"
Assert-IRSafety -LabConfirmed:$LabConfirmed
$paths = Get-IRPaths
$expectedRoot = Join-Path $env:PUBLIC 'IcedRevilSim'
if ($paths.Root -ne $expectedRoot) { throw 'Cleanup root mismatch' }
if (-not (Test-Path -LiteralPath $paths.Root)) { return }
if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:IRId) { throw 'Refusing unowned root' }
if ($PSCmdlet.ShouldProcess($paths.Root,'Remove scenario-owned artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed $($paths.Root)"
}
