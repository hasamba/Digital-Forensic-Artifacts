#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarAnchorSim-utilities.ps1"
Assert-BASafety -LabConfirmed:$LabConfirmed
$paths = Get-BAPaths
$expectedRoot = Join-Path $env:PUBLIC 'BazarAnchorSim'
if ($paths.Root -ne $expectedRoot) { throw 'Cleanup root mismatch' }
if (-not (Test-Path -LiteralPath $paths.Root)) { return }
if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:BAId) { throw 'Refusing unowned root' }
if ($PSCmdlet.ShouldProcess($paths.Root,'Remove scenario-owned artifact tree')) { Remove-Item -LiteralPath $paths.Root -Recurse -Force;Write-Host "Removed $($paths.Root)" }
