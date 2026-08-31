#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'FogToolkitSim-utilities.ps1')
Assert-FogLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-FogPaths
if (-not (Test-Path -LiteralPath $paths.Root)) { Write-Host 'No Fog simulation root exists.'; return }
if (-not (Test-Path -LiteralPath $paths.Owner)) { throw 'Cleanup refused: ownership marker is missing.' }
if ((Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:FogScenarioId) { throw 'Cleanup refused: ownership marker does not match.' }
$expected = Join-Path $env:PUBLIC 'FogOpenDirectorySim'
if ([IO.Path]::GetFullPath($paths.Root).TrimEnd('\') -ne [IO.Path]::GetFullPath($expected).TrimEnd('\')) { throw 'Cleanup refused: unexpected root path.' }
if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove the owned FogOpenDirectorySim artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed owned simulation artifacts: $($paths.Root)" -ForegroundColor Yellow
}
