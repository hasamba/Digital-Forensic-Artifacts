#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'ElpacoSim-utilities.ps1')
Assert-ElpacoLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-ElpacoPaths

if (-not (Test-Path -LiteralPath $paths.Root)) {
    Write-Host 'No ELPACO simulation root exists.'
    return
}
if (-not (Test-Path -LiteralPath $paths.Owner)) { throw 'Cleanup refused: ownership marker is missing.' }
if ((Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:ElpacoScenarioId) { throw 'Cleanup refused: ownership marker does not match this scenario.' }
if ([IO.Path]::GetFullPath($paths.Root).TrimEnd('\') -ne [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'ElpacoConfluenceSim')).TrimEnd('\')) {
    throw 'Cleanup refused: scenario root is not the fixed expected path.'
}
if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove the owned ElpacoConfluenceSim artifact tree')) {
    Remove-Item -LiteralPath $paths.Root -Recurse -Force
    Write-Host "Removed owned simulation artifacts: $($paths.Root)" -ForegroundColor Yellow
}
