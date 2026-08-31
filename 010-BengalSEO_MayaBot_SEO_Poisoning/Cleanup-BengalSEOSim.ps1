#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'BengalSEOSim-utilities.ps1')

Assert-BengalLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-BengalPaths
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'BengalSEOSim'))
$actualRoot = [IO.Path]::GetFullPath($paths.Root)
if ($actualRoot -ne $expectedRoot) { throw "Cleanup root safety check failed: $actualRoot" }

$targets = @(
    (Join-Path $paths.Downloads 'Bitdefender_Central_Setup.zip'),
    (Join-Path $paths.Downloads 'Bitdefender_Central_Setup.zip.Zone.Identifier.txt'),
    (Join-Path $paths.Downloads 'Bitdefender_Central_Setup'),
    $paths.MayaCache,
    $paths.Root
)
foreach ($target in $targets) {
    if (Test-Path -LiteralPath $target) {
        if ($PSCmdlet.ShouldProcess($target, 'Remove BengalSEOSim-owned artifact')) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
}
if (Test-Path -LiteralPath 'HKCU:\Software\BengalSEOSim') {
    if ($PSCmdlet.ShouldProcess('HKCU:\Software\BengalSEOSim', 'Remove BengalSEOSim registry canary')) {
        Remove-Item -LiteralPath 'HKCU:\Software\BengalSEOSim' -Recurse -Force
    }
}

Write-Host 'BengalSEOSim cleanup complete.' -ForegroundColor Green
