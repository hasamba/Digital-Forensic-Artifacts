#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'LynxSim-utilities.ps1')

Assert-LynxLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-LynxPaths
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'LynxSim'))
$actualRoot = [IO.Path]::GetFullPath($paths.Root)
if ($actualRoot -ne $expectedRoot) { throw "Cleanup root safety check failed: $actualRoot" }

if (Test-Path -LiteralPath $paths.DesktopWOwner) {
    $owner = (Get-Content -LiteralPath $paths.DesktopWOwner -Raw).Trim()
    if ($owner -eq $script:LynxScenarioId) {
        foreach ($target in @($paths.DesktopW, $paths.DesktopWOwner)) {
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, 'Remove LynxSim-owned Desktop artifact')) {
                    Remove-Item -LiteralPath $target -Force
                }
            }
        }
    }
}

$desktop000Owner = Join-Path $paths.Desktop000 '.LynxSim.owner'
if (Test-Path -LiteralPath $desktop000Owner) {
    $owner = (Get-Content -LiteralPath $desktop000Owner -Raw).Trim()
    if ($owner -eq $script:LynxScenarioId) {
        foreach ($name in @('netscan.exe', 'netscan.xml', 'netscan.lic', 'ss.xml', 'nxc.exe', 'nxc.txt', '7zG.exe', '.LynxSim.owner')) {
            $target = Join-Path $paths.Desktop000 $name
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, 'Remove LynxSim-owned Desktop 000 artifact')) {
                    Remove-Item -LiteralPath $target -Force
                }
            }
        }
        if ((Test-Path -LiteralPath $paths.Desktop000) -and -not (Get-ChildItem -LiteralPath $paths.Desktop000 -Force)) {
            if ($PSCmdlet.ShouldProcess($paths.Desktop000, 'Remove empty LynxSim-owned directory')) {
                Remove-Item -LiteralPath $paths.Desktop000 -Force
            }
        } elseif (Test-Path -LiteralPath $paths.Desktop000) {
            Write-Warning "Leaving non-empty directory in place: $($paths.Desktop000)"
        }
    }
}

if (Test-Path -LiteralPath $paths.Root) {
    if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove fixed LynxSim scenario root')) {
        Remove-Item -LiteralPath $paths.Root -Recurse -Force
    }
}

Write-Host 'LynxSim cleanup complete.' -ForegroundColor Green
