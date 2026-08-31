#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'InterlockSim-utilities.ps1')

Assert-InterlockLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-InterlockPaths
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'InterlockFileFixSim'))
$actualRoot = [IO.Path]::GetFullPath($paths.Root)
if ($actualRoot -ne $expectedRoot) { throw "Cleanup root safety check failed: $actualRoot" }

$expectedRun = Get-InterlockExpectedRunCommand
$currentRun = Get-ItemPropertyValue -LiteralPath $paths.RunKey -Name $script:InterlockRunValue -ErrorAction SilentlyContinue
if ($null -ne $currentRun) {
    if ($currentRun -eq $expectedRun) {
        if ($PSCmdlet.ShouldProcess("$($paths.RunKey)\$script:InterlockRunValue", 'Remove Interlock canary Run value')) {
            Remove-ItemProperty -LiteralPath $paths.RunKey -Name $script:InterlockRunValue -Force
        }
    } else {
        Write-Warning "Leaving changed Run value in place: $script:InterlockRunValue"
    }
}

if (Test-Path -LiteralPath $paths.PhpOwner) {
    $owner = (Get-Content -LiteralPath $paths.PhpOwner -Raw).Trim()
    if ($owner -eq $script:InterlockScenarioId) {
        foreach ($target in @(
            $paths.PhpExe,
            $paths.Config,
            $paths.AltConfig,
            (Join-Path $paths.PhpRoot 'ext\php_zip.dll'),
            $paths.PhpOwner
        )) {
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, 'Remove Interlock scenario-owned AppData artifact')) {
                    Remove-Item -LiteralPath $target -Force
                }
            }
        }
        $ext = Join-Path $paths.PhpRoot 'ext'
        if ((Test-Path -LiteralPath $ext) -and -not (Get-ChildItem -LiteralPath $ext -Force)) {
            if ($PSCmdlet.ShouldProcess($ext, 'Remove empty scenario-owned ext directory')) { Remove-Item -LiteralPath $ext -Force }
        }
        if ((Test-Path -LiteralPath $paths.PhpRoot) -and -not (Get-ChildItem -LiteralPath $paths.PhpRoot -Force)) {
            if ($PSCmdlet.ShouldProcess($paths.PhpRoot, 'Remove empty scenario-owned PHP directory')) { Remove-Item -LiteralPath $paths.PhpRoot -Force }
        } elseif (Test-Path -LiteralPath $paths.PhpRoot) {
            Write-Warning "Leaving non-empty PHP directory in place: $($paths.PhpRoot)"
        }
    }
}

if (Test-Path -LiteralPath $paths.Root) {
    if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove fixed InterlockFileFixSim root')) {
        Remove-Item -LiteralPath $paths.Root -Recurse -Force
    }
}
Write-Host 'InterlockFileFixSim cleanup complete.' -ForegroundColor Green
