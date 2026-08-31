#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'AkiraFlashSim-utilities.ps1')

Assert-AkiraFlashLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-AkiraFlashPaths
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'AkiraFlashSim'))
$actualRoot = [IO.Path]::GetFullPath($paths.Root)
if ($actualRoot -ne $expectedRoot) { throw "Cleanup root safety check failed: $actualRoot" }

if (Test-Path -LiteralPath $paths.InstallerOwner) {
    $owner = (Get-Content -LiteralPath $paths.InstallerOwner -Raw).Trim()
    if ($owner -eq $script:AkiraScenarioId) {
        foreach ($target in @($paths.Installer, $paths.InstallerOwner)) {
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, 'Remove AkiraFlashSim-owned Downloads artifact')) {
                    Remove-Item -LiteralPath $target -Force
                }
            }
        }
    }
}
if (Test-Path -LiteralPath $paths.Root) {
    if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove fixed AkiraFlashSim scenario root')) {
        Remove-Item -LiteralPath $paths.Root -Recurse -Force
    }
}
Write-Host 'AkiraFlashSim cleanup complete.' -ForegroundColor Green
