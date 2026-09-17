#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'RansomHubSim-utilities.ps1')

Assert-RansomHubLabSafety -LabConfirmed:$LabConfirmed
$paths = Get-RansomHubPaths
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'RansomHubRdpSim'))
$actualRoot = [IO.Path]::GetFullPath($paths.Root)
if ($actualRoot -ne $expectedRoot) { throw "Cleanup root safety check failed: $actualRoot" }

if (Test-Path -LiteralPath $paths.DesktopOwner) {
    $owner = (Get-Content -LiteralPath $paths.DesktopOwner -Raw).Trim()
    if ($owner -eq $script:RansomHubScenarioId) {
        foreach ($name in @('setup.msi', 'Advanced_IP_Scanner.exe', 'netscan.exe', 'CredentialsFileView.exe', 'mimikatz.exe', '.RansomHubRdpSim.owner')) {
            $target = Join-Path $paths.DesktopRoot $name
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, 'Remove RansomHub scenario-owned Desktop artifact')) { Remove-RansomHubGeneratedFile -Path $target -WarnOnFailure }
            }
        }
        if ((Test-Path -LiteralPath $paths.DesktopRoot) -and -not (Get-ChildItem -LiteralPath $paths.DesktopRoot -Force)) {
            if ($PSCmdlet.ShouldProcess($paths.DesktopRoot, 'Remove empty scenario-owned Desktop directory')) { Remove-Item -LiteralPath $paths.DesktopRoot -Force }
        } elseif (Test-Path -LiteralPath $paths.DesktopRoot) {
            Write-Warning "Leaving non-empty Desktop directory in place: $($paths.DesktopRoot)"
        }
    }
}
if (Test-Path -LiteralPath $paths.Root) {
    if ($PSCmdlet.ShouldProcess($paths.Root, 'Remove fixed RansomHubRdpSim root')) { Remove-Item -LiteralPath $paths.Root -Recurse -Force }
}
Write-Host 'RansomHubRdpSim cleanup complete.' -ForegroundColor Green
