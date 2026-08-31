#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch]$LabConfirmed,
    [switch]$LaunchVisibleBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'BengalSEOSim-utilities.ps1')
. (Join-Path $scriptDirectory 'BengalSEOSim-Phase1-LureAndTDS.ps1')
. (Join-Path $scriptDirectory 'BengalSEOSim-Phase2-PayloadDelivery.ps1')
. (Join-Path $scriptDirectory 'BengalSEOSim-Phase3-MayaBotAndScam.ps1')

Assert-BengalLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-BengalEnvironment

Invoke-BengalLureAndTDS -Paths $paths -LaunchVisibleBrowser:$LaunchVisibleBrowser
Invoke-BengalPayloadDelivery -Paths $paths
Invoke-BengalMayaBotAndScam -Paths $paths
Write-BengalSummary -Paths $paths

Write-Host 'BengalSEO simulation complete. Artifacts intentionally remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-BengalSEOSim.ps1"
