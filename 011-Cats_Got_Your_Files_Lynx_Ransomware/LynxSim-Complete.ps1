#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'LynxSim-utilities.ps1')
. (Join-Path $scriptDirectory 'LynxSim-Phase1-InitialAccessDiscovery.ps1')
. (Join-Path $scriptDirectory 'LynxSim-Phase2-PersistenceLateralMovement.ps1')
. (Join-Path $scriptDirectory 'LynxSim-Phase3-CollectionExfiltration.ps1')
. (Join-Path $scriptDirectory 'LynxSim-Phase4-Impact.ps1')

Assert-LynxLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-LynxEnvironment

Invoke-LynxInitialAccessDiscovery -Paths $paths
Invoke-LynxPersistenceAndLateralMovement -Paths $paths
Invoke-LynxCollectionAndExfiltration -Paths $paths
Invoke-LynxImpact -Paths $paths
Write-LynxSummary -Paths $paths

Write-Host 'Lynx simulation complete. Artifacts intentionally remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Timeline:      $($paths.Timeline)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-LynxSim.ps1"
