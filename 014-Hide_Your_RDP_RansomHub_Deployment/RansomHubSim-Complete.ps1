#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'RansomHubSim-utilities.ps1')
. (Join-Path $scriptDirectory 'RansomHubSim-Phase1-InitialAccessDiscovery.ps1')
. (Join-Path $scriptDirectory 'RansomHubSim-Phase2-CredentialPersistenceLateral.ps1')
. (Join-Path $scriptDirectory 'RansomHubSim-Phase3-RcloneExfiltration.ps1')
. (Join-Path $scriptDirectory 'RansomHubSim-Phase4-Impact.ps1')

Assert-RansomHubLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-RansomHubEnvironment

Invoke-RansomHubInitialAccessDiscovery -Paths $paths
Invoke-RansomHubCredentialPersistenceLateral -Paths $paths
Invoke-RansomHubRcloneExfiltration -Paths $paths
Invoke-RansomHubImpact -Paths $paths
Write-RansomHubSummary -Paths $paths

Write-Host 'RansomHub RDP simulation complete. Artifacts remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root:   $($paths.Root)"
Write-Host "Desktop tools:  $($paths.DesktopRoot)"
Write-Host "Manifest:       $($paths.Manifest)"
Write-Host "Timeline:       $($paths.Timeline)"
Write-Host "Cleanup:        $scriptDirectory\Cleanup-RansomHubSim.ps1"
