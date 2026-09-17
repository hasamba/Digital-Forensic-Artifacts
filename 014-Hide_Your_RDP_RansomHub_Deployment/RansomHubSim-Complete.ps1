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

Write-Host '[Phase 1/4] Initial Access & Discovery - starting...' -ForegroundColor Yellow
Invoke-RansomHubInitialAccessDiscovery -Paths $paths
Write-Host '[Phase 1/4] Initial Access & Discovery - complete.' -ForegroundColor Green

Write-Host '[Phase 2/4] Credential Access, Persistence & Lateral Movement - starting...' -ForegroundColor Yellow
Invoke-RansomHubCredentialPersistenceLateral -Paths $paths
Write-Host '[Phase 2/4] Credential Access, Persistence & Lateral Movement - complete.' -ForegroundColor Green

Write-Host '[Phase 3/4] Rclone Exfiltration - starting...' -ForegroundColor Yellow
Invoke-RansomHubRcloneExfiltration -Paths $paths
Write-Host '[Phase 3/4] Rclone Exfiltration - complete.' -ForegroundColor Green

Write-Host '[Phase 4/4] Impact - starting...' -ForegroundColor Yellow
Invoke-RansomHubImpact -Paths $paths
Write-Host '[Phase 4/4] Impact - complete.' -ForegroundColor Green

Write-RansomHubSummary -Paths $paths

Write-Host 'RansomHub RDP simulation complete. Artifacts remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root:   $($paths.Root)"
Write-Host "Desktop tools:  $($paths.DesktopRoot)"
Write-Host "Manifest:       $($paths.Manifest)"
Write-Host "Timeline:       $($paths.Timeline)"
Write-Host "Cleanup:        $scriptDirectory\Cleanup-RansomHubSim.ps1"
