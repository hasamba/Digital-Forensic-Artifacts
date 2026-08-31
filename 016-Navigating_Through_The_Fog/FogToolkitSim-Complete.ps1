#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory 'FogToolkitSim-utilities.ps1')
. (Join-Path $scriptDirectory 'FogToolkitSim-Phase1-OpenDirectoryInitialAccess.ps1')
. (Join-Path $scriptDirectory 'FogToolkitSim-Phase2-AnyDeskLateral.ps1')
. (Join-Path $scriptDirectory 'FogToolkitSim-Phase3-CredentialPrivilege.ps1')
. (Join-Path $scriptDirectory 'FogToolkitSim-Phase4-SliverTunneling.ps1')

Assert-FogLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-FogEnvironment
Invoke-FogOpenDirectoryInitialAccess -Paths $paths
Invoke-FogAnyDeskLateral -Paths $paths
Invoke-FogCredentialPrivilege -Paths $paths
Invoke-FogSliverTunneling -Paths $paths
Write-FogSummary -Paths $paths

Write-Host 'Fog open-directory toolkit simulation complete. Artifacts remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Timeline:      $($paths.Timeline)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-FogToolkitSim.ps1"
