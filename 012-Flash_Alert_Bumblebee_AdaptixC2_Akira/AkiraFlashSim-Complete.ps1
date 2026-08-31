#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'AkiraFlashSim-utilities.ps1')
. (Join-Path $scriptDirectory 'AkiraFlashSim-Phase1-SEOInstallerBumblebee.ps1')
. (Join-Path $scriptDirectory 'AkiraFlashSim-Phase2-AdaptixDiscoveryPersistence.ps1')
. (Join-Path $scriptDirectory 'AkiraFlashSim-Phase3-CredentialAccessExfiltration.ps1')
. (Join-Path $scriptDirectory 'AkiraFlashSim-Phase4-TwoWaveImpact.ps1')

Assert-AkiraFlashLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-AkiraFlashEnvironment

Invoke-AkiraFlashSEOInstallerBumblebee -Paths $paths
Invoke-AkiraFlashAdaptixDiscoveryPersistence -Paths $paths
Invoke-AkiraFlashCredentialAccessExfiltration -Paths $paths
Invoke-AkiraFlashTwoWaveImpact -Paths $paths
Write-AkiraFlashSummary -Paths $paths

Write-Host 'Akira flash-alert simulation complete. Artifacts intentionally remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Timeline:      $($paths.Timeline)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-AkiraFlashSim.ps1"
