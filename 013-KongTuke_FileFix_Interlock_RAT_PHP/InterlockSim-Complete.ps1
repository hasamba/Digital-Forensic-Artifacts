#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'InterlockSim-utilities.ps1')
. (Join-Path $scriptDirectory 'InterlockSim-Phase1-WebInjectFileFix.ps1')
. (Join-Path $scriptDirectory 'InterlockSim-Phase2-PHPExecutionDiscovery.ps1')
. (Join-Path $scriptDirectory 'InterlockSim-Phase3-C2PersistenceCapabilities.ps1')

Assert-InterlockLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-InterlockEnvironment

Invoke-InterlockWebInjectFileFix -Paths $paths
Invoke-InterlockPHPExecutionDiscovery -Paths $paths
Invoke-InterlockC2PersistenceCapabilities -Paths $paths
Write-InterlockSummary -Paths $paths

Write-Host 'Interlock FileFix/PHP RAT simulation complete. Artifacts remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "PHP artifacts: $($paths.PhpRoot)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Timeline:      $($paths.Timeline)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-InterlockSim.ps1"
