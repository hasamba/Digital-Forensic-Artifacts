#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$LabConfirmed)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'ElpacoSim-utilities.ps1')
. (Join-Path $scriptDirectory 'ElpacoSim-Phase1-ConfluenceMeterpreter.ps1')
. (Join-Path $scriptDirectory 'ElpacoSim-Phase2-AnyDeskPrivilege.ps1')
. (Join-Path $scriptDirectory 'ElpacoSim-Phase3-CredentialDiscoveryLateral.ps1')
. (Join-Path $scriptDirectory 'ElpacoSim-Phase4-ElpacoImpact.ps1')

Assert-ElpacoLabSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-ElpacoEnvironment
Invoke-ElpacoConfluenceMeterpreter -Paths $paths
Invoke-ElpacoAnyDeskPrivilege -Paths $paths
Invoke-ElpacoCredentialDiscoveryLateral -Paths $paths
Invoke-ElpacoImpact -Paths $paths
Write-ElpacoSummary -Paths $paths

Write-Host 'ELPACO Confluence simulation complete. Artifacts remain for investigation.' -ForegroundColor Cyan
Write-Host "Scenario root: $($paths.Root)"
Write-Host "Manifest:      $($paths.Manifest)"
Write-Host "Timeline:      $($paths.Timeline)"
Write-Host "Cleanup:       $scriptDirectory\Cleanup-ElpacoSim.ps1"
