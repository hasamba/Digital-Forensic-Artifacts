#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DefenderControlSim-utilities.ps1";Assert-DCSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DCEnvironment
Write-DCFile(Join-Path $p.Evidence 'reported-ui-state.txt')"SIMULATED SCREENSHOT TRANSCRIPT`nReported: Defender menu vanished; Windows said organization manages Defender.`nActual: no Windows Security UI, service, policy, registry, or driver state was changed." ui-evidence;Write-DCFile(Join-Path $p.Evidence 'safety-state.json')(@{DefenderStateRead=$false;DefenderStateChanged=$false;securityControlsImpaired=$false;registryChanges=0;serviceChanges=0;driverChanges=0;policyChanges=0;systemRebooted=$false}|ConvertTo-Json) safety;Add-DCTimeline 15 defense-evasion 'Reported post-disable UI state represented as retained analyst evidence' @{DefenderStateChanged=$false;securityControlsImpaired=$false}
