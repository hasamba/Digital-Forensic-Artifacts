#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Remove-DFIRLabScenario -Config ([pscustomobject]@{Id='009-Blurring_Lines_Play_RansomHub_DragonForce';RootName='BlurringLinesSim'}) -LabConfirmed:$LabConfirmed
