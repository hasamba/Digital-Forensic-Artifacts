#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Remove-DFIRLabScenario -Config ([pscustomobject]@{Id='002-Fake Zoom Ends in BlackSuit Ransomware';RootName='BlackSuitZoomSim'}) -LabConfirmed:$LabConfirmed
