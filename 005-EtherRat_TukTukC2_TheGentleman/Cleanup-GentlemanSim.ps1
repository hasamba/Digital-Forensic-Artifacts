#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Remove-DFIRLabScenario -Config ([pscustomobject]@{Id='005-EtherRat_TukTukC2_TheGentleman';RootName='GentlemanSim'}) -LabConfirmed:$LabConfirmed
