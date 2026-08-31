#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Remove-DFIRLabScenario -Config ([pscustomobject]@{Id='004-Bing_Search_Bumblebee_AdaptixC2_Akira';RootName='AkiraSim'}) -LabConfirmed:$LabConfirmed
