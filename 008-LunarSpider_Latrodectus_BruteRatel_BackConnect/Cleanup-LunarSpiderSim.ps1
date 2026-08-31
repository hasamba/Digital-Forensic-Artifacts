#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]param([switch]$LabConfirmed)
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Remove-DFIRLabScenario -Config ([pscustomobject]@{Id='008-LunarSpider_Latrodectus_BruteRatel_BackConnect';RootName='LunarSpiderSim'}) -LabConfirmed:$LabConfirmed
