#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([Parameter(Mandatory)][switch]$LabConfirmed)
$d=Split-Path -Parent $MyInvocation.MyCommand.Path;. (Join-Path $d 'EggResumeSim-utilities.ps1');. (Join-Path $d 'EggResumeSim-Phase1-LureMoreEggs.ps1');. (Join-Path $d 'EggResumeSim-Phase2-CobaltPyramidDiscovery.ps1');. (Join-Path $d 'EggResumeSim-Phase3-VeeamCloudflaredEviction.ps1');Assert-EggSafety -LabConfirmed:$LabConfirmed;$p=Initialize-EggEnvironment;Invoke-EggLureMoreEggs $p;Invoke-EggCobaltPyramidDiscovery $p;Invoke-EggVeeamCloudflaredEviction $p;Write-EggSummary $p;Write-Host "Egg-Cellent Resume simulation complete: $($p.Root)" -ForegroundColor Cyan
