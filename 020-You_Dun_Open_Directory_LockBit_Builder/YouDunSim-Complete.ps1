#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([Parameter(Mandatory)][switch]$LabConfirmed)
$d=Split-Path -Parent $MyInvocation.MyCommand.Path;. (Join-Path $d 'YouDunSim-utilities.ps1');. (Join-Path $d 'YouDunSim-Phase1-ReconExploitation.ps1');. (Join-Path $d 'YouDunSim-Phase2-C2Toolkit.ps1');. (Join-Path $d 'YouDunSim-Phase3-PrivilegeImpact.ps1');Assert-YouDunSafety -LabConfirmed:$LabConfirmed;$p=Initialize-YouDunEnvironment;Invoke-YouDunReconExploitation $p;Invoke-YouDunC2Toolkit $p;Invoke-YouDunPrivilegeImpact $p;Write-YouDunSummary $p;Write-Host "You Dun open-directory simulation complete: $($p.Root)" -ForegroundColor Cyan
