#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SummitDetectSim-utilities.ps1"
Assert-SummitDetectSafety -LabConfirmed:$LabConfirmed
$p = Initialize-SummitDetectEnvironment

Write-SummitDetectFile (Join-Path $p.Delivery 'invoice.xlsb') 'INERT OFFICE-MACRO CANARY. Not a workbook and contains no macro.' 'Office lure'
Write-SummitDetectFile (Join-Path $p.Delivery 'delivery.iso') 'INERT ISO-NAME CANARY. Not a disk image and never mounted.' 'ISO lure'
Write-SummitDetectFile (Join-Path $p.Delivery 'document.lnk') 'INERT LNK-NAME CANARY. Not a shortcut.' 'LNK lure'
$office = Join-Path $p.Payloads 'regsvr32.exe'
New-SummitDetectDecoy $office 'Office-child and abnormal-drive LOLBin stand-in'
foreach ($command in @('EXCEL.EXE -> regsvr32.exe /s generated.ocx','WINWORD.EXE -> rundll32.exe generated.dll,Entry','EXCEL.EXE -> cmd.exe /c generated.bat','WINWORD.EXE -> powershell.exe -NoProfile [generated command]','EXCEL.EXE -> wmic process call create [generated command]','rundll32.exe E:\generated.dll,Entry')) { Invoke-SummitDetectDecoy $office $command 'Office application' }
Write-SummitDetectFile (Join-Path $p.Evidence 'synthetic-vhdmp-events.json') (@{events=@(@{eventId=1;action='ISO mount represented'},@{eventId=12;action='ISO dismount represented'});synthetic=$true;actualMounts=0} | ConvertTo-Json -Depth 5) 'synthetic ISO telemetry'

foreach ($name in @('scheduled-task.xml','bits-job.json','exchange-webshell.aspx','AnyDesk.exe','Splashtop.exe','NetSupport.exe')) { Write-SummitDetectFile (Join-Path $p.Staging $name) "INERT DETECTION CANARY: $name. No service, task, job, shell, or remote tool exists." 'persistence canary' }
Invoke-SummitDetectDecoy $office 'schtasks /create /tn generated-lolbin-task; BITS job every 3 hours; w3wp.exe -> cmd.exe web shell; AnyDesk/Splashtop/NetSupport service install' 'generated foothold'
foreach ($target in @('AnyDesk service','Splashtop service','NetSupport service')) { Invoke-SummitDetectLoopback 443 $target 'remote-access detection marker' }
Write-SummitDetectFile (Join-Path $p.Evidence 'delivery-persistence-negative-record.json') (@{officeDocumentsOpened=0;macrosExecuted=0;ISOMounts=0;MOTWBypasses=0;payloadsExecuted=0;scheduledTasksCreated=0;BITSJobsCreated=0;webShellsCreated=0;RMMToolsInstalled=0;servicesCreated=0} | ConvertTo-Json) 'phase safety record'
Add-SummitDetectTimeline 0 initial-access 'Office children, ISO/LNK/MOTW, VHDMP 1/12, and abnormal-drive rundll32 detections represented' @{executions=0;mounts=0}
Add-SummitDetectTimeline 1 persistence 'Scheduled task, three-hour BITS job, Exchange/web-server shell, and RMM persistence detections represented' @{persistenceChanges=0}
