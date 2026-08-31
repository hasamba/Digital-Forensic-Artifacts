#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\MacroNokoSim-utilities.ps1";Assert-MacroNokoSafety -LabConfirmed:$LabConfirmed;$p=Initialize-MacroNokoEnvironment
$xls=Join-Path $p.Lure '4_202210250456866742.xls';Write-MacroNokoFile $xls 'INERT EXCEL MALDOC-NAME CANARY. No OLE content, VBA, image action, or macro.' 'Excel lure'
Write-MacroNokoFile(Join-Path $p.Lure 'macro-network-negative-record.json')(@{reportedUrl='https://simipimi.com';methods=@('OPTIONS','OPTIONS','GET');officeHeaders=@('X-Office-Major-Version','X-MSGETWEBURL','X-IDCRL_ACCEPTED','UA-CPU');requestsSent=0;payloadDecoded=$false}|ConvertTo-Json)'macro network evidence'
Write-MacroNokoFile(Join-Path $p.Payloads '7030270')'INERT ICEDID PAYLOAD-NAME CANARY. Not Base64-decoded malware.''IcedID canary'
$calc=Join-Path $p.Beach 'Documents\calc.exe';New-MacroNokoDecoy $calc 'renamed rundll32 IcedID loader stand-in';Invoke-MacroNokoDecoy $calc 'EXCEL.EXE -> Documents\calc.exe -> 7030270 IcedID DLL'
Write-MacroNokoFile(Join-Path $p.Payloads 'exdudipo.dll')'INERT ICEDID FIRST-STAGE DLL-NAME CANARY. Not a PE file.''IcedID stage';Write-MacroNokoFile(Join-Path $p.Payloads 'license.dat')'INERT ENCODED SECOND-STAGE NAME CANARY.''IcedID stage'
$task=[ordered]@{name='{3774AD25-8218-8099-89BA-CE96C6E9DC4E}';interval='PT1H';logonTrigger=$true;highestAvailable=$true;command='rundll32 exdudipo.dll,#1 --pa=AntiquePeanut\license.dat';created=$false};Write-MacroNokoFile(Join-Path $p.Evidence 'icedid-task-negative-record.json')($task|ConvertTo-Json)'task evidence'
foreach($target in @('kicknocisd.com / 159.65.169.200 campaign 3298576311','curabiebarristie.com and stayersa.art / 198.244.180.66:443','guaracheza.pics and belliecow.wiki / 45.66.248.119:443')){Invoke-MacroNokoLoopback 443 $target 'IcedID marker'}
Add-MacroNokoTimeline 0 initial-access 'Italian-targeted Excel attachment and image-triggered VBA represented' @{macrosExecuted=$false;downloads=0;techniques=@('T1566.001','T1059.005','T1204.002')};Add-MacroNokoTimeline .05 execution 'Downloaded numeric DLL and renamed rundll32 calc.exe ancestry represented' @{malwareExecuted=$false;techniques=@('T1036.003','T1218.011')};Add-MacroNokoTimeline .1 persistence 'IcedID hourly/logon task, exdudipo.dll, and license.dat represented' @{taskCreated=$false;technique='T1053.005'}
