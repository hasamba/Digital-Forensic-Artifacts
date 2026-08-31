#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DagonSim-utilities.ps1";Assert-DagonSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DagonEnvironment;if(-not(Test-Path(Join-Path $p.Evidence 'day28-portproxy.json'))){throw'Run phase 2 first'}
$locker=Join-Path $p.Impact 'sysfunc.dll';New-DagonDecoy $locker 'Dagon Locker DLL decoy';Write-DagonFile(Join-Path $p.Impact 'sysfunc.cmd')'@echo off`r`nREM INERT service-stop/shadow-delete/recovery-mode/locker deployment evidence`r`necho ICEDID-DAGON-CANARY''locker batch canary';$command='invokemodule -module locker -locker REDACTED.dll -lockerpath programdata\microsoft -lockertype dll -lockername sysfunc -lockerdeployonly $true -lockerentrypoint run -handlesystems custom';$impact=[ordered]@{reportedCommand=$command;deployment='AWSCollector SMB plus generated sysfunc.cmd';serviceFamilies=@('eventlog','wecsvc','Sophos','ArcticWolf','Cybereason','Cylance','Veeam','BackupExec','Acronis','OSSEC');referencedFamilies=@('Egregor','REvil','Xing','Quantum','Mount Locker','Conti');remoteCopies=0;remoteExecutions=0;servicesStopped=0;securityToolsChanged=0;shadowCopiesDeleted=0;bootChanged=$false;telegramMessages=0;encryption=$false;reportedTTRHours=684}
Write-DagonFile(Join-Path $p.Evidence 'dagon-deployment-negative-record.json')($impact|ConvertTo-Json -Depth 8)'Dagon impact negative record';Invoke-DagonDecoy $locker 'rundll32.exe C:\ProgramData\Microsoft\sysfunc.dll,run /target=C:\ProgramData\Microsoft\WPD\ [ECHO-ONLY]'
foreach($h in @('BEACHHEAD','DC1','FILE-SRV','VIRT-MGR','BACKUP-SRV','APP-SRV')){$d=Join-Path $p.Impact $h;New-Item $d -ItemType Directory -Force|Out-Null;foreach($n in @('operations.docx','vm-backup.bak','finance.xlsx')){$o=Join-Path $d $n;Write-DagonFile $o "Generated intact $h/$n; not encrypted." 'intact canary';Write-DagonFile "$o.dagoned-CANARY" "Marker only for $n; original intact." 'Dagon marker'};Write-DagonFile(Join-Path $d 'README-DAGON.txt')'INERT DAGON LOCKER CANARY NOTE. No encryption, contact, payment, service stop, or recovery impairment.''ransom note canary'}
$log=@'
Ver 5.1 x64
CMDLINE: rundll32.exe C:\programdata\microsoft\sysfunc.dll,run /target=C:\programdata\microsoft\WPD\
[INFO] locker.init > locker ext .dagoned
[INFO] CANARY MODE - no service/process action and no encryption
Total crypted: 0.000 GB
Locked: 0
[OK] locker > finished
'@;Write-DagonFile(Join-Path $p.Impact 'sysfunc.dll.log')$log 'inert Dagon execution log';Add-DagonTimeline 41040 impact 'Day-29 Dagon Locker deployment represented at 684-hour TTR' @{remoteHosts=0;servicesStopped=0;shadowsDeleted=0;encryption=$false;intactOriginals=18;markers=18;techniques=@('T1489','T1490','T1486')}
