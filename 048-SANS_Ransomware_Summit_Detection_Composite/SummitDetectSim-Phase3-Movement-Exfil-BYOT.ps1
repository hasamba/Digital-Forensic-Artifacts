#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SummitDetectSim-utilities.ps1"
Assert-SummitDetectSafety -LabConfirmed:$LabConfirmed
$p = Initialize-SummitDetectEnvironment

$remote = Join-Path $p.Payloads 'PsExec.exe'
New-SummitDetectDecoy $remote 'PsExec/WMI/Cobalt movement stand-in'
foreach ($command in @('PsExec.exe \\LAB-SRV01.invalid generated.exe','wmic /node:LAB-SRV01.invalid process call create generated.exe','jump psexec LAB-DC01.invalid','copy generated.exe \\LAB-SRV01.invalid\ADMIN$')) { Invoke-SummitDetectDecoy $remote $command 'generated beacon' }
foreach ($port in @(445,135)) { Invoke-SummitDetectLoopback $port "PsExec, admin-share, and remote-WMI movement detection on port $port" 'lateral marker' }

foreach ($name in @('Legal-Archive.zip','generated-lsass.dmp')) { Write-SummitDetectFile (Join-Path $p.Collection $name) "GENERATED COLLECTION CANARY: $name. Contains no organizational data, process memory, or secrets." 'collection canary' }
$transfer = Join-Path $p.Payloads 'rclone.exe'
New-SummitDetectDecoy $transfer 'Rclone/WinSCP/FileZilla stand-in'
foreach ($command in @('rclone.exe copy generated-collection mega:case --transfers 4','WinSCP.exe generated SFTP upload','FileZilla.exe generated FTP upload','upload generated-lsass.dmp to regional ufile.io subdomain')) { Invoke-SummitDetectDecoy $transfer $command 'generated operator' }
foreach ($target in @('MEGA upload service','ufile.io regional upload service','generated SFTP/FTP destination')) { Invoke-SummitDetectLoopback 443 $target 'exfiltration detection marker' }

Invoke-SummitDetectDecoy $remote 'operator shell mistake: av_query; getsystem; execute-assembly entered in cmd.exe' 'injected process shell'
foreach ($name in @('adf.bat','adfind.bat','locker.bat','kill.bat','def.bat','start.bat','shadow.bat','logdelete.bat','closeapps.bat')) { Write-SummitDetectFile (Join-Path $p.Staging $name) "@REM INERT BYOT FILENAME CANARY: $name. No command or impact action is present." 'BYOT detection canary' }
Write-SummitDetectFile (Join-Path $p.Evidence 'movement-exfil-byot-negative-record.json') (@{remoteHostsTouched=0;domainControllersTouched=0;remoteProcessesCreated=0;remoteServicesCreated=0;adminSharesAccessed=0;realFilesRead=0;archivesCreated=0;cloudOrTransferServicesAccessed=0;bytesTransferred=0;operatorCommandsExecuted=0;BYOTScriptsExecuted=0;logsCleared=0;shadowCopiesDeleted=0;filesEncrypted=0;impactActions=0} | ConvertTo-Json) 'phase safety record'
Add-SummitDetectTimeline 6 lateral-movement 'PsExec, Cobalt jump, remote WMI, and admin-share copy detections represented' @{remoteHostsTouched=0}
Add-SummitDetectTimeline 7 collection-exfiltration 'Rclone/MEGA, WinSCP, FileZilla, and ufile LSASS-upload detections represented' @{realFilesRead=0;bytesTransferred=0}
Add-SummitDetectTimeline 8 operator-tradecraft 'Cobalt operator bloopers and nine recurring BYOT batch filenames represented' @{commandsExecuted=0;impactActions=0}
