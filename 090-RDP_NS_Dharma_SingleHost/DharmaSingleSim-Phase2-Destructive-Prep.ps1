#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DharmaSingleSim-utilities.ps1";Assert-DSSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DSEnvironment
$runner=Join-Path $p.Payloads 'prep-runner.exe';New-DSDecoy -Path $runner -Role 'destructive-preparation telemetry stand-in'
$commands=@('shadow.bat -> vssadmin delete shadows /all','LogDelete.bat -> FOR /F "delims=" %%I IN (''WEVTUTIL EL'') DO WEVTUTIL CL "%%I"','closeapps.bat loops through Exchange, Veeam, SQL, backup, web, and security processes with taskkill')
foreach($command in $commands){Invoke-DSDecoy -FilePath $runner -Reported $command -Parent 'RDP operator shell' -Label 'NO-DESTRUCTIVE-ACTION'}
foreach($file in @('Shadow.bat','LogDelete.bat','closeapps.bat')){Write-DSFile -Path(Join-Path $p.Payloads $file)-Content "INERT $file-NAME CANARY. No commands." -Purpose payload-canary}
Write-DSJson -Path(Join-Path $p.Evidence 'destructive-prep.json')-Object([ordered]@{reportedCommands=$commands;shadowCopiesEnumerated=0;shadowCopiesDeleted=0;eventLogsEnumerated=0;eventLogsCleared=0;processesEnumerated=0;processesTerminated=0;servicesStopped=0})-Purpose impact-preparation
Write-DSJson -Path(Join-Path $p.Evidence 'persistence-markers.json')-Object([ordered]@{reportedStartupPaths=@('C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\1pgp.exe','C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\1pgp.exe');reportedRunKey='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\1pgp.exe';startupFilesWritten=0;registryValuesWritten=0})-Purpose persistence
Add-DSTimeline 40 impact-preparation 'shadow.bat shadow-copy deletion represented' @{shadowCopiesDeleted=0};Add-DSTimeline 41 defense-evasion 'LogDelete.bat event-log clearing represented seconds later' @{eventLogsCleared=0};Add-DSTimeline 43 impact-preparation 'closeapps.bat process termination and 1pgp persistence represented' @{processesTerminated=0;startupFilesWritten=0;registryValuesWritten=0}
Write-DSJson -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{shadowCopiesDeleted=0;eventLogsCleared=0;processesTerminated=0;servicesStopped=0;startupFilesWritten=0;registryValuesWritten=0;securityControlsChanged=0})-Purpose safety
