#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SettraSim-utilities.ps1";Assert-SxSafety -LabConfirmed:$LabConfirmed;$p=Initialize-SxEnvironment
# Ransom note text (RESTORE_FILES.txt) - generic representation; the report shows only an excerpt.
$note=@"
!!! YOUR NETWORK HAS BEEN COMPROMISED !!!

All of your important files have been encrypted.
To recover your files, contact us and follow the instructions.
Do not rename, move, or attempt to decrypt files yourself - you will lose them permanently.

Your ID: SETTRA-LAB-CANARY-0000

--------------------------------------------------------------------
GENERATED FORENSIC CANARY - NO DATA WAS ENCRYPTED IN THIS EXERCISE.
--------------------------------------------------------------------
"@
# Reported native recovery-inhibition + log-clearing commands, embedded in the ransomware executable and launched as child processes.
$reg=Join-Path $p.Payloads 'wevtutil.exe';New-SxDecoy $reg 'event-log clear command stand-in'
$reagentc=Join-Path $p.Payloads 'reagentc.exe';New-SxDecoy $reagentc 'Windows Recovery Environment disable stand-in'
$diskpart=Join-Path $p.Payloads 'diskpart.exe';New-SxDecoy $diskpart 'recovery-partition removal stand-in'
$ipconfig=Join-Path $p.Payloads 'ipconfig.exe';New-SxDecoy $ipconfig 'DNS cache flush stand-in'
$cipher=Join-Path $p.Payloads 'cipher.exe';New-SxDecoy $cipher 'free-space wipe stand-in'
# September incident cleared/attempted event-log list. Final entry is misspelled in the malware (Microsoft-Windows-Defender/Operational);
# the correct name is Microsoft-Windows-Windows-Defender/Operational, so that log was NOT cleared.
$logs=@(
 [ordered]@{name='Application';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Security';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='System';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Setup';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='ForwardedEvents';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-TerminalServices-RDPClient/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-Sysmon/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-PowerShell/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-WinRM/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-TaskScheduler/Operational';misspelled=$false;reportedCleared=$true},
 [ordered]@{name='Microsoft-Windows-Defender/Operational';misspelled=$true;reportedCleared=$false;correctName='Microsoft-Windows-Windows-Defender/Operational';reason='threat-actor typo; log name does not exist so clear failed'}
)
foreach($l in $logs){Invoke-SxDecoy $reg ("WEVTUTIL CL `"{0}`"" -f $l.name) 'ransomware executable child process'}
# Two victim organizations, each with the domain-named executable, launch path, and file extension from its incident.
$incidents=@(
 [ordered]@{host='JULY-RETAIL-CONSUMER';domain='retailcorp';launchPath='C$\Perflogs';ext='.locked';cipher=$true;flushdns=$true},
 [ordered]@{host='SEPT-MANUFACTURING';domain='mfgworks';launchPath='C$\Users\jsmith\Documents';ext='.locked_wip';cipher=$false;flushdns=$false}
)
foreach($i in $incidents){
 $r=Join-Path $p.Hosts $i.host
 $exeName=('{0}_win64.exe' -f $i.domain)  # ransomware executable named for the victim domain, appended with _win64.exe
 $exe=Join-Path $r ("{0}\{1}" -f $i.launchPath,$exeName)
 New-SxDecoy $exe ("Settra ransomware executable named for victim domain ({0}), launched from {1}" -f $exeName,$i.launchPath)
 Invoke-SxDecoy $exe ("{0} (Settra; embeds recovery-inhibition and log-clearing child commands)" -f $exeName) 'manual RMM session / MeshAgent'
 # Recovery-inhibition child commands embedded in the executable.
 Invoke-SxDecoy $reagentc 'reagentc.exe /disable (disable Windows Recovery Environment boot image)' $exeName
 Invoke-SxDecoy $diskpart 'diskpart.exe /s <script> (remove recovery partition; script not recovered by Huntress)' $exeName
 if($i.flushdns){Invoke-SxDecoy $ipconfig 'ipconfig /flushdns' $exeName}
 if($i.cipher){Invoke-SxDecoy $cipher 'cmd.exe /c cipher /w:D:\ >nul 2>&1 (overwrite free space on D: to hinder deleted-data recovery)' $exeName}
 # Canary user data + ransom notes + encryption sidecar markers. Originals remain intact; nothing is encrypted.
 foreach($d in @('C$\Users\jsmith\Desktop','C$\Finance','C$\Shared')){
  New-Item(Join-Path $r $d)-ItemType Directory -Force|Out-Null
  Write-SxFile(Join-Path $r "$d\RESTORE_FILES.txt")$note 'generated ransom-note canary'
 }
 foreach($f in @('C$\Finance\payroll.xlsx','C$\Shared\contract.docx','C$\Users\jsmith\Desktop\notes.txt')){
  Write-SxFile(Join-Path $r $f)"GENERATED CANARY for $($i.host); original never modified.`n" 'canary user data'
  Write-SxFile(Join-Path $r "$f$($i.ext)")"Encryption sidecar marker representing $($i.ext); original $f left intact.`n" 'encryption sidecar marker'
 }
 Write-SxJson(Join-Path $r 'incident-impact.json')([ordered]@{host=$i.host;reportedExecutable=$exeName;reportedLaunchPath=$i.launchPath;reportedExtension=$i.ext;reportedRansomNote='RESTORE_FILES.txt';reportedCipherWipe=$i.cipher;reportedFlushDns=$i.flushdns;filesEncrypted=0;originalFilesModified=0;shadowCopiesDeleted=0;recoveryDisabled=$false}) impact
}
Write-SxJson(Join-Path $p.Evidence 'impact-and-outcome.json')([ordered]@{reportedVariant='Settra';firstObserved='2026-06';reportedRmm='MeshAgent';reportedExecutableNaming='<victim-domain>_win64.exe';reportedNotes='RESTORE_FILES.txt';reportedExtensions=@('.locked (July)','.locked_wip (September)');reportedEventLogs=$logs;reportedDefenderLogMisspelling='Microsoft-Windows-Defender/Operational -> should be Microsoft-Windows-Windows-Defender/Operational (clear failed)';reportedRecoveryInhibition=@('reagentc /disable','diskpart recovery-partition removal','cipher /w:D:\\ (July only)','ipconfig /flushdns (July)');processesLaunched=0;logsCleared=0;recoveryOptionsDisabled=0;recoveryPartitionsRemoved=0;freeSpaceWiped=0;filesEncrypted=0;originalFilesModified=0}) impact
Add-SxTimeline 20 execution 'Domain-named <domain>_win64.exe launched (July: C:\Perflogs; September: user Documents) - represented' @{filesEncrypted=0}
Add-SxTimeline 25 impact 'Files "encrypted" (.locked / .locked_wip sidecars) and RESTORE_FILES.txt dropped - represented' @{filesEncrypted=0;notesDropped=0}
Add-SxTimeline 30 defense-evasion 'Event logs cleared via wevtutil; Defender log misspelled and NOT cleared - represented' @{logsCleared=0}
Add-SxTimeline 35 impact 'Recovery inhibited: reagentc /disable, diskpart partition removal, cipher free-space wipe (July) - represented' @{recoveryDisabled=0;freeSpaceWiped=0}
Write-SxJson(Join-Path $p.Evidence 'scenario-negative.json')([ordered]@{authenticationAttempts=0;credentialsAccessed=0;lsassAccessed=$false;rmmInstalled=0;driversLoaded=0;securityToolsImpaired=0;servicesCreated=0;logsCleared=0;recoveryOptionsDisabled=0;recoveryPartitionsRemoved=0;shadowCopiesDeleted=0;freeSpaceWiped=0;registryChanges=0;filesEncrypted=0;originalFilesModified=0;externalConnections=0;bytesTransferred=0;reportIocAddressesContacted=0}) safety
