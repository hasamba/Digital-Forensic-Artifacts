#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SummitDetectSim-utilities.ps1"
Assert-SummitDetectSafety -LabConfirmed:$LabConfirmed
$p = Initialize-SummitDetectEnvironment

$survey = Join-Path $p.Payloads 'survey.exe'
New-SummitDetectDecoy $survey 'privilege, credential, defense, and discovery stand-in'
foreach ($command in @('getsystem','procdump64.exe -ma lsass.exe generated-lsass.dmp','Taskmgr.exe create dump file for lsass.exe','mimikatz sekurlsa::logonpasswords','ntdsutil snapshot and IFM command','reg save HKLM\SAM generated-sam.hive','reg save HKLM\SYSTEM generated-system.hive','Set-MpPreference -DisableRealtimeMonitoring $true')) { Invoke-SummitDetectDecoy $survey $command 'Cobalt/interactive operator' }
foreach ($name in @('generated-lsass.dmp','generated-sam.hive','generated-system.hive','ntds.dit')) { Write-SummitDetectFile (Join-Path $p.Staging $name) "GENERATED CREDENTIAL-ARTIFACT NAME: $name. Contains no memory, registry data, directory database, credentials, or secrets." 'credential canary' }

$commands = @('whoami /all','net user','net group "domain admins" /domain','nltest /domain_trusts','ipconfig /all','netstat -ano','chcp','wmic computersystem get domain','AdFind.exe -f objectcategory=computer','Advanced_IP_Scanner.exe generated-range')
foreach ($command in $commands) { Invoke-SummitDetectDecoy $survey $command 'generated beacon'; Add-SummitDetectManifest discovery-command generated-commandline-only represented @{reportedCommandLine=$command;directoryQueries=0;packetsSent=0} }
foreach ($name in @('adfind-results.txt','ip-scanner-results.csv')) { Write-SummitDetectFile (Join-Path $p.Staging $name) "GENERATED DISCOVERY OUTPUT: $name. No host, domain, or network query occurred." 'discovery output' }
Write-SummitDetectFile (Join-Path $p.Evidence 'credential-defense-discovery-negative-record.json') (@{privilegeEscalations=0;LSASSAccessed=$false;memoryDumpsCreated=0;NTDSAccessed=$false;registryHivesRead=0;credentialsCollected=0;securityControlsChanged=0;directoryQueries=0;remoteHostsScanned=0;packetsSent=0} | ConvertTo-Json) 'phase safety record'
Add-SummitDetectTimeline 3 privilege-credential-access 'GetSystem, LSASS access and dumps, ntdsutil, registry hives, and Mimikatz detections represented' @{privilegeEscalations=0;credentialsCollected=0}
Add-SummitDetectTimeline 4 defense-evasion-discovery 'Defender impairment, native recon, AdFind, and Advanced IP Scanner detections represented' @{securityControlsChanged=0;queries=0;packetsSent=0}
