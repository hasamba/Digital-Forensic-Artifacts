#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GraceWipeSim-utilities.ps1"
Assert-GraceWipeSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-GraceWipeEnvironment

$cmd = Join-Path $paths.Beach 'discovery\cmd.exe'
New-GraceWipeDecoy $cmd 'Cobalt Strike and FlawedGrace command stand-in'
$reportedCommands = @(
    'net group "Domain Admins" /domain','net group "Domain Controllers" /domain','net group /domain','net localgroup "Remote Desktop Users"','net localgroup Administrators','net user REDACTED /domain','nltest /domain_trusts','quser','tasklist /S GENERATED-HOST',
    'AdFind.exe -f "&(objectcategory=computer)" operatingSystem -csv > 1.csv','AdFind.exe -f "objectcategory=person" sAMAccountName name displayName givenName department description title mail logonCount -csv > person.csv',
    'for /f %i in (hosts.txt) do ping -n 1 %i | find "TTL"','for /f %i in (servers_live.txt) do net view \\%i /all','dir \\GENERATED-HOST\C$','wmic /node:GENERATED-HOST process get executablepath','powershell Get-MpComputerStatus','Impacket atexec discovery','Cobalt Strike jump psexec'
)
foreach ($reported in $reportedCommands) { Invoke-GraceWipeDecoy $cmd $reported }

foreach ($name in @('hosts.txt','servers.txt','hosts_live.txt','servers_live.txt','servers_live_netview.txt','servers_live_dir.txt','1.txt','KMzFGwGn.tmp','1.csv','person.csv')) {
    Write-GraceWipeFile (Join-Path $paths.Staging $name) "GENERATED DISCOVERY RESULT CANARY: $name`nNo directory, registry, process, session, share, DNS, or remote-host query occurred." 'discovery staging canary'
}
New-GraceWipeDecoy (Join-Path $paths.Payloads 'AdFind.exe') 'AdFind filename stand-in' 'c92c158d7c37fea795114fa6491fe5f145ad2f8c08776b18ae79db811e8e36a3'
foreach ($name in @('aB3dE7gH.tmp','kL4mN8pQ.tmp')) { Write-GraceWipeFile (Join-Path $paths.Evidence $name) 'INERT RANDOM-NAME HIVE-DUMP CANARY. Contains no registry or credential material.' 'credential artifact canary' }
$credential = [ordered]@{RemoteRegistryStarted=$false;samOrSystemHiveRead=$false;lsassAccessed=$false;credentialsOrHashesCollected=0;passTheHashPerformed=$false;logonType9Created=$false;seclogoUsed=$false}
Write-GraceWipeFile (Join-Path $paths.Evidence 'credential-access-negative-record.json') ($credential | ConvertTo-Json) 'credential negative record'
foreach ($hostName in @('APP-01','FILE-01','SQL-01','WKSTN-01')) { New-Item -Path (Join-Path $paths.Hosts $hostName) -ItemType Directory -Force | Out-Null }
$lateral = [ordered]@{remoteHostsTouched=0;atexecTasksCreated=0;psexecServicesCreated=0;wmiQueries=0;smbAdminSharesAccessed=0;FlawedGraceLoadedOnRemoteHosts=$false;movementCadenceMinutes='5-20 (reported only)'}
Write-GraceWipeFile (Join-Path $paths.Evidence 'lateral-movement-negative-record.json') ($lateral | ConvertTo-Json) 'lateral negative record'
Invoke-GraceWipeLoopback 443 '5.188.206.78 Cobalt Strike /ga.js and /submit.php' 'HTTPS marker'
Add-GraceWipeTimeline 1 credential-access 'RemoteRegistry hive dump, LSASS access, and local-admin pass-the-hash represented' @{credentialMaterialRead=$false;techniques=@('T1003.001','T1003.002','T1550.002')}
Add-GraceWipeTimeline 2 command-and-control 'Truebot loaded Cobalt Strike and then went dormant' @{beaconExecuted=$false}
Add-GraceWipeTimeline 4 discovery 'Net, nltest, tasklist, AdFind, share, process, session, and Defender discovery represented' @{realQueries=0;techniques=@('T1069.002','T1069.001','T1482','T1057','T1087.002','T1018','T1518.001')}
Add-GraceWipeTimeline 4.5 lateral-movement 'atexec, jump psexec, WMI, and remote FlawedGrace loading represented' @{remoteHostsTouched=0;tasksCreated=0;servicesCreated=0;techniques=@('T1021.002','T1543.003')}
