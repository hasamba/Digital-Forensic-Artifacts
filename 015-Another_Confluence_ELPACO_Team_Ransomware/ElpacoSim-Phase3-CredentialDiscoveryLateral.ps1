function Invoke-ElpacoCredentialDiscoveryLateral {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-ElpacoTimeline
    $mimikatz = Join-Path $Paths.Tools 'mimikatz\x64\mimikatz.exe'
    $mimikatz32 = Join-Path $Paths.Tools 'mimikatz\Win32\mimikatz.exe'
    foreach ($binary in @($mimikatz, $mimikatz32)) { New-ElpacoBinaryDecoy -Path $binary -Role 'Mimikatz process-name canary' }
    foreach ($name in @('mimidrv.sys', 'mimilove.exe', 'mimilib.dll')) {
        Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Tools "mimikatz\$name") -Content "ELPACO INERT MIMIKATZ COMPONENT: $name" -Purpose 'Mimikatz file-set canary' -Timestamp $time.Credential
    }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Tools '!start.cmd') -Content @'
@echo off
REM ELPACO CANARY. Reported only; never access LSASS/SAM.
REM .\mimikatz\x64\mimikatz.exe "privilege::debug" "log .\!logs\Result.txt" "sekurlsa::logonPasswords" "token::elevate" "lsadump::sam" exit
echo ELPACO-CANARY: credential access disabled
'@ -Purpose 'inert Mimikatz launcher canary' -Timestamp $time.Credential
    foreach ($binary in @($mimikatz, $mimikatz32, $mimikatz, $mimikatz32)) {
        Invoke-ElpacoDecoyProcess -FilePath $binary -ReportedCommandLine 'mimikatz.exe "privilege::debug" "log .\!logs\Result.txt" "sekurlsa::logonPasswords" "token::elevate" "lsadump::sam" exit'
    }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Tools '!logs\Result.txt') -Content @'
Authentication Id : 0 ; 424242 (00000000:00067932)
User Name         : CANARY_DA
Domain            : LAB.INVALID
NTLM              : 00000000000000000000000000000000
NOTICE: generated values only; no credential source or LSASS was opened.
'@ -Purpose 'synthetic Mimikatz output' -Timestamp $time.Credential.AddMinutes(1)

    $processAccess = @()
    1..4 | ForEach-Object { $processAccess += @{ EventId = 10; SourceImage = 'mimikatz.exe'; TargetImage = 'lsass.exe'; GrantedAccess = '0x1010'; actualAccess = false } }
    $processAccess += @{ EventId = 10; SourceImage = 'ProcessHacker.exe'; TargetImage = 'lsass.exe'; GrantedAccess = '0x1010'; actualAccess = false; host = 'BACKUP01' }
    $processAccess += @{ EventId = 10; SourceImage = 'ProcessHacker.exe'; TargetImage = 'lsass.exe'; GrantedAccess = '0x1010'; actualAccess = false; host = 'FILE01' }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'synthetic-sysmon-process-access.json') -Content ($processAccess | ConvertTo-Json -Depth 5) -Purpose 'credential-access detection canaries' -Timestamp $time.Credential

    $secretsdump = Join-Path $Paths.Tools 'secretsdump.exe'
    New-ElpacoBinaryDecoy -Path $secretsdump -Role 'Impacket secretsdump process-name canary' -ReportedSha256 'c3405d9c9d593d75d773c0615254e69d0362954384058ee970a3ec0944519c37'
    1..8 | ForEach-Object {
        Invoke-ElpacoDecoyProcess -FilePath $secretsdump -ReportedCommandLine "secretsdump.exe -hashes :00000000000000000000000000000000 CANARY$($_ % 2)@127.0.0.1"
    }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Tools 'sessionresume_QaZxSwEd') -Content 'synthetic Impacket resume marker; no remote registry, SAM, LSA, or NTDS access' -Purpose 'Impacket sessionresume filename canary' -Timestamp $time.Credential.AddMinutes(25)

    $netscan = Join-Path $Paths.Desktop 'netscan.exe'
    New-ElpacoBinaryDecoy -Path $netscan -Role 'SoftPerfect NetScan process-name canary' -ReportedSha256 '5748bfb17e662fb6d197886a69df47f1071052c3381eb1c609a2bc5dba8c2992'
    Invoke-ElpacoDecoyProcess -FilePath $netscan -ReportedCommandLine 'netscan.exe ports 88,137,445,3389,6160 targets LAB-SUBNET (actual 127.0.0.1)'
    foreach ($port in @(88, 137, 445, 3389, 6160)) { Invoke-ElpacoLoopbackPort -Port $port -ReportedTarget "synthetic local subnet port $port" }
    foreach ($hostName in @('DC01', 'DC02', 'BACKUP01', 'FILE01')) {
        $sharePath = Join-Path $Paths.Hosts "$hostName\share"
        New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
        Write-ElpacoEvidenceFile -Path (Join-Path $sharePath 'delete.me.tombstone.json') -Content '{"reportedName":"delete.me","EventId":5145,"remote":false,"note":"No remote share accessed."}' -Purpose 'NetScan share-write check canary' -Timestamp $time.Day3.AddMinutes(15)
    }

    $rpcdump = Join-Path $Paths.Tools 'rpcdump.exe'
    New-ElpacoBinaryDecoy -Path $rpcdump -Role 'Impacket rpcdump process-name canary' -ReportedSha256 '3c300726a6cdd8a39230f0775ea726c2d42838ac7ff53bfdd7c58d28df4182d5'
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Tools 'CheckVuln.bat') -Content @'
@echo off
REM NOT EXECUTED against a DC: rpcdump.exe @DC01 | findstr /C:"MS-RPRN" /C:"MS-PAR"
echo ELPACO-CANARY: 473 synthetic endpoints; MS-RPRN/MS-PAR absent
'@ -Purpose 'inert PrintNightmare discovery batch' -Timestamp $time.Day3.AddMinutes(30)
    Invoke-ElpacoDecoyProcess -FilePath $rpcdump -ReportedCommandLine 'rpcdump.exe @127.0.0.1 | findstr /C:"MS-RPRN" /C:"MS-PAR"'

    $wmiexec = Join-Path $Paths.Tools 'wmiexec.exe'
    New-ElpacoBinaryDecoy -Path $wmiexec -Role 'Impacket wmiexec process-name canary' -ReportedSha256 '14f0c4ce32821a7d25ea5e016ea26067d6615e3336c3baa854ea37a290a462a8'
    foreach ($command in @(
        'wmiexec.exe :NTLM_HASH domain_admind@dc_ip',
        'NET1 USER NONAME SLEPOY_123 /DOMAIN /ADD',
        'NET1 GROUP "DOMAIN ADMINS" NONAME /DOMAIN /ADD',
        'NET1 GROUP "ENTERPRISE ADMINS" NONAME /DOMAIN /ADD'
    )) { Invoke-ElpacoDecoyProcess -FilePath $wmiexec -ReportedCommandLine $command }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'synthetic-wmi-rdp-share-events.json') -Content ((@(
        @{ parent = 'wmiprvse.exe'; child = 'cmd.exe /Q /c whoami > C:\Windows\__1719000000 2>&1'; remoteExecution = false },
        @{ EventId = 5142; shareName = 'share'; localPath = $Paths.Share; realShare = false },
        @{ parent = 'netscan.exe'; child = 'mstsc.exe /v:BACKUP01'; actualTarget = '127.0.0.1'; realRdp = false },
        @{ source = 'Confluence'; destination = @('BACKUP01', 'FILE01'); protocol = @('WMI', 'RDP', 'SMB'); remoteActivity = false }
    ) | ConvertTo-Json -Depth 6)) -Purpose 'lateral movement event canaries' -Timestamp $time.Lateral

    Add-ElpacoTimelineEvent -Timestamp $time.Credential -Phase 'Credential Access' -Event 'Mimikatz, ProcessHacker, and eight secretsdump executions were represented using signed decoys and generated credentials.' -Details @{ lsassOpened = $false; ntdsAccessed = $false; remoteRegistryUsed = $false }
    Add-ElpacoTimelineEvent -Timestamp $time.Lateral -Phase 'Discovery and Lateral Movement' -Event 'NetScan, rpcdump, wmiexec, synthetic share creation, and RDP movement were reproduced locally.' -Details @{ actualNetworkScope = '127.0.0.1'; domainModified = $false; remoteSystemsContacted = $false }
}
