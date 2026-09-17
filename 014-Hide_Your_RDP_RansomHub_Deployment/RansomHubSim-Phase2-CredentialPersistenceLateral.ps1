function Invoke-RansomHubCredentialPersistenceLateral {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-RansomHubTimeline

    $credentialsView = Join-Path $Paths.DesktopRoot 'CredentialsFileView.exe'
    New-RansomHubBinaryDecoy -Path $credentialsView -Role 'NirSoft CredentialsFileView process-name canary'
    Invoke-RansomHubDecoyProcess -FilePath $credentialsView -ReportedCommandLine 'CredentialsFileView.exe /stext saved-credentials.txt (generated canary source only)'
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'saved-credentials.txt') -Content "Application,User,Password`nLAB-CANARY,LAB\user,NOT-A-REAL-PASSWORD" -Purpose 'synthetic stored-credential output; no credential store read' -Timestamp $time.Day1.AddHours(1).AddMinutes(20)

    $mimikatz = Join-Path $Paths.DesktopRoot 'mimikatz.exe'
    New-RansomHubBinaryDecoy -Path $mimikatz -Role 'Mimikatz process-name and command-line canary'
    Invoke-RansomHubDecoyProcess -FilePath $mimikatz -ReportedCommandLine 'mimikatz.exe "sekurlsa::logonpasswords" "exit" (LSASS never opened)'
    foreach ($child in @('CHILD-A', 'CHILD-B', 'CHILD-C')) {
        Invoke-RansomHubDecoyProcess -FilePath $mimikatz -ReportedCommandLine "mimikatz.exe `"lsadump::dcsync /domain:$child.lab.invalid /user:LAB-DOMAINADMIN /csv`""
        Write-RansomHubEvidenceFile -Path (Join-Path $Paths.SyntheticAD "$child.csv") -Content "domain,user,status`n$child.lab.invalid,LAB-DOMAINADMIN,CANARY-ACCOUNT-PRESENT" -Purpose 'synthetic DCSync/domain-account validation output' -Timestamp $time.Day1.AddHours(2)
    }
    $credentialEvents = @(
        [ordered]@{ EventId = 5379; TimeCreated = $time.Day1.AddHours(1).AddMinutes(20).ToString('o'); Target = 'generated credential canary'; realCredentialRead = $false },
        [ordered]@{ EventId = 10; Provider = 'Sysmon'; TimeCreated = $time.Day1.AddHours(1).AddMinutes(24).ToString('o'); SourceImage = $mimikatz; TargetImage = 'lsass.exe'; GrantedAccess = 'CANARY-NOT-OPENED'; realProcessAccess = $false },
        [ordered]@{ EventId = 4662; TimeCreated = $time.Day1.AddHours(2).ToString('o'); ObjectType = 'DS-Replication-Get-Changes'; realDirectorySync = $false }
    )
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'credential-access-event-canaries.json') -Content ($credentialEvents | ConvertTo-Json -Depth 6) -Purpose '5379, Sysmon 10, and 4662 evidence representations' -Timestamp $time.Day1.AddHours(1).AddMinutes(20)

    $mstsc = Join-Path $Paths.Tools 'mstsc.exe'
    New-RansomHubBinaryDecoy -Path $mstsc -Role 'RDP lateral-movement process-name canary'
    foreach ($target in @('DC01', 'DC02', 'BACKUP01', 'FILE01', 'HV01', 'WS001')) {
        Invoke-RansomHubDecoyProcess -FilePath $mstsc -ReportedCommandLine "mstsc.exe /v:$target /admin (actual network target 127.0.0.1 only)"
        Invoke-RansomHubLoopbackPort -Port 3389 -ReportedTarget $target
    }
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    foreach ($command in @(
        'mmc.exe dnsmgmt.msc',
        'mmc.exe domain.msc',
        'mmc.exe dssite.msc',
        'mmc.exe dsa.msc'
    )) { Invoke-RansomHubDecoyProcess -FilePath $cmd -ReportedCommandLine $command }

    $setupMsi = Join-Path $Paths.DesktopRoot 'setup.msi'
    Write-RansomHubEvidenceFile -Path $setupMsi -Content "RANSOMHUB-SIM MSI CANARY`nReportedSHA256=ec45ebd938e363e36cacb42e968a960fbe4e21ced511f0ea2c0790b743ff3c67`nThe public report does not assign this hash to a specific installer in the IOC table." -Purpose 'reported setup.msi IOC represented as an invalid MSI' -Timestamp $time.Day2.AddMinutes(8)
    $advancedScanner = Join-Path $Paths.DesktopRoot 'Advanced_IP_Scanner.exe'
    Invoke-RansomHubDecoyProcess -FilePath $advancedScanner -ReportedCommandLine 'Advanced_IP_Scanner.exe second execution /range LAB-SUBNET (actual scope 127.0.0.1 only)'
    Invoke-RansomHubDecoyProcess -FilePath $advancedScanner -ReportedCommandLine 'Advanced_IP_Scanner.exe third execution /range LAB-SUBNET (actual scope 127.0.0.1 only)'
    Add-RansomHubManifestEntry -Type 'file' -Path $advancedScanner -Action 'deleted-generated-canary' -Details @{ reason = 'represent reported post-scan binary deletion'; userFile = $false }
    Remove-RansomHubGeneratedFile -Path $advancedScanner
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'Advanced_IP_Scanner.exe.tombstone.json') -Content '{"executions":3,"reportedAction":"deleted","actualUserFile":false}' -Purpose 'portable scanner-deletion tombstone' -Timestamp $time.Day2.AddMinutes(10)
    $atera = Join-Path $Paths.Rmm 'AteraAgent.exe'
    $splashtop = Join-Path $Paths.Rmm 'SplashtopRemoteService.exe'
    New-RansomHubBinaryDecoy -Path $atera -Role 'Atera RMM process-name canary'
    New-RansomHubBinaryDecoy -Path $splashtop -Role 'Splashtop RMM process-name canary'
    Invoke-RansomHubDecoyProcess -FilePath $atera -ReportedCommandLine 'AteraAgent.exe /install /server BACKUP01 (service not installed)'
    Invoke-RansomHubDecoyProcess -FilePath $splashtop -ReportedCommandLine 'SplashtopRemoteService.exe /service (service not installed)'
    $serviceEvents = @(
        [ordered]@{ EventId = 7045; ServiceName = 'AteraAgent'; ImagePath = 'C:\Program Files\ATERA Networks\AteraAgent.exe'; Host = 'BACKUP01'; actualServiceInstall = $false },
        [ordered]@{ EventId = 7045; ServiceName = 'SplashtopRemoteService'; ImagePath = 'C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRService.exe'; Host = 'BACKUP02'; actualServiceInstall = $false }
    )
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Rmm 'service-7045-canaries.json') -Content ($serviceEvents | ConvertTo-Json -Depth 6) -Purpose 'Atera and Splashtop service-install event canaries' -Timestamp $time.Day2.AddMinutes(12)
    $agentLog = @"
<1>$($time.Day5.ToString('yyyy-MM-dd HH:mm:ss')) 11600[App] event WM_WTSSESSION_CHANGE session: 5 id:2
<1>$($time.Day5.AddSeconds(2).ToString('yyyy-MM-dd HH:mm:ss')) 11600[Handler] save logon user LAB\DOMAINADMIN
<1>$($time.Day5.AddSeconds(4).ToString('yyyy-MM-dd HH:mm:ss')) SM_00352[Auth] disp name johnattan johnattan
<1>$($time.Day5.AddSeconds(5).ToString('yyyy-MM-dd HH:mm:ss')) SM_12412[Auth-L] ok, client (WINVM) can connect to AV server
ClientInfo: user: LAB\DOMAINADMIN ip: 10.0.2.15 hostname: WIN
"@
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Rmm 'Splashtop\agent_log.txt') -Content $agentLog -Purpose 'Splashtop agent/SPLog attribution canary' -Timestamp $time.Day5

    $passwordResets = [ordered]@{ disclaimer = 'Synthetic password-reset records only; no account changed.'; password = 'LAB-CANARY-SAME-PASSWORD'; users = @('ops-admin', 'backup-admin', 'file-admin') }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.SyntheticAD 'password-reset-canaries.json') -Content ($passwordResets | ConvertTo-Json -Depth 5) -Purpose 'day-five account password-change representation' -Timestamp $time.Day5.AddMinutes(45)
    foreach ($user in $passwordResets.users) { Invoke-RansomHubDecoyProcess -FilePath $cmd -ReportedCommandLine "net user $user LAB-CANARY-SAME-PASSWORD /domain" }

    Add-RansomHubTimelineEvent -Timestamp $time.Day1.AddHours(1).AddMinutes(20) -Phase 'Credential Access' -Event 'CredentialsFileView, Mimikatz LSASS, and DCSync activity represented with signed decoys and synthetic outputs.' -Details @{ credentialStoresRead = $false; LSASSAccessed = $false; DCSyncPerformed = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day1.AddHours(2) -Phase 'Lateral Movement' -Event 'RDP pivots to DCs, backup, file, hypervisor, and workstation targets represented through loopback.' -Details @{ remoteAuthentication = $false; actualTarget = '127.0.0.1' }
    Add-RansomHubTimelineEvent -Timestamp $time.Day2.AddMinutes(8) -Phase 'Persistence' -Event 'Atera and Splashtop deployment represented with process and service-event canaries.' -Details @{ servicesInstalled = $false; RmmNetworkContact = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day2.AddMinutes(10) -Phase 'Defense Evasion' -Event 'Advanced IP Scanner completed its second and third canary executions and the generated binary was deleted.' -Details @{ executions = 3; userFileDeleted = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day5 -Phase 'Persistence' -Event 'Return through Splashtop and same-password resets represented with logs and inert command lines.' -Details @{ accountPasswordsChanged = $false; actorDisplayName = 'johnattan johnattan'; actorHostname = 'WINVM' }
}
