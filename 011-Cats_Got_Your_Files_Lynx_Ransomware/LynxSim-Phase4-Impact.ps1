function Invoke-LynxImpact {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-LynxTimeline

    $backupJobsBefore = [ordered]@{
        server = 'BACKUP01-CANARY'
        product = 'Veeam Backup & Replication (representation only)'
        jobs = @(
            [ordered]@{ name = 'Daily-VM-Backup'; state = 'Enabled'; repository = 'REPO01-CANARY' },
            [ordered]@{ name = 'Weekly-File-Backup'; state = 'Enabled'; repository = 'TAPE01-CANARY' }
        )
    }
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Backup 'veeam-jobs-before.json') -Content ($backupJobsBefore | ConvertTo-Json -Depth 6) -Purpose 'generated Veeam backup-job inventory canary' -Timestamp $time.Day9.AddMinutes(8)

    $backupJobsAfter = [ordered]@{
        server = 'BACKUP01-CANARY'
        actualVeeamContact = $false
        actualBackupDeletion = $false
        jobs = @(
            [ordered]@{ name = 'Daily-VM-Backup'; state = 'Deleted-SIMULATED'; event = 'Job deletion represented in local JSON only' },
            [ordered]@{ name = 'Weekly-File-Backup'; state = 'Deleted-SIMULATED'; event = 'Job deletion represented in local JSON only' }
        )
    }
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Backup 'veeam-jobs-after.json') -Content ($backupJobsAfter | ConvertTo-Json -Depth 6) -Purpose 'backup-job deletion representation without touching backup software' -Timestamp $time.Day9.AddMinutes(11)
    $veeamLog = @"
$($time.Day9.AddMinutes(10).ToString('yyyy-MM-dd HH:mm:ss')) [Warning] [LYNXSIM-CANARY] Job Daily-VM-Backup removed from configuration (SIMULATED ONLY)
$($time.Day9.AddMinutes(11).ToString('yyyy-MM-dd HH:mm:ss')) [Warning] [LYNXSIM-CANARY] Job Weekly-File-Backup removed from configuration (SIMULATED ONLY)
ActualVeeamContact=False; ActualBackupDeletion=False
"@
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Backup 'Svc.VeeamBackup.canary.log') -Content $veeamLog -Purpose 'Veeam-shaped job-deletion log canary' -Timestamp $time.Day9.AddMinutes(12)

    foreach ($server in @('BACKUP01', 'BACKUP02', 'FILE01', 'FILE02')) {
        Invoke-LynxRdpLoopback -ReportedTarget $server -ReportedAccount 'LAB\administratr'
    }

    New-LynxCommandDecoy -Path $Paths.DesktopW -ReportedSha256 '07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a' -Role 'Lynx w.exe process-name and hash-mismatch canary'
    Set-Content -LiteralPath $Paths.DesktopWOwner -Value $script:LynxScenarioId -Encoding ASCII
    Add-LynxManifestEntry -Type 'file' -Path $Paths.DesktopWOwner -Action 'created' -Details @{ purpose = 'cleanup ownership marker for Desktop w.exe' }

    $syntheticEw = Join-Path $Paths.CanaryData 'w.exe'
    New-LynxCommandDecoy -Path $syntheticEw -ReportedSha256 '07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a' -Role 'reported accidental E-drive drop represented under scenario canary root'

    Write-LynxEvidenceFile -Path (Join-Path $Paths.CanaryData 'FileServer\Operations\QuarterlyPlan_CANARY.docx') -Content 'LYNXSIM generated canary document. This is not user data.' -Purpose 'generated impact canary' -Timestamp $time.Day9.AddMinutes(15)
    Write-LynxEvidenceFile -Path (Join-Path $Paths.CanaryData 'BackupServer\Catalog\VMInventory_CANARY.csv') -Content "Name,State`nLAB-VM-01,Protected`nLAB-VM-02,Protected" -Purpose 'generated impact canary' -Timestamp $time.Day9.AddMinutes(15)

    Invoke-LynxDecoyProcess -FilePath $Paths.DesktopW -ReportedCommandLine 'w.exe --dir E:\ --mode fast --verbose --noprint'
    foreach ($source in Get-ChildItem -LiteralPath $Paths.CanaryData -File -Recurse | Where-Object { $_.Name -ne 'w.exe' -and $_.Extension -ne '.LYNX' }) {
        $destination = "$($source.FullName).LYNX"
        $originalHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
        $representation = @"
LYNXSIM-INERT-IMPACT-REPRESENTATION
No encryption occurred. The original generated canary remains intact.
OriginalPath=$($source.FullName)
OriginalSHA256=$originalHash
ReportedMode=fast (5 percent in the report)
"@
        Write-LynxEvidenceFile -Path $destination -Content $representation -Purpose 'Lynx extension artifact without encryption' -Timestamp $time.Day9.AddMinutes(18)
    }

    $ransomNote = @'
LYNX RANSOMWARE FORENSIC CANARY

This is an inert lab artifact. No file was encrypted and no contact details,
victim identifier, onion address, or payment instruction is real.
Review the paired original and .LYNX representation files and the manifest.
'@
    Write-LynxEvidenceFile -Path (Join-Path $Paths.CanaryData 'README.txt') -Content $ransomNote -Purpose 'inert Lynx ransom-note artifact' -Timestamp $time.Day9.AddMinutes(19)

    Add-LynxTimelineEvent -Timestamp $time.Day9.AddMinutes(8) -Phase 'Inhibit System Recovery' -Event 'Veeam job deletion represented using local before/after JSON and a canary log.' -Details @{ backupSoftwareContacted = $false; jobsDeleted = $false; shadowCopiesTouched = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day9.AddMinutes(14) -Phase 'Impact' -Event 'w.exe signed decoy executed with reported Lynx arguments; .LYNX representation files created beside intact generated canaries.' -Details @{ encryption = $false; userDataTouched = $false; reportedSha256 = '07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a' }
}
