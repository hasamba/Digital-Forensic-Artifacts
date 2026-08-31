function Invoke-RansomHubImpact {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-RansomHubTimeline
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

    $netscan = Join-Path $Paths.DesktopRoot 'netscan.exe'
    Invoke-RansomHubDecoyProcess -FilePath $netscan -ReportedCommandLine 'netscan.exe day-five Splashtop network sweep (actual scope 127.0.0.1 only)'
    Invoke-RansomHubDecoyProcess -FilePath $netscan -ReportedCommandLine 'netscan.exe day-six pre-ransomware network sweep (actual scope 127.0.0.1 only)'
    foreach ($port in @(135, 445, 3389)) { Invoke-RansomHubLoopbackPort -Port $port -ReportedTarget 'day-six synthetic victim subnet' }

    $amd64 = Join-Path $Paths.Tools 'amd64.exe'
    New-RansomHubBinaryDecoy -Path $amd64 -Role 'RansomHub amd64.exe process-name and hash-mismatch canary' -ReportedSha256 '25117dcb2d852df15fe44c5757147e7038f289e6156b0f6ab86d02c0e97328cb'
    Invoke-RansomHubDecoyProcess -FilePath $amd64 -ReportedCommandLine 'amd64.exe -pass LAB-CANARY-NOT-A-RANSOMWARE-PASSWORD'

    $impactCommands = @(
        'powershell.exe -Command "Get-VM | Where-Object { $_.Name -ne ''VM01'' -and $_.Name -ne ''VM02'' } | Stop-VM -Force"',
        'powershell.exe -Command "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"',
        'vssadmin.exe Delete Shadows /all /quiet',
        'fsutil behavior set SymlinkEvaluation R2L:1',
        'fsutil behavior set SymlinkEvaluation R2R:1',
        'wevtutil cl security',
        'wevtutil cl system',
        'wevtutil cl application'
    )
    foreach ($command in $impactCommands) { Invoke-RansomHubDecoyProcess -FilePath $cmd -ReportedCommandLine $command }
    $controlMatrix = [ordered]@{
        commands = $impactCommands
        virtualMachinesStopped = $false
        shadowCopiesQueried = $false
        shadowCopiesDeleted = $false
        symlinkPolicyChanged = $false
        eventLogsCleared = $false
        execution = 'escaped echo-only signed cmd process telemetry'
    }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'impact-command-safety-matrix.json') -Content ($controlMatrix | ConvertTo-Json -Depth 6) -Purpose 'reported destructive commands with explicit non-execution state' -Timestamp $time.Day6.AddMinutes(3)

    $serviceEvents = @()
    $remoteNames = @('QJTRAZ', 'MNPQRS', 'UVWXZA', 'BCDEFG')
    $targets = @('FILE01', 'FILE02', 'BACKUP01', 'HV01')
    for ($index = 0; $index -lt $targets.Count; $index++) {
        $target = $targets[$index]
        $randomName = $remoteNames[$index]
        $remoteCopy = Join-Path $Paths.SyntheticNet "$target\C-drive\$randomName.exe"
        New-Item -Path (Split-Path -Parent $remoteCopy) -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $amd64 -Destination $remoteCopy -Force
        Set-RansomHubArtifactTime -Path $remoteCopy -Timestamp $time.Day6.AddMinutes(5 + $index)
        Add-RansomHubManifestEntry -Type 'lateral-transfer-canary' -Path $remoteCopy -Action 'local-copy-only' -Details @{ reportedTarget = $target; protocol = 'SMB'; actualRemoteTransfer = $false; sha256 = (Get-FileHash -LiteralPath $remoteCopy -Algorithm SHA256).Hash }
        Invoke-RansomHubLoopbackPort -Port 445 -ReportedTarget "$target SMB ransomware transfer"
        Invoke-RansomHubDecoyProcess -FilePath $cmd -ReportedCommandLine "sc.exe \\$target create $randomName binPath= C:\$randomName.exe -only-local"
        $serviceEvents += [ordered]@{ EventId = 7045; Host = $target; ServiceName = $randomName; ImagePath = "C:\$randomName.exe -only-local"; actualServiceInstall = $false }
    }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'remote-service-7045-canaries.json') -Content ($serviceEvents | ConvertTo-Json -Depth 6) -Purpose 'random six-letter remote-service deployment records' -Timestamp $time.Day6.AddMinutes(6)

    $localData = Join-Path $Paths.Impact 'LOCAL-SERVER'
    Write-RansomHubEvidenceFile -Path (Join-Path $localData 'Finance\Budget_CANARY.xlsx') -Content 'RANSOMHUB generated impact canary; no user data.' -Purpose 'generated impact canary' -Timestamp $time.Day6.AddMinutes(8)
    Write-RansomHubEvidenceFile -Path (Join-Path $localData 'Shared\Operations_CANARY.docx') -Content 'RANSOMHUB generated operations canary; no user data.' -Purpose 'generated impact canary' -Timestamp $time.Day6.AddMinutes(8)
    foreach ($source in Get-ChildItem -LiteralPath $localData -File -Recurse | Where-Object { $_.Name -notlike '*.RANSOMHUB-CANARY' }) {
        $destination = "$($source.FullName).RANSOMHUB-CANARY"
        $hash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
        $representation = @"
RANSOMHUB-INERT-IMPACT-REPRESENTATION
No encryption occurred. Original generated canary remains intact.
OriginalPath=$($source.FullName)
OriginalSHA256=$hash
"@
        Write-RansomHubEvidenceFile -Path $destination -Content $representation -Purpose 'RansomHub extension artifact without encryption' -Timestamp $time.Day6.AddMinutes(10)
    }
    $note = @'
RANSOMHUB FORENSIC CANARY
No file was encrypted. No victim identifier, onion URL, attacker contact,
payment instruction, or password in this note is real.
'@
    Write-RansomHubEvidenceFile -Path (Join-Path $localData 'README_RANSOMHUB.txt') -Content $note -Purpose 'inert RansomHub ransom-note artifact' -Timestamp $time.Day6.AddMinutes(11)

    Add-RansomHubTimelineEvent -Timestamp $time.Day6 -Phase 'Impact' -Event 'amd64.exe launched roughly 118 hours after initial access.' -Details @{ reportedSha256 = '25117dcb2d852df15fe44c5757147e7038f289e6156b0f6ab86d02c0e97328cb'; liveRansomware = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day6.AddMinutes(3) -Phase 'Defense Evasion and Recovery Inhibition' -Event 'VM stop, shadow deletion, symlink, and log-clear commands represented as escaped echo-only telemetry.' -Details @{ VMsStopped = $false; shadowsDeleted = $false; symlinksChanged = $false; logsCleared = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day6.AddMinutes(5) -Phase 'Lateral Movement' -Event 'Identical signed decoys copied into synthetic host roots and random service events created; SMB attempts remained loopback-only.' -Details @{ remoteHosts = $false; servicesInstalled = $false; propagation = $false }
    Add-RansomHubTimelineEvent -Timestamp $time.Day6.AddMinutes(10) -Phase 'Impact' -Event 'RansomHub extensions and note created beside intact generated canaries.' -Details @{ encryption = $false; userDataTouched = $false }
}
