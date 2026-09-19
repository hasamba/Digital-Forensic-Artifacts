function Invoke-ElpacoImpact {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-ElpacoTimeline
    $primaryHash = 'a710ed9e008326b981ff0fadb1c75d89deca2b52451d4677a8fd808b4ac0649b'
    $secondaryHash = '0b83f2667abff814bb724808c404396e6ad417591165f1762a8e99ec108d4996'

    $ransomware = Join-Path $Paths.Desktop 'ELPACO-team.exe'
    New-ElpacoBinaryDecoy -Path $ransomware -Role 'ELPACO/Mimic ransomware process-name canary' -ReportedSha256 $primaryHash
    foreach ($hostName in @('BACKUP01', 'FILE01')) {
        $hostAdmin = Join-Path $Paths.Hosts "$hostName\D\Admin"
        New-Item -Path $hostAdmin -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $ransomware -Destination (Join-Path $hostAdmin 'ELPACO-team.exe') -Force
        Add-ElpacoManifestEntry -Type 'file' -Path (Join-Path $hostAdmin 'ELPACO-team.exe') -Action 'local-synthetic-host-copy' -Details @{ host = $hostName; remoteTransfer = $false; reportedSha256 = $primaryHash }
    }

    $sfxFiles = @('7za.exe', 'Everything.exe', 'Everything32.dll', 'DC.exe', 'ELPACO-team.exe', 'ENC_default_default_2023-12-27_09-27-40=Telegram@datadecrypt.exe', 'gui35.exe', 'gui40.exe', 'xdel.exe')
    foreach ($name in $sfxFiles) {
        if ($name -match '\.exe$') {
            New-ElpacoBinaryDecoy -Path (Join-Path $Paths.RansomTemp $name) -Role '7-Zip SFX payload filename canary' -ReportedSha256 $(if ($name -eq 'ELPACO-team.exe') { $secondaryHash } else { 'NOT-PUBLISHED' })
        } else {
            Write-ElpacoEvidenceFile -Path (Join-Path $Paths.RansomTemp $name) -Content "ELPACO INERT SFX COMPONENT: $name" -Purpose 'SFX payload filename canary' -Timestamp $time.Impact
        }
    }
    foreach ($name in @('svhostss.exe', 'Everything32.dll', 'Everything64.dll')) {
        if ($name -match '\.exe$') {
            New-ElpacoBinaryDecoy -Path (Join-Path $Paths.RansomHome $name) -Role 'renamed ELPACO ransomware process-name canary' -ReportedSha256 $secondaryHash
        } else {
            Write-ElpacoEvidenceFile -Path (Join-Path $Paths.RansomHome $name) -Content "ELPACO INERT COMPONENT: $name" -Purpose 'ransomware component filename canary' -Timestamp $time.Impact
        }
    }
    foreach ($name in @('Everything.ini', 'Everything2.ini', 'global_options.ini')) {
        Write-ElpacoEvidenceFile -Path (Join-Path $Paths.RansomHome $name) -Content "[simulation]`nenabled=false`nreportedEverythingDllPassword=7595128543001923103" -Purpose 'ransomware configuration canary' -Timestamp $time.Impact
    }
    $svhostss = Join-Path $Paths.RansomHome 'svhostss.exe'
    foreach ($arguments in @('-e u1', '-e u2', '-e watch -pid 5544 -!')) { Invoke-ElpacoDecoyProcess -FilePath $svhostss -ReportedCommandLine "svhostss.exe $arguments" }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'run-key-canary.json') -Content (@{
        key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        valueName = 'svhostss'
        valueData = 'C:\Users\noname\AppData\Local\F6A3737E-E3B0-8956-8261-0121C68105F3\svhostss.exe'
        registryModified = $false
    } | ConvertTo-Json -Depth 4) -Purpose 'Run-key persistence metadata; registry untouched' -Timestamp $time.Impact
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Impact 'C-temp\MIMIC_LOG.txt') -Content 'ELPACO/Mimic operation log canary; no real process termination or file encryption' -Purpose 'reported ransomware log filename' -Timestamp $time.Impact
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Impact 'C-temp\session.tmp') -Content 'synthetic ransomware session' -Purpose 'reported ransomware session filename' -Timestamp $time.Impact

    $dangerousCommands = @(
        'Get-VM',
        'Get-VM | Get-VHD | Get-DiskImage -ImagePath $_.Path | Dismount-DiskImage',
        'Get-VM | Stop-VM',
        'DC.exe /disable-defender',
        'logs_delete.cmd (event-log and artifact deletion)',
        'process access against lsass.exe 0x40 and svchost.exe 0x121411'
    )
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'non-executed-impact-actions.json') -Content (($dangerousCommands | ForEach-Object { @{ commandOrAction = $_; executed = $false } }) | ConvertTo-Json -Depth 5) -Purpose 'dangerous impact and evasion actions recorded, never run' -Timestamp $time.Impact

    foreach ($hostName in @('BACKUP01', 'FILE01', 'DC01')) {
        $hostImpact = Join-Path $Paths.Impact $hostName
        New-Item -Path $hostImpact -ItemType Directory -Force | Out-Null
        foreach ($name in @('financials.xlsx', 'backup-catalog.vbk', 'operations.docx')) {
            $original = Join-Path $hostImpact $name
            Write-ElpacoEvidenceFile -Path $original -Content "Generated investigation canary for $hostName/$name. Original remains intact." -Purpose 'generated source document' -Timestamp $time.Impact
            Write-ElpacoEvidenceFile -Path "$original.ELPACO-team" -Content "ELPACO extension marker only; paired original is intact; no cryptography used." -Purpose 'non-encrypted impact marker' -Timestamp $time.Impact.AddMinutes(2)
        }
    }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Impact 'Decryption_INFO.txt') -Content @'
ELPACO-team FORENSIC CANARY
No files were encrypted. No payment address or contact channel is present.
This note exists only to reproduce the report's filename and analyst workflow.
'@ -Purpose 'inert ransom-note canary' -Timestamp $time.Impact.AddMinutes(5)

    $impactEvents = @(
        @{ source = 'Confluence'; destination = 'BACKUP01'; method = 'RDP copy to D:\Admin'; actualRemoteAccess = $false },
        @{ source = 'Confluence'; destination = 'FILE01'; method = 'RDP and SMB'; actualRemoteAccess = $false },
        @{ EventId = 10; source = 'svhostss.exe'; target = 'lsass.exe'; GrantedAccess = '0x40'; count = 9000; actualAccess = $false },
        @{ EventId = 10; source = 'svhostss.exe'; target = 'svchost.exe'; GrantedAccess = @('0x40', '0x121411'); count = 3000; actualAccess = $false },
        @{ exfiltration = 'none observed'; reportedAnyDeskBidirectionalBytes = 70000000; dataTransferred = $false }
    )
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'synthetic-impact-events.json') -Content ($impactEvents | ConvertTo-Json -Depth 6) -Purpose 'impact and no-exfiltration evidence canaries' -Timestamp $time.Impact

    Add-ElpacoTimelineEvent -Timestamp $time.Impact -Phase 'Impact' -Event 'ELPACO/Mimic was copied to backup and file-server canaries and produced its reported SFX layout, extension, note, and process telemetry.' -Details @{ encryptionUsed = $false; userFilesTraversed = $false; remoteHostsContacted = $false; securityToolsModified = $false }
}
