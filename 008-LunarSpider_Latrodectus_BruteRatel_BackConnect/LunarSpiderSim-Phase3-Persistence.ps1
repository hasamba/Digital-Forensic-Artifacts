# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 3: PERSISTENCE
# ============================================================================
# Simulates: Latrodectus HKCU Run key "Update" (upfilles.dll, later
# wscadminui.dll), and the .NET backdoor's SchedulerLsass scheduled task
# pointing at %ALLUSERSPROFILE%\USOShared\lsassa.exe (trigger: onstart).
# MITRE: T1547.001 Registry Run Keys, T1053.005 Scheduled Task
# ============================================================================

function Simulate-Persistence {
    param($SimPaths)

    Write-Host "[+] Phase 3: Persistence - Run key + SchedulerLsass task ..." -ForegroundColor Green

    # --- HKCU Run key "Update" (Latrodectus) ---------------------------------
    # Day 1 value points at upfilles.dll; Day 5 it was updated to wscadminui.dll.
    $wscadminui = "$env:ALLUSERSPROFILE\wscadminui.dll"
    New-DecoyBinary -Path $wscadminui -SizeBytes 251904 | Out-Null

    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $runVal = "rundll32.exe `"$env:ALLUSERSPROFILE\upfilles.dll`",stow"
    Set-ItemProperty -Path $runKey -Name "Update" -Value $runVal -Force
    Write-Host "    Set HKCU Run key 'Update' -> upfilles.dll (Day 1 value)" -ForegroundColor DarkGray
    # Day 5 update to the wscadminui.dll BRC4 replacement
    Set-ItemProperty -Path $runKey -Name "Update" -Value "rundll32.exe `"$wscadminui`",stow" -Force
    Write-SimEvent -EventId 3001 -Message "SIMULATION: HKCU\...\Run 'Update' set for Latrodectus persistence (upfilles.dll -> wscadminui.dll)"

    # --- .NET backdoor lsassa.exe + SchedulerLsass scheduled task -------------
    # Real path: %ALLUSERSPROFILE%\USOShared\lsassa.exe, created via:
    #   cmd.exe /c schtasks /create /tn "SchedulerLsass"
    #     /tr "%ALLUSERSPROFILE%\USOShared\lsassa.exe" /sc onstart
    $usoShared = "$env:ALLUSERSPROFILE\USOShared"
    New-Item -Path $usoShared -ItemType Directory -Force | Out-Null
    $lsassa = "$usoShared\lsassa.exe"
    New-DecoyBinary -Path $lsassa -SizeBytes 24576 | Out-Null  # small .NET backdoor

    $taskName = "SchedulerLsass"
    try {
        # Use the exact schtasks.exe command line from the report for authentic
        # process-creation + Task Scheduler operational-log artifacts.
        $tr = "`"$lsassa`""
        cmd.exe /c "schtasks /create /tn `"$taskName`" /tr $tr /sc onstart /ru SYSTEM /f" 2>$null | Out-Null
        Write-Host "    Created scheduled task '$taskName' (onstart -> lsassa.exe)" -ForegroundColor DarkGray
    } catch {
        Write-Warning "schtasks creation failed: $($_.Exception.Message)"
    }
    Write-SimEvent -EventId 3002 -Message "SIMULATION: scheduled task 'SchedulerLsass' created for .NET backdoor lsassa.exe (onstart)"

    Write-Host "  [OK] Persistence artifacts created" -ForegroundColor Yellow
}
