# ============================================================================
# BLURRING THE LINES SIM - PHASE 4: PRIVILEGE ESCALATION
# ============================================================================
# Simulates: the actor used PsExec with the -s flag to relaunch the SystemBC
# loader (rundll32 WakeWordEngine.dll,Reset) as NT AUTHORITY\SYSTEM. PsExec
# installs a temporary service (PSEXESVC) on the target, which the report's
# detections key on. We reproduce the PSEXESVC service-install + SYSTEM launch
# artifact using a benign runnable stand-in for psexec, and record the exact
# reported command line.
# MITRE: T1543.003 Windows Service, T1569.002 Service Execution,
#        T1078.003 Valid Accounts: Local Accounts, T1134 Access Token Manipulation
# ============================================================================

function Simulate-PrivilegeEscalation {
    param($SimPaths)

    Write-Host "[+] Phase 4: Privilege Escalation - PsExec -s -> SYSTEM SystemBC ..." -ForegroundColor Green

    $wakeword = "$($SimPaths.PublicMusic)\WakeWordEngine.dll"
    if (-not (Test-Path $wakeword)) { New-DecoyBinary -Path $wakeword -SizeBytes 421888 | Out-Null }

    # --- Stage PsExec (benign runnable stand-in) ------------------------------
    $psexec = "$($SimPaths.PublicMusic)\PsExec.exe"
    New-RunnablePayload -Path $psexec -OverlayStrings @(
        "Sysinternals PsExec", "psexec -s", "PSEXESVC"
    ) | Out-Null
    Set-ArtifactTimestamp -Path $psexec -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 35

    # Exact reported command line (artifact for the analyst)
    $psexecCmd = "psexec -s rundll32.exe `"$wakeword`" Reset"
    Set-Content -Path "$($SimPaths.Logs)\psexec_system.log" -Value $psexecCmd -Force
    Write-Host "    Command: $psexecCmd" -ForegroundColor DarkGray

    # --- Reproduce the PSEXESVC transient service artifact --------------------
    # PsExec drops PSEXESVC.exe and registers/starts a service named PSEXESVC to
    # run the target as SYSTEM. Create + start + delete a real service pointing at
    # a benign binary so System 7045 (service install) and Security 4697 fire with
    # the recognizable service name.
    try {
        & sc.exe create PSEXESVC binPath= "cmd.exe /c whoami > $($SimPaths.Logs)\psexesvc_whoami.txt" type= own start= demand 2>$null | Out-Null
        & sc.exe start PSEXESVC 2>$null | Out-Null
        Start-Sleep -Seconds 1
        & sc.exe delete PSEXESVC 2>$null | Out-Null
        Write-Host "    PSEXESVC service install/start/delete artifact generated (System 7045)" -ForegroundColor DarkGray
    } catch { Write-Warning "PSEXESVC service artifact failed: $($_.Exception.Message)" }
    Write-SimEvent -EventId 4001 -Message "SIMULATION: PsExec -s installed PSEXESVC and ran 'rundll32 WakeWordEngine.dll,Reset' as SYSTEM (T1569.002)"

    # --- Run the SYSTEM-context rundll32 artifact -----------------------------
    Invoke-BenignRundll32 -DllPath $wakeword -ExportName "Reset"
    Write-SimEvent -EventId 4002 -Message "SIMULATION: SystemBC/SectopRAT loader relaunched under SYSTEM via PsExec"

    Write-Host "  [OK] Privilege Escalation artifacts created (PSEXESVC, SYSTEM rundll32)" -ForegroundColor Yellow
}
