# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 5: DEFENSE EVASION
# ============================================================================
# Simulates: repeated process injection into long- and short-lived sacrificial
# processes (explorer.exe, dllhost.exe, sihost.exe, spoolsv.exe, gpupdate.exe in
# the real case), and cleanup - the actor deleted more than half of the tools
# and files they downloaded to cover their tracks.
# MITRE: T1055 Process Injection, T1070.004 File Deletion,
# T1036 Masquerading, T1027 Obfuscated Files
# ============================================================================

function Simulate-DefenseEvasion {
    param($SimPaths)

    Write-Host "[+] Phase 5: Defense Evasion - injection into sacrificial procs + cleanup ..." -ForegroundColor Green

    # --- Reproduce the injection-target fingerprint safely --------------------
    # Report targets: explorer.exe, dllhost.exe, sihost.exe, spoolsv.exe, gpupdate.exe.
    # We DO NOT inject into those real system processes. Instead we log the exact
    # target set and spawn short-lived benign stand-ins (dllhost.exe /Processid,
    # gpupdate.exe) so the process-creation + spawnto artifacts appear. The real
    # RWX+CreateRemoteThread injection demo already ran in Phase 2 against a
    # sacrificial notepad.exe.
    $targets = @("explorer.exe", "dllhost.exe", "sihost.exe", "spoolsv.exe", "gpupdate.exe")
    Set-Content -Path "$($SimPaths.Logs)\injection_targets.log" `
        -Value ("Cobalt Strike / BackConnect injection targets (report):`r`n" + ($targets -join "`r`n")) -Force

    # Cobalt Strike spawnto artifact: gpupdate.exe (matches beacon config spawnto_x64)
    try {
        Start-Process -FilePath "$env:SystemRoot\System32\gpupdate.exe" -ArgumentList "/force" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Process -FilePath "$env:SystemRoot\System32\dllhost.exe" -ArgumentList "/Processid:{00000000-0000-0000-0000-000000000000}" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Get-Process -Name "dllhost" -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-4) } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
    Write-SimEvent -EventId 5001 -Message "SIMULATION: Cobalt Strike/BackConnect injection targets exercised (spawnto gpupdate.exe)"

    # --- Anti-forensic cleanup: delete staged tools --------------------------
    # The actor deleted >50% of downloaded files/tools. Reproduce by dropping a
    # set of tool markers, then securely deleting a subset, leaving the classic
    # "file existed then removed" MFT/$LogFile/USN-journal artifact.
    $toolsToWipe = @("mimikatz.exe", "netscan.exe", "PsExec64.exe", "adfind.exe.bak", "loader_tmp.dll")
    foreach ($t in $toolsToWipe) {
        $p = Join-Path $SimPaths.Tools $t
        New-DecoyBinary -Path $p -SizeBytes 8192 | Out-Null
    }
    Start-Sleep -Seconds 1
    foreach ($t in $toolsToWipe) {
        $p = Join-Path $SimPaths.Tools $t
        # Overwrite-then-delete to mimic the actor's cleanup and leave USN DELETE records
        try {
            $fs = [System.IO.File]::OpenWrite($p)
            $zero = New-Object byte[] ($fs.Length)
            $fs.Write($zero, 0, $zero.Length); $fs.Close()
        } catch {}
        Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
    }
    Write-SimEvent -EventId 5002 -Message "SIMULATION: anti-forensic cleanup - overwrote and deleted staged tools (>50% of downloads, per report)"

    Write-Host "  [OK] Defense Evasion artifacts created" -ForegroundColor Yellow
}
