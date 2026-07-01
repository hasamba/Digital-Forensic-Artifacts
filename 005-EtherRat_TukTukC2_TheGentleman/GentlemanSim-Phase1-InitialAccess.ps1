# ============================================================================
# GENTLEMAN SIMULATION - PHASE 1: INITIAL ACCESS
# ============================================================================
# Simulates: a user executing a malicious MSI installer masquerading as the
# Sysinternals RAMMap utility, spawned from Desktop/Downloads, which drops
# and launches a batch script child process.
# MITRE: T1204.002 Malicious File, T1036.005 Masquerading (match legit name)
#
# Report artifact reproduced:
#   C:\Windows\system32\msiexec.exe /V
#   |_ cmd.exe /c start /min "" "MVnVmUYj.cmd"
# ============================================================================

function Simulate-InitialAccess {
    param($SimPaths)

    Write-Host "[+] Phase 1: Initial Access - Trojanized RAMMap MSI ..." -ForegroundColor Green

    # --- Stage the trojanized MSI at a user-facing path, matching the report's
    #     Desktop/Downloads/ProgramData hunting guidance ---
    $desktopDrop = Join-Path $env:USERPROFILE "Desktop\RAMMap.msi"
    $msiPath = New-DecoyBinary -Path $desktopDrop -SizeBytes 512000
    Copy-Item -Path $msiPath -Destination "$($SimPaths.Payloads)\RAMMap.msi" -Force
    Write-SimEvent -EventId 1001 -Message "SIMULATION: Malicious MSI 'RAMMap.msi' masquerading as Sysinternals RAMMap staged at $desktopDrop (T1204.002, T1036.005)"

    # --- Real reported command lines, logged verbatim for detection-rule testing ---
    $realCmdLog = @"
C:\Windows\system32\msiexec.exe /V
|_ cmd.exe /c start /min "" "MVnVmUYj.cmd"
"@
    Set-Content -Path "$($SimPaths.Logs)\phase1_initial_access_commands.log" -Value $realCmdLog -Force

    # --- Reproduce the process tree: msiexec.exe spawns cmd.exe, which spawns
    #     the dropped .cmd script (decoy, inert - no real EtherRAT logic) ---
    $cmdScriptName = "MVnVmUYj.cmd"
    $cmdScriptPath = "$($SimPaths.Payloads)\$cmdScriptName"
    Set-Content -Path $cmdScriptPath -Value "@echo off`r`nREM SIMULATION: inert decoy stand-in for the real EtherRAT dropper .cmd`r`nexit /b 0" -Force

    $msiexecProc = $null
    try {
        # Launch msiexec against our decoy MSI in a way that will fail-fast
        # (not a real installer table) but still generate the msiexec.exe
        # process-creation telemetry the report calls out.
        $msiexecProc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($SimPaths.Payloads)\RAMMap.msi`" /quiet /qn" -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    } catch { Write-Warning "msiexec simulation failed: $_" }

    try {
        # cmd.exe /c start /min "" "MVnVmUYj.cmd" - exact reported child command line
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c start /min `"`" `"$cmdScriptPath`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 1002 -Message "SIMULATION: cmd.exe /c start /min `"`" `"$cmdScriptName`" spawned from msiexec.exe (matches reported child process pattern)"
    } catch { Write-Warning "cmd.exe child-process simulation failed: $_" }

    if ($msiexecProc) {
        Start-Sleep -Milliseconds 500
        Stop-Process -Id $msiexecProc.Id -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  [OK] Initial Access artifacts created - $desktopDrop" -ForegroundColor Yellow

    return @{
        DesktopMsiPath = $desktopDrop
        CmdScriptPath  = $cmdScriptPath
    }
}
