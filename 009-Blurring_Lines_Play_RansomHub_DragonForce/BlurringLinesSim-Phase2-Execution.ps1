# ============================================================================
# BLURRING THE LINES SIM - PHASE 2: EXECUTION & PROCESS INJECTION
# ============================================================================
# Simulates: SectopRAT (WakeWordEngine.dll) injected into the MSBuild.exe host
# process; SystemBC loaded in-memory (dropped alongside as conhost.dll) to stand
# up a SOCKS proxy/tunnel; and the SectopRAT stealer enumerating Steam, Discord,
# Telegram, browsers, and crypto wallets. No real cross-process memory writes are
# performed - a sacrificial host process is spawned and the injection is recorded
# as authentic Sysmon-shaped telemetry + event-log markers.
# MITRE: T1055 Process Injection, T1059 Command and Scripting Interpreter,
#        T1555 Credentials from Password Stores, T1005 Data from Local System
# ============================================================================

function Simulate-Execution {
    param($SimPaths)

    Write-Host "[+] Phase 2: Execution & Injection - SectopRAT into MSBuild, SystemBC in-memory ..." -ForegroundColor Green

    # --- Sacrificial MSBuild host for SectopRAT injection ---------------------
    # Real case: SectopRAT ran injected inside MSBuild.exe. Spawn a real, benign
    # host process to carry the injection markers (fails closed to notepad).
    $hostProc = $null
    $msbuild = Get-MSBuildPath
    try {
        if ($msbuild) {
            $hostProc = Start-Process -FilePath $msbuild -ArgumentList "/nologo /version" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        }
        if (-not $hostProc) { $hostProc = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue }
    } catch {}
    $hostPid = if ($hostProc) { $hostProc.Id } else { $PID }

    Set-Content -Path "$($SimPaths.Logs)\sectoprat_injection.log" -Value @"
[SectopRAT / ArechClient2 injection - BlurringLinesSim]
Technique   : reflective load into a spawned MSBuild.exe host (T1055)
Host PID    : $hostPid
Source DLL  : $($SimPaths.PublicMusic)\WakeWordEngine.dll
C2          : $($Global:BlurIOCs.SectopRatC2):$($Global:BlurIOCs.SectopRatPorts -join ',')
Note        : the injected module also loads SystemBC in-memory (conhost.dll).
"@ -Force
    Write-SimEvent -EventId 2001 -Message "SIMULATION: SectopRAT injected into MSBuild.exe host PID $hostPid (T1055); C2 $($Global:BlurIOCs.SectopRatC2)"

    Start-Sleep -Milliseconds 600
    if ($hostProc) { Stop-Process -Id $hostProc.Id -Force -ErrorAction SilentlyContinue }

    # --- SystemBC dropped as conhost.dll (loaded in-memory for the proxy tunnel) --
    $conhost = "$($SimPaths.PublicMusic)\conhost.dll"
    New-DecoyBinary -Path $conhost -SizeBytes 421888 | Out-Null    # same family blob as WakeWordEngine.dll
    Set-ArtifactTimestamp -Path $conhost -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 25
    Set-Content -Path "$($SimPaths.Logs)\systembc_tunnel.log" -Value @"
[SystemBC proxy/tunnel - BlurringLinesSim]
Module      : conhost.dll (in-memory), dropped to $conhost
C2          : $($Global:BlurIOCs.SystemBcC2):$($Global:BlurIOCs.SystemBcPort)
Function    : SOCKS proxy; later enables RDP-over-proxy for the operator (Phase 8)
"@ -Force
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.SystemBcC2 -Port $Global:BlurIOCs.SystemBcPort
    Write-SimEvent -EventId 2002 -Message "SIMULATION: SystemBC (conhost.dll) established tunnel to $($Global:BlurIOCs.SystemBcC2):$($Global:BlurIOCs.SystemBcPort)"

    # --- SectopRAT stealer enumeration output ---------------------------------
    $stealerOut = @"
[SectopRAT stealer harvest - BlurringLinesSim lab data]
steam       : C:\Program Files (x86)\Steam\config\loginusers.vdf  (enumerated)
discord     : %AppData%\discord\Local Storage\leveldb  (tokens enumerated)
telegram    : %AppData%\Telegram Desktop\tdata  (enumerated)
browsers    : Chrome/Edge/Firefox Login Data + cookies enumerated
wallets     : Exodus, Electrum, Metamask extension IDs enumerated
"@
    Set-Content -Path "$($SimPaths.Loot)\sectoprat_stealer_output.txt" -Value $stealerOut -Force
    Write-SimEvent -EventId 2003 -Message "SIMULATION: SectopRAT stealer enumerated Steam/Discord/Telegram/browsers/crypto wallets (T1555)"

    Write-Host "  [OK] Execution & Injection artifacts created (SectopRAT host, SystemBC tunnel, stealer output)" -ForegroundColor Yellow
}
