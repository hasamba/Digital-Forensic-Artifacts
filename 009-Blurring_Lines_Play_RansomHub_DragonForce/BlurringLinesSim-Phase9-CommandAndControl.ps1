# ============================================================================
# BLURRING THE LINES SIM - PHASE 9: COMMAND AND CONTROL
# ============================================================================
# Simulates: the full C2 stack and the Day-6 second payload. MSBuild.exe wrote
# C:\Users\Public\Music\ccs.exe (Betruger, RansomHub-linked), which injected into
# 172 running processes and beaconed to 504e1c95.host.njalla[.]net and
# 80.78.28.149 (ports 80/443). Alongside it: the SectopRAT beacons
# (45.141.87.55:9000/15647) and the SystemBC tunnel (149.28.101.219:443). All
# outbound attempts fire against the real report IOCs for authentic network
# telemetry and fail closed.
# MITRE: T1071.001 Web Protocols, T1090 Proxy, T1572 Protocol Tunneling,
#        T1055 Process Injection, T1105 Ingress Tool Transfer
# ============================================================================

function Simulate-CommandAndControl {
    param($SimPaths)

    Write-Host "[+] Phase 9: Command and Control - Betruger (Day 6) + full C2 stack ..." -ForegroundColor Green

    # --- Day 6: MSBuild writes ccs.exe (Betruger) into the staging folder -----
    $ccs = "$($SimPaths.PublicMusic)\ccs.exe"
    if (-not (Test-Path $ccs)) {
        New-RunnablePayload -Path $ccs -OverlayStrings @(
            "Avast Antivirus", "Betruger backdoor", "SHA256:$($Global:BlurIOCs.Hashes['ccs.exe'])"
        ) | Out-Null
    }
    Set-ArtifactTimestamp -Path $ccs -Anchor $Global:BlurTimeline.Day6 -JitterMinutes 20
    Write-Host "    Executing ccs.exe (Betruger stand-in, real EID 1/4688) ..." -ForegroundColor DarkGray
    Invoke-RunPayload -Path $ccs

    # --- Betruger injected into 172 processes (recorded, not literally done) ---
    $procNames = (Get-Process | Select-Object -ExpandProperty ProcessName -Unique | Select-Object -First 30) -join ", "
    Set-Content -Path "$($SimPaths.Logs)\betruger_injection.log" -Value @"
[Betruger (ccs.exe) mass injection - BlurringLinesSim]
Injected into : 172 distinct running processes (per report)
Sample hosts  : $procNames ...
C2 domain     : $($Global:BlurIOCs.BetrugerC2Domain)
C2 IP         : $($Global:BlurIOCs.BetrugerC2Ip) (ports 80, 443)
Spoofed as    : Avast Antivirus component
"@ -Force
    Write-SimEvent -EventId 9001 -Message "SIMULATION: Betruger (ccs.exe) deployed Day 6, injected into 172 processes (T1055)"

    # --- Beacon to every C2 in the report for authentic network telemetry -----
    Write-Host "    Beaconing to report C2 infrastructure (offline, expected) ..." -ForegroundColor DarkGray

    # SectopRAT
    foreach ($p in $Global:BlurIOCs.SectopRatPorts) {
        Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.SectopRatC2 -Port $p
    }
    # SystemBC tunnel
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.SystemBcC2 -Port $Global:BlurIOCs.SystemBcPort
    # Betruger (domain + IP, 80 and 443)
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.BetrugerC2Domain -Port 443
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.BetrugerC2Ip -Port 80
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.BetrugerC2Ip -Port 443

    Set-Content -Path "$($SimPaths.Logs)\c2_beacons.txt" -Value @"
[C2 stack - BlurringLinesSim]
SectopRAT   : $($Global:BlurIOCs.SectopRatC2):$($Global:BlurIOCs.SectopRatPorts -join ',')
SystemBC    : $($Global:BlurIOCs.SystemBcC2):$($Global:BlurIOCs.SystemBcPort)  (proxy/tunnel, RDP relay)
Betruger    : $($Global:BlurIOCs.BetrugerC2Domain) / $($Global:BlurIOCs.BetrugerC2Ip):80,443
Config src  : $($Global:BlurIOCs.PastebinHost) (MSBuild retrieved SectopRAT config)
"@ -Force
    Write-SimEvent -EventId 9002 -Message "SIMULATION: C2 beacons issued to SectopRAT/SystemBC/Betruger infrastructure (T1071.001/T1090/T1572)"

    Write-Host "  [OK] Command and Control artifacts created (Betruger + full C2 stack)" -ForegroundColor Yellow
}
