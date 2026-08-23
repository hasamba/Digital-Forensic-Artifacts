# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 9: COMMAND AND CONTROL
# ============================================================================
# Simulates outbound beacons to the full set of reported C2 families:
#   Latrodectus  -> workspacin.cloud / illoskanawer.com / ... (/live/)
#   Brute Ratel  -> anikvan.com / erbolsan.com / ... (upfilles/wscadminui)
#   BackConnect  -> 193.168.143.196 / 185.93.221.12 : 443 (VNC-based)
#   Cobalt Strike-> 45.129.199.214 (/vodeo/wg01ck01), sys.dll -> 206.206.123.209
#                   / resources.avtechupdate.com/samlss/vm.ico, CS User-Agent
#   .NET backdoor-> cloudmeri.com (162.0.209.121) /comm.php every 250s
# MITRE: T1071.001 Web C2, T1571 Non-Standard Port, T1105 Ingress Tool Transfer
# ============================================================================

function Simulate-CommandAndControl {
    param($SimPaths)

    Write-Host "[+] Phase 9: Command and Control - multi-family beacons (real IOCs) ..." -ForegroundColor Green
    Write-Host "    (connections are expected to fail closed off-network - that is fine)" -ForegroundColor DarkGray

    # --- Latrodectus /live/ beacons -------------------------------------------
    foreach ($d in $Global:LunarIOCs.LatrodectusDomains) { Invoke-SafeNetworkAttempt -Target $d -Port 443 }
    Write-SimEvent -EventId 9001 -Message "SIMULATION: Latrodectus C2 beacons to $($Global:LunarIOCs.LatrodectusDomains -join ', ') (/live/)"

    # --- Brute Ratel C4 beacons -----------------------------------------------
    foreach ($d in $Global:LunarIOCs.BruteRatelDomains) { Invoke-SafeNetworkAttempt -Target $d -Port 443 }
    Write-SimEvent -EventId 9002 -Message "SIMULATION: Brute Ratel C4 beacons (upfilles.dll / wscadminui.dll config domains)"

    # --- BackConnect (VNC-based) ----------------------------------------------
    foreach ($ip in $Global:LunarIOCs.BackConnectIPs) { Invoke-SafeNetworkAttempt -Target $ip -Port 443 }
    Write-SimEvent -EventId 9003 -Message "SIMULATION: BackConnect VNC C2 to 193.168.143.196 / 185.93.221.12:443"

    # --- Cobalt Strike beacons (HTTP + sys.dll) -------------------------------
    # cron801.dl_/system.dl_ HTTP beacon path (with the reported CS User-Agent)
    $csBeaconLog = @"
[Cobalt Strike beacon - from report]
Version:      4.6   Jitter: 49%   Watermark: 987654321   MaxGetSize: 2105681
User-Agent:   $($Global:LunarIOCs.CobaltStrikeUA)
spawnto_x64:  %windir%\sysnative\gpupdate.exe
GET:          hxxp://45.129.199[.]214/vodeo/wg01ck01
sys.dll C2:   206.206.123[.]209:443  ->  resources.avtechupdate[.]com/samlss/vm.ico
"@
    Set-Content -Path "$($SimPaths.Logs)\cobaltstrike_beacon.log" -Value $csBeaconLog -Force
    foreach ($ip in $Global:LunarIOCs.CobaltStrikeC2) { Invoke-SafeNetworkAttempt -Target $ip -Port 80 }
    foreach ($d in $Global:LunarIOCs.CobaltStrikeDomains) { Invoke-SafeNetworkAttempt -Target $d -Port 443 }

    # sys.dll loaded via rundll32 StartUp471
    $sysDll = "$env:ALLUSERSPROFILE\sys.dll"
    New-DecoyBinary -Path $sysDll -SizeBytes 307200 | Out-Null   # sys.dll (MD5 ad3c5231... ref)
    Invoke-BenignRundll32 -DllPath $sysDll -ExportName "StartUp471"
    Write-SimEvent -EventId 9004 -Message "SIMULATION: Cobalt Strike HTTP beacon + sys.dll (rundll32 StartUp471) to avtechupdate.com"

    # --- Custom .NET backdoor (lsassa.exe) HTTPS loop -------------------------
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.DotNetBackdoorDomain -Port 443
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.DotNetBackdoorIP     -Port 443
    Set-Content -Path "$($SimPaths.Logs)\dotnet_backdoor_c2.log" `
        -Value "lsassa.exe -> hxxps://cloudmeri[.]com/comm.php (162.0.209.121:443), poll every 250s; sends username + machine name (obfuscated)" -Force
    Write-SimEvent -EventId 9005 -Message "SIMULATION: .NET backdoor lsassa.exe beacons to cloudmeri.com/comm.php every 250s"

    Write-Host "  [OK] Command and Control artifacts created" -ForegroundColor Yellow
}
