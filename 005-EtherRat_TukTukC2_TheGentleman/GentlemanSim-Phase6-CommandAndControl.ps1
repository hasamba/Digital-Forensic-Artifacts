# ============================================================================
# GENTLEMAN SIMULATION - PHASE 6: COMMAND AND CONTROL
# ============================================================================
# Simulates: TukTuk's primary C2 channels through SaaS platforms ClickHouse
# and Supabase, secondary/backup channels (Ably, Dropbox, direct HTTP,
# GitHub Issues), and the threat actor's use of GoTo Resolve RMM as a
# blended C2/remote-access channel.
# MITRE: T1102 Web Service, T1071.001 Web Protocols, T1219 Remote Access
#        Software
# ============================================================================

function Simulate-CommandAndControl {
    param($SimPaths)

    Write-Host "[+] Phase 6: Command and Control - TukTuk SaaS Channels + GoTo Resolve ..." -ForegroundColor Green

    # --- Primary channels: ClickHouse + Supabase (real domains from the report) ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.ClickHouseDomain -Port 443
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.SupabaseDomain -Port 443
    Write-SimEvent -EventId 6001 -Message "SIMULATION: TukTuk primary C2 channels contacted - ClickHouse ($($Global:GentlemanIOCs.ClickHouseDomain)) and Supabase ($($Global:GentlemanIOCs.SupabaseDomain))"

    # --- Related-campaign SaaS infrastructure (same TukTuk family, different intrusion) ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.RelatedClickHouse -Port 443
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.RelatedSupabase -Port 443
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.RelatedNeon -Port 443
    Write-SimEvent -EventId 6002 -Message "SIMULATION: related-campaign TukTuk SaaS infrastructure telemetry generated (ClickHouse/Supabase/Neon variants)"

    # --- Fallback HTTP C2 ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.FallbackHttpC2 -Port 80
    Write-SimEvent -EventId 6003 -Message "SIMULATION: TukTuk fallback HTTP C2 contacted - $($Global:GentlemanIOCs.FallbackHttpC2)"

    # --- Secondary/backup transports: Ably, Dropbox, GitHub Issues ---
    $secondaryTransports = @(
        @{ Name = "Ably";          Domain = "realtime.ably.io" },
        @{ Name = "Dropbox";       Domain = "api.dropboxapi.com" },
        @{ Name = "GitHub Issues"; Domain = "api.github.com" }
    )
    foreach ($t in $secondaryTransports) {
        Invoke-SafeNetworkAttempt -Target $t.Domain -Port 443
        Write-SimEvent -EventId 6004 -Message "SIMULATION: TukTuk secondary/backup C2 transport check - $($t.Name) ($($t.Domain))"
    }

    # --- GoTo Resolve RMM used as blended C2/remote access channel ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.GoToResolveDomain -Port 443
    Write-SimEvent -EventId 6005 -Message "SIMULATION: GoTo Resolve RMM (gotoresolve.com) used for remote access blending with legitimate administrative traffic (T1219)"

    Set-Content -Path "$($SimPaths.Logs)\phase6_c2_channels.log" -Value @"
Primary: $($Global:GentlemanIOCs.ClickHouseDomain), $($Global:GentlemanIOCs.SupabaseDomain)
Fallback HTTP: $($Global:GentlemanIOCs.FallbackHttpC2)
Secondary/backup: $(($secondaryTransports | ForEach-Object { $_.Name }) -join ', ')
RMM channel: $($Global:GentlemanIOCs.GoToResolveDomain)
"@ -Force

    Write-Host "  [OK] C2 artifacts created across TukTuk SaaS channels + GoTo Resolve" -ForegroundColor Yellow
}
