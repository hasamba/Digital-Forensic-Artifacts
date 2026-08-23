# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 11: IMPACT (no ransomware)
# ============================================================================
# The report is explicit: despite ~2 months of dwell time and full access to
# critical infrastructure (DC, file share, backup server), NO ransomware was
# deployed. The observed impact was data exfiltration (Phase 10) and long-term
# access. This phase records that outcome as a forensic marker instead of
# encrypting anything - deliberately different from ransomware cases 002/004/007.
# MITRE: T1657 Financial Theft (exfil-driven), T0000 (no T1486 Data Encrypted)
# ============================================================================

function Simulate-Impact {
    param($SimPaths)

    Write-Host "[+] Phase 11: Impact - dwell + exfiltration (NO ransomware) ..." -ForegroundColor Green

    $summary = @"
=== LUNAR SPIDER INTRUSION - IMPACT SUMMARY ===
Outcome:            Data exfiltration + near-two-month persistent access.
Ransomware:         NONE observed. No file encryption, no ransom note, no VSS
                    deletion. (Contrast with the BlackSuit/Akira/LockBit cases
                    in this repo, which DO reach T1486.)
Dwell time:         ~60 days (initial JS click -> eviction).
Exfiltration:       Day 20, ~9h46m, Rclone (sihosts.exe) over FTP to
                    45.135.232[.]3 (user J0eBidenAbrabdy1aS3ha2Yeami).
Access footprint:   Domain controller, file share server, backup server.
Attribution:        Lunar Spider (Latrodectus / Brute Ratel C4 tradecraft).

For the analyst: the investigative value here is the LONG, layered C2 stack and
the credential-theft / lateral-movement chain - not an encryption event. Build
your timeline from the persistence (Run key 'Update', SchedulerLsass), the C2
beacons (Phase 9), and the exfil launcher (start.vbs -> run.bat -> sihosts.exe).
"@
    Set-Content -Path "$($SimPaths.VictimFiles)\_INTRUSION_IMPACT_SUMMARY.txt" -Value $summary -Force
    Write-SimEvent -EventId 11001 -Message "SIMULATION: Impact = exfiltration + persistent access; NO ransomware deployed (per report)"

    Write-Host "  [OK] Impact marker written (no encryption performed)" -ForegroundColor Yellow
}
