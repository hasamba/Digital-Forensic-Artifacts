# ============================================================================
# AKIRA SIMULATION - PHASE 1: INITIAL ACCESS (SEO Poisoning -> BumbleBee)
# ============================================================================
# Simulates: Bing SEO poisoning lure -> trojanized ManageEngine OpManager MSI
# -> DLL search-order hijack (consent.exe sideloads msimg32.dll) -> BumbleBee
# first-stage loader C2 beacon.
# MITRE: T1189 Drive-by Compromise, T1204.002 Malicious File, T1574.001 DLL
# Search Order Hijacking, T1036 Masquerading
# ============================================================================

function Simulate-InitialAccess {
    param($SimPaths)

    Write-Host "[+] Phase 1: Initial Access - SEO Poisoning / BumbleBee ..." -ForegroundColor Green

    # --- Simulate browser history / download of the trojanized installer ---
    # Real report chain: Bing search -> opmanager[.]pro -> download-center[.]online -> MSI
    $historyLog = @"
[Simulated browser navigation history - AkiraSim]
https://www.bing.com/search?q=ManageEngine+OpManager+download
https://opmanager[.]pro/
https://download-center[.]online/Get?q=opmanager
File download: ManageEngine-OpManager.msi
"@
    Set-Content -Path "$($SimPaths.Logs)\browser_history_sim.log" -Value $historyLog -Force

    foreach ($domain in $Global:AkiraIOCs.SEODomains) {
        Invoke-SafeNetworkAttempt -Target $domain -Port 443
    }

    # --- Stage the MSI on a "network share" then land on the desktop (as in report) ---
    $shareStage = "$($SimPaths.Staging)\network_share\ManageEngine-OpManager.msi"
    New-DecoyBinary -Path $shareStage -SizeBytes 2621440 | Out-Null

    $desktopMsi = "$env:USERPROFILE\Desktop\ManageEngine-OpManager.msi"
    Copy-Item -Path $shareStage -Destination $desktopMsi -Force

    # --- MSI "installs" and drops the DLL side-loading trio into %TEMP% ---
    $installFolder = "$env:TEMP\ApplicationInstallationFolder_11"
    New-Item -Path $installFolder -ItemType Directory -Force | Out-Null

    # 1) Legit-looking decoy binary (the real OpManager installer, standing in as a placeholder)
    $decoyExe = "$installFolder\ManageEngine_OpManager_64bit.exe"
    New-DecoyBinary -Path $decoyExe -SizeBytes 10485760 | Out-Null

    # 2) consent.exe - copy the REAL, legitimate signed Windows UAC binary to stage the sideload
    $consentSrc = "$env:SystemRoot\System32\consent.exe"
    $consentDst = "$installFolder\consent.exe"
    if (Test-Path $consentSrc) {
        Copy-Item -Path $consentSrc -Destination $consentDst -Force
    } else {
        New-DecoyBinary -Path $consentDst -SizeBytes 65536 | Out-Null
    }

    # 3) msimg32.dll - the BumbleBee first-stage loader stand-in. This is a benign
    #    placeholder DLL (not functional malware) dropped alongside consent.exe to
    #    reproduce the exact DLL search-order hijack path/filename pair that Sysmon
    #    and the Sigma rule "System File Execution Location Anomaly" alert on.
    $maliciousDll = "$installFolder\msimg32.dll"
    New-DecoyBinary -Path $maliciousDll -SizeBytes 184320 | Out-Null

    Write-SimEvent -EventId 1001 -Message "SIMULATION: MSI dropped DLL side-load trio into $installFolder (consent.exe + msimg32.dll)"

    # --- Execute consent.exe from the %TEMP% path (parent=explorer.exe, matches report) ---
    # This is a REAL execution of the legitimate Windows consent.exe binary from an
    # abnormal location, which is exactly what the Sigma "System File Execution
    # Location Anomaly" rule and Sysmon Event ID 1 (process creation from AppData/Temp)
    # are designed to catch. The dropped msimg32.dll next to it is inert, so no actual
    # sideload/injection happens here - that is demonstrated safely in Phase 2.
    try {
        Start-Process -FilePath $consentDst -ArgumentList "/C" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Get-Process -Name "consent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}

    # --- BumbleBee geofence check + DGA C2 beacon simulation ---
    $localeLog = "BumbleBee loader geofence check: GetSystemDefaultLocaleName() = $((Get-WinSystemLocale).Name) -> not in CIS block-list, continuing.`n"
    Set-Content -Path "$($SimPaths.Logs)\bumblebee_geofence.log" -Value $localeLog -Force

    Write-Host "    Beaconing to BumbleBee DGA domains (real IOCs, expect failures) ..." -ForegroundColor DarkGray
    foreach ($domain in $Global:AkiraIOCs.BumbleBeeDomains) {
        Invoke-SafeNetworkAttempt -Target $domain -Port 443
    }
    foreach ($ip in $Global:AkiraIOCs.BumbleBeeIPs) {
        Invoke-SafeNetworkAttempt -Target $ip -Port 443
    }

    Write-SimEvent -EventId 1002 -Message "SIMULATION: BumbleBee loader (msimg32.dll sideloaded via consent.exe) established outbound C2 beacon"

    Write-Host "  [OK] Initial Access artifacts created ($installFolder)" -ForegroundColor Yellow
    return $installFolder
}
