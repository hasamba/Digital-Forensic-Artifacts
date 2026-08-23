# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 2: EXECUTION / INJECTION
# ============================================================================
# Simulates: the Brute Ratel C4 loader (upfilles.dll) decrypts an XOR-then-RC4
# BRC4 badger, which injects Latrodectus into explorer.exe via CreateRemoteThread.
# Latrodectus (v1.3, campaign 2221766521) then downloads its stealer module
# (fxrm_vn_9.557302425.bin) via command ID 21. Day 4 adds a Cobalt Strike
# beacon (cron801.dl_ -> system.dl_) run via rundll32.
# MITRE: T1055 Process Injection, T1055.002 PE Injection,
# T1620 Reflective Code Loading, T1059.001 PowerShell, T1218.011 Rundll32
# ============================================================================

function Simulate-ExecutionAndInjection {
    param($SimPaths)

    Write-Host "[+] Phase 2: Execution / Injection - BRC4 -> Latrodectus -> stealer ..." -ForegroundColor Green

    # --- Record the BRC4 decryption chain as a forensic note (keys from report) ---
    $decryptLog = @"
[Brute Ratel C4 loader decryption chain - from report]
Stage: upfilles.dll ,stow
XOR key (intermediary):  21 79 3C 7A 39 5F 3E 24 54 4A 7A 35 6C 33 3E 32 5F 66 74 76 6D 59 3C 4D 00
RC4 key (BRC4 badger):   71 24 70 2C 7D 70 61 3F
API resolution:          CRC32 hash-based
Injection target:        explorer.exe (CreateRemoteThread)
"@
    Set-Content -Path "$($SimPaths.Logs)\brc4_decrypt_chain.log" -Value $decryptLog -Force

    # --- Stage the (inert) Brute Ratel badger and Latrodectus DLL placeholders ---
    $brc4Badger  = "$($SimPaths.Payloads)\brc4_badger.bin"
    $latroDll    = "$($SimPaths.Payloads)\latrodectus.dll"
    New-DecoyBinary -Path $brc4Badger -SizeBytes 98304  | Out-Null
    New-DecoyBinary -Path $latroDll   -SizeBytes 163840 | Out-Null

    # --- SAFE process-injection artifact into explorer.exe ---------------------
    # The report: BRC4 injected Latrodectus into explorer.exe via CreateRemoteThread.
    # We reproduce the exact API sequence (OpenProcess -> VirtualAllocEx(RWX) ->
    # WriteProcessMemory -> CreateRemoteThread) against a NEW, sacrificial notepad.exe
    # process we spawn ourselves - NOT the real explorer.exe - and the injected bytes
    # are an inert RET stub (0xC3). This yields authentic Sysmon EID 8
    # (CreateRemoteThread) + EID 10 (ProcessAccess) telemetry and an RWX/unbacked
    # allocation for memory-forensics practice, without harming the shell.
    Invoke-SafeRemoteThreadInjection -HostImage "notepad.exe" -SimPaths $SimPaths

    Write-SimEvent -EventId 2001 -Message "SIMULATION: Brute Ratel C4 injected Latrodectus into a sacrificial process via CreateRemoteThread (explorer.exe in the real case)"

    # --- Latrodectus config + stealer module download (command ID 21) ----------
    $latroConfig = @"
[Latrodectus configuration - decrypted, from report]
Version:      1.3
Campaign ID:  2221766521
C2s:          hxxps://workspacin[.]cloud/live/, hxxps://illoskanawer[.]com/live/
RC4 Key:      $($Global:LunarIOCs.LatrodectusRC4Key)
"@
    Set-Content -Path "$($SimPaths.Logs)\latrodectus_config.log" -Value $latroConfig -Force

    # Stealer module fetched via command ID 21
    $stealerModule = "$($SimPaths.Payloads)\fxrm_vn_9.557302425.bin"
    New-DecoyBinary -Path $stealerModule -SizeBytes 57344 | Out-Null
    foreach ($d in $Global:LunarIOCs.LatrodectusDomains) { Invoke-SafeNetworkAttempt -Target $d -Port 443 }
    Write-SimEvent -EventId 2002 -Message "SIMULATION: Latrodectus (v1.3) downloaded stealer module fxrm_vn_9.557302425.bin via command ID 21"

    # --- Day 4: Cobalt Strike beacon cron801.dl_ (renamed system.dl_) ----------
    $cron = "$env:ALLUSERSPROFILE\cron801.dl_"
    New-DecoyBinary -Path $cron -SizeBytes 286720 | Out-Null
    $system = "$env:ALLUSERSPROFILE\system.dl_"
    Copy-Item -Path $cron -Destination $system -Force
    Write-Host "    Executing Cobalt Strike loader: rundll32 cron801.dl_,lvQkzdrFdILT ..." -ForegroundColor DarkGray
    Invoke-BenignRundll32 -DllPath $cron -ExportName "lvQkzdrFdILT"
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.CobaltStrikeC2[0] -Port 80
    Write-SimEvent -EventId 2003 -Message "SIMULATION: Cobalt Strike beacon cron801.dl_/system.dl_ executed via rundll32 (C2 45.129.199.214)"

    Write-Host "  [OK] Execution/Injection artifacts created" -ForegroundColor Yellow
    return $stealerModule
}

function Invoke-SafeRemoteThreadInjection {
    <#
        Spawns a fresh, suspended-then-visible sacrificial host process and performs
        a REAL CreateRemoteThread injection of an inert RET (0xC3) stub into it via
        P/Invoke. Purpose: generate authentic Sysmon EID 8/10 + RWX allocation
        artifacts for detection/memory-forensics training. No malicious code runs;
        the remote thread returns immediately. Never targets a real system process.
    #>
    param(
        [Parameter(Mandatory)][string]$HostImage,
        [Parameter(Mandatory)]$SimPaths
    )

    $signature = @'
using System;
using System.Runtime.InteropServices;
public static class RTInj {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool i, uint pid);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, uint size, uint type, uint prot);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, uint size, out UIntPtr wrote);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);
    public static void Inject(uint pid) {
        IntPtr h = OpenProcess(0x1F0FFF, false, pid);
        if (h == IntPtr.Zero) return;
        byte[] stub = new byte[] { 0xC3 }; // RET - inert
        IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, 0x1000, 0x3000, 0x40); // MEM_COMMIT|RESERVE, RWX
        UIntPtr wrote;
        WriteProcessMemory(h, mem, stub, (uint)stub.Length, out wrote);
        CreateRemoteThread(h, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
'@
    try {
        if (-not ("RTInj" -as [type])) {
            Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue | Out-Null
        }
        $proc = Start-Process -FilePath $HostImage -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        if ($proc) {
            Start-Sleep -Milliseconds 500
            [RTInj]::Inject([uint32]$proc.Id)
            Start-Sleep -Seconds 1
            Set-Content -Path "$($SimPaths.Logs)\injection_target.log" `
                -Value "Sacrificial host $HostImage PID $($proc.Id) - RWX alloc + CreateRemoteThread (inert RET stub)" -Force
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Safe injection artifact skipped: $($_.Exception.Message)"
    }
}
