# ============================================================================
# BLURRING THE LINES - PLAY / RANSOMHUB / DRAGONFORCE INTRUSION - UTILITIES
# ============================================================================
# Source: "Blurring the Lines: Intrusion Shows Connection with Three Major
# Ransomware Gangs" - The DFIR Report, 2025-09-08
#   https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-
#   connection-with-three-major-ransomware-gangs/
#
# One affiliate, tooling from THREE gangs:
#   - Play        -> Grixba recon (GT_NET.exe / GRB_NET.exe), SystemBC
#   - RansomHub   -> Betruger backdoor (ccs.exe), C:\Users\Public\Music staging
#   - DragonForce -> SystemBC overlap + a prior-victim NetScan output artifact
#
# Utility functions shared by all BlurringLinesSim phase scripts.
# LAB-ONLY. Every function here makes real, system-modifying changes or reaches
# real threat-actor IOC infrastructure. Run only on an isolated, snapshot VM.
# ============================================================================

function Confirm-Execution {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " WARNING: This script simulates a real ransomware-affiliate"       -ForegroundColor Red
    Write-Host " intrusion chain (fake EarthTime.exe -> MSBuild -> SectopRAT ->"    -ForegroundColor Red
    Write-Host " SystemBC proxy -> Betruger backdoor -> Grixba/SharpHound recon"    -ForegroundColor Red
    Write-Host " -> DCSync / Veeam credential theft -> RDP+wmiexec lateral"         -ForegroundColor Red
    Write-Host " movement -> WinRAR + WinSCP FTP exfiltration) based on a real"     -ForegroundColor Red
    Write-Host " DFIR Report investigation linking Play, RansomHub and"             -ForegroundColor Red
    Write-Host " DragonForce."                                                      -ForegroundColor Red
    Write-Host " It creates local accounts, BITS jobs, scheduled/startup"           -ForegroundColor Red
    Write-Host " persistence, registry keys, dropped tooling, and outbound"         -ForegroundColor Red
    Write-Host " connection attempts to REAL threat-actor infrastructure taken"     -ForegroundColor Red
    Write-Host " from the report."                                                  -ForegroundColor Red
    Write-Host " ONLY run this on an isolated, disposable/snapshot VM that has"      -ForegroundColor Red
    Write-Host " no access to production data or networks."                         -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red

    $confirmation = Read-Host "Type 'EXECUTE-BLURRINGLINES-SIM' (exactly) to confirm you understand the risks"
    if ($confirmation -ne "EXECUTE-BLURRINGLINES-SIM") {
        Write-Host "Execution cancelled." -ForegroundColor Yellow
        exit
    }

    Write-Host "`nSimulation starting. Creating attack artifacts..." -ForegroundColor Cyan
}

function Start-SimulationLogging {
    $logPath = "$env:TEMP\BlurringLinesSim_execution.log"
    Start-Transcript -Path $logPath -Append | Out-Null
    Write-Host "Logging to $logPath"
    return $logPath
}

function Initialize-SimulationEnvironment {
    $simRoot = "$env:SystemDrive\BlurringLinesSim"
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

    # The report's signature staging path (RansomHub TTP): a publicly writable,
    # low-visibility folder used for nearly every dropped tool. Created here so
    # every phase can drop into the exact reported location.
    New-Item -Path "$env:SystemDrive\Users\Public\Music" -ItemType Directory -Force | Out-Null

    if (-not [System.Diagnostics.EventLog]::SourceExists("BlurringLinesSim")) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource("BlurringLinesSim", "Application")
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
        PublicMusic = "$env:SystemDrive\Users\Public\Music"
    }
}

function Disable-DefenderForSimulation {
    <#
        Disables Microsoft Defender real-time protection for the duration of the
        simulation so the chain detonates deterministically and leaves the
        intended artifacts. Authentic behavior: the report shows the actor
        disabling Defender via HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
        policy writes (T1562.001 Impair Defenses: Disable or Modify Tools).

        On modern Windows, Tamper Protection blocks Set-MpPreference / registry
        edits; if so, the individual calls fail closed and we log that Defender is
        still active. Turn Tamper Protection OFF once in the VM image and snapshot
        for a deterministic run.
    #>
    param([switch]$AddExclusions)

    Write-Host "[*] Disabling Microsoft Defender for the simulation (lab-only, T1562.001) ..." -ForegroundColor Magenta

    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue } catch {}
    try { Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue } catch {}

    # Registry policy writes exactly as the report describes (real system change)
    try {
        $rt = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        New-Item -Path $rt -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $rt -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rt -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rt -Name "DisableOnAccessProtection"  -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        $dp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        New-Item -Path $dp -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $dp -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}

    if ($AddExclusions) {
        try { Add-MpPreference -ExclusionPath "$env:SystemDrive\BlurringLinesSim" -ErrorAction SilentlyContinue } catch {}
        try { Add-MpPreference -ExclusionPath "$env:SystemDrive\Users\Public\Music" -ErrorAction SilentlyContinue } catch {}
    }

    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        Write-Host ("    RealTimeProtection now: {0}  (Tamper Protection: {1})" -f `
            $st.RealTimeProtectionEnabled, $st.IsTamperProtected) -ForegroundColor DarkGray
        if ($st.RealTimeProtectionEnabled) {
            Write-Host "    [!] Defender still active - Tamper Protection likely ON. Disable it once in the VM image and snapshot." -ForegroundColor Yellow
        } else {
            Write-Host "    [OK] Defender real-time protection disabled." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Defender status query unavailable (Defender may be absent on this VM)." -ForegroundColor DarkGray
    }
    Write-SimEvent -EventId 1000 -Message "SIMULATION: attempted to disable Microsoft Defender via policy keys (T1562.001) at simulation start"
}

# Real threat-actor infrastructure and IOCs from the DFIR Report. Used for
# outbound connection attempts only, to generate authentic DNS/network telemetry.
# Connections typically fail closed (offline/sinkholed) - that is expected and
# still yields real Sysmon/Zeek/firewall artifacts for detection engineering.
$Global:BlurIOCs = @{
    # SectopRAT / ArechClient2 (WakeWordEngine.dll injected into MSBuild.exe)
    SectopRatC2       = "45.141.87.55"
    SectopRatPorts    = @(9000, 15647)

    # SystemBC proxy/tunnel (loaded in-memory from WakeWordEngine.dll / conhost.dll)
    SystemBcC2        = "149.28.101.219"   # port 443 tunnel enabling RDP-over-proxy
    SystemBcPort      = 443

    # Betruger backdoor (ccs.exe, spoofed as Avast)
    BetrugerC2Ip      = "80.78.28.149"     # ports 80, 443
    BetrugerC2Domain  = "504e1c95.host.njalla.net"

    # WinSCP clear-text FTP exfiltration endpoint (US-based cloud host)
    ExfilFtpIp        = "144.202.61.209"
    ExfilFtpPort      = 21

    # MSBuild retrieved its C2 configuration from Pastebin (T1102 / T1105)
    PastebinHost      = "pastebin.com"

    # Malicious code-signing identity on EarthTime.exe (revoked, known-bad signer)
    RevokedSigner     = "Brave Pragmatic Network Technology Co., Ltd."

    # Local account the actor created and added to Administrators
    LocalAccountUser  = "Admon"
    LocalAccountPass  = "Qwerty12345!"

    # Threat-actor RDP client hostnames observed in the logs (note the typo)
    ActorHostnames    = @("DESCTOP-QPITRY", "DESKTOP-A1HRTMJ", "DESKTOP-PGD76HT", "WIN-FLGU1CC210K")

    # DCSync object GUID: DS-Replication-Get-Changes (Security Event ID 4662)
    DcsyncObjectGuid  = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

    # Reference file hashes (SHA256) for YARA/IOC cross-checking - not fetched
    Hashes = @{
        "EarthTime.exe"        = "bcff246f0739ed98f8aa615d256e7e00bc1cb24c8cabaea609b25c3f050c7805"
        "WakeWordEngine.dll"   = "6f9326224e6047458e692cd27aeb1054b9381c67aaf2fe238dbebfbc916c4b33"
        "ccs.exe"              = "ae7c31d4547dd293ba3fd3982b715c65d731ee07a9c1cc402234d8705c01dfca"
        "GT_NET.exe"           = "aeaf7cc7364a44b381af9f317fe6f78c2717217800b93bee8839ab3e56233254"
        "GRB_NET.exe"          = "f8810179ab033a9b79cd7006c1a74fbcde6ed0451c92fbb8c7ce15b52499353a"
        "netscan.exe"          = "18f0898d595ec054d13b02915fb7d3636f65b8e53c0c66b3c7ee3b6fc37d3566"
        "sh.exe"               = "a7240d8a7aee872c08b915a58976a1ddee2ff5a8a679f78ec1c7cf528f40deed"
        "adfind.exe"           = "c92c158d7c37fea795114fa6491fe5f145ad2f8c08776b18ae79db811e8e36a3"
        "fs64.exe"             = "e1521e077079032df974c7ae39e4737cdb4f05c6ded677ed5446167466eeb899"
    }
}

# --- Timeline anchors: the report describes a 6-day intrusion ---------------
# Day 1 = initial access + persistence + SystemBC + DCSync.
# Day 2 = lateral movement, Grixba/Veeam, WinRAR+FTP exfiltration, recon tools.
# Day 6 = Betruger (ccs.exe) second payload + Impacket wmiexec from the DC.
# Backdating dropped artifacts into these three clusters (instead of one short
# run) makes the on-disk/event cadence match the real incident - one of the
# clearest tells of a synthetic run. Anchored to "now" so it always looks recent.
$Global:BlurTimeline = @{
    Day1 = (Get-Date).AddDays(-6)
    Day2 = (Get-Date).AddDays(-5)
    Day6 = (Get-Date).AddDays(-1)
}

function Set-ArtifactTimestamp {
    <#
        Backdates Creation/LastWrite/LastAccess on a dropped artifact so it falls
        into the correct intrusion day. Best-effort; locked files are skipped.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][datetime]$Anchor,
        [int]$JitterMinutes = 0
    )
    if (-not (Test-Path $Path)) { return }
    $ts = if ($JitterMinutes -gt 0) { $Anchor.AddMinutes((Get-Random -Minimum 0 -Maximum $JitterMinutes)) } else { $Anchor }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $item.CreationTime   = $ts
        $item.LastWriteTime  = $ts.AddMinutes((Get-Random -Minimum 1 -Maximum 5))
        $item.LastAccessTime = $ts.AddMinutes((Get-Random -Minimum 1 -Maximum 5))
    } catch {}
}

function Invoke-SafeNetworkAttempt {
    <#
        Fires a real DNS resolution + TCP connect toward a report IOC to generate
        authentic DNS/connection telemetry (Sysmon EID 3/22, Zeek conn/dns,
        firewall logs). Fails closed against offline hosts - expected.
    #>
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
        Write-EventLog -LogName "Application" -Source "BlurringLinesSim" -EventId $EventId -Message $Message -EntryType $EntryType
    } catch {}
}

function Test-DomainJoined {
    return (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
}

function New-DecoyBinary {
    <#
        Writes a random-byte placeholder binary with an MZ header. Used for files
        the report references that we do NOT execute (they exist purely as
        on-disk / YARA-gating IOC artifacts). Not a valid PE - never Start-Process
        one of these; use New-RunnablePayload for anything that must launch.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$SizeBytes = 4096
    )
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $bytes = New-Object byte[] $SizeBytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $bytes[0] = 0x4D; $bytes[1] = 0x5A   # 'MZ' so PE-gating YARA rules still match
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    return $Path
}

function New-RunnablePayload {
    <#
        Produces a payload file at $Path that IS a real, launchable Windows PE by
        copying a benign Microsoft-signed system binary (default: where.exe, a
        tiny console LOLBin that exits immediately) to the malware's name/path.
        Unlike New-DecoyBinary (random bytes + MZ header, which is NOT a valid PE
        and makes Start-Process fail with "not a valid application for this OS
        platform" or pop an "Unsupported 16-Bit Application" modal), this launches
        for real, so the simulation produces the full execution artifact set:
          - Sysmon EID 1 / Security 4688 process creation (correct image name,
            path, hashes, parent-child tree)
          - Prefetch (<NAME>.EXE-<HASH>.pf), Amcache, ShimCache entries
          - Image-load telemetry

        SAFETY: the copied binary is an ordinary signed Windows tool doing nothing
        harmful; only its FILE NAME impersonates the malware. No SectopRAT /
        SystemBC / Betruger / Grixba code is ever reconstructed or run. The
        report's YARA/string IOCs are appended as a benign OVERLAY past the PE so
        string/YARA matching still works while the PE stays valid and launchable.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$SeedBinary = "$env:SystemRoot\System32\where.exe",
        [string[]]$OverlayStrings = @()
    )
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    if (-not (Test-Path $SeedBinary)) {
        Write-Warning "Seed binary '$SeedBinary' not found - falling back to inert (non-runnable) decoy for $Path"
        return (New-DecoyBinary -Path $Path -SizeBytes 73802)
    }

    Copy-Item -Path $SeedBinary -Destination $Path -Force

    if ($OverlayStrings.Count -gt 0) {
        $overlay = "`r`n[BLURRINGLINESSIM-OVERLAY] " + ($OverlayStrings -join " | ") + "`r`n"
        $overlayBytes = [System.Text.Encoding]::ASCII.GetBytes($overlay)
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append)
        try { $fs.Write($overlayBytes, 0, $overlayBytes.Length) } finally { $fs.Close() }
    }
    return $Path
}

function Invoke-RunPayload {
    <#
        Launches a New-RunnablePayload PE to produce an authentic process-creation
        artifact (correct image name/path, parent = this PowerShell/cmd), then
        bounds it with WaitForExit and kills any stray instance. where.exe with an
        unknown arg exits on its own in milliseconds; the WaitForExit is a backstop.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Arguments = "",
        [int]$TimeoutMs = 4000
    )
    if (-not (Test-Path $Path)) { return }
    try {
        $p = Start-Process -FilePath $Path -ArgumentList $Arguments -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($p) {
            if (-not $p.WaitForExit($TimeoutMs)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        }
    } catch {}
}

function Invoke-BenignRundll32 {
    <#
        Reproduces the "rundll32 <payload>,<export>" process-tree and command-line
        artifact (Sysmon EID 1, Prefetch, Amcache) using the REAL, signed Windows
        rundll32.exe pointed at an inert placeholder DLL. rundll32 exits
        immediately (no functional payload runs) yet the command line, parent/child
        relationship, and image-load telemetry are authentic. Modal error dialogs
        (from the invalid DLL) are suppressed so the run stays fully unattended.
    #>
    param(
        [Parameter(Mandatory)][string]$DllPath,
        [Parameter(Mandatory)][string]$ExportName
    )
    try {
        $sig = 'using System;using System.Runtime.InteropServices;public static class WinErrModeBL{[DllImport("kernel32.dll")]public static extern uint SetErrorMode(uint m);}'
        if (-not ("WinErrModeBL" -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue | Out-Null }
        $prev = [WinErrModeBL]::SetErrorMode(0x8003)   # SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX
        try {
            $p = Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" `
                -ArgumentList "`"$DllPath`",$ExportName" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                if (-not $p.WaitForExit(3000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
            }
        } finally {
            [WinErrModeBL]::SetErrorMode($prev) | Out-Null
        }
        Get-Process -Name "rundll32" -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-6) } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Get-MSBuildPath {
    <#
        Locates a real MSBuild.exe (ships with the .NET Framework, present by
        default on Windows). Used by Phase 1 to run a benign inline-task project so
        the T1127.001 "MSBuild as a proxy execution" artifact (real MSBuild.exe
        process creation + child telemetry) is authentic. Returns $null if none
        is found, and the caller falls back to a logged command-line artifact.
    #>
    $candidates = @(
        "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $vs = Get-ChildItem "$env:ProgramFiles*\Microsoft Visual Studio" -Recurse -Filter "MSBuild.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vs) { return $vs.FullName }
    return $null
}
