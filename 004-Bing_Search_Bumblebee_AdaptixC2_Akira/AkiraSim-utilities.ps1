# ============================================================================
# AKIRA / BUMBLEBEE / ADAPTIXC2 SIMULATION - UTILITY FUNCTIONS
# ============================================================================
# Source: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
# Utility functions shared by all AkiraSim phase scripts.
# ============================================================================

function Confirm-Execution {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " WARNING: This script simulates a real malicious intrusion chain" -ForegroundColor Red
    Write-Host " (BumbleBee loader -> AdaptixC2 -> credential theft -> Akira" -ForegroundColor Red
    Write-Host " ransomware) based on a real DFIR Report investigation." -ForegroundColor Red
    Write-Host " It creates local accounts, services, scheduled tasks, registry" -ForegroundColor Red
    Write-Host " keys, dropped files, and outbound connection attempts to REAL" -ForegroundColor Red
    Write-Host " threat-actor IOC infrastructure taken from the report." -ForegroundColor Red
    Write-Host " ONLY run this on an isolated, disposable/snapshot VM that has" -ForegroundColor Red
    Write-Host " no access to production data or networks." -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red

    $confirmation = Read-Host "Type 'EXECUTE-AKIRA-SIM' (exactly) to confirm you understand the risks"
    if ($confirmation -ne "EXECUTE-AKIRA-SIM") {
        Write-Host "Execution cancelled." -ForegroundColor Yellow
        exit
    }

    Write-Host "`nSimulation starting. Creating attack artifacts..." -ForegroundColor Cyan
}

function Start-SimulationLogging {
    $logPath = "$env:TEMP\AkiraSim_execution.log"
    Start-Transcript -Path $logPath -Append | Out-Null
    Write-Host "Logging to $logPath"
    return $logPath
}

function Initialize-SimulationEnvironment {
    $simRoot = "$env:SystemDrive\AkiraSim"
    $directories = @(
        "$simRoot\payloads",
        "$simRoot\tools",
        "$simRoot\logs",
        "$simRoot\exfil",
        "$simRoot\victim_files",
        "$simRoot\staging"
    )
    foreach ($dir in $directories) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    if (-not [System.Diagnostics.EventLog]::SourceExists("AkiraSim")) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource("AkiraSim", "Application")
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
    }
}

# Real threat-actor infrastructure from the DFIR Report - used for outbound
# connection attempts only, to generate authentic DNS/network telemetry.
# Connections will typically fail closed (sinkholed/offline) - that is expected
# and still yields real Sysmon/Zeek/firewall artifacts for detection engineering.
$Global:AkiraIOCs = @{
    BumbleBeeDomains = @(
        "ev2sirbd269o5j.org", "2rxyt9urhq0bgj.org", "d1hmxkpwby0d4s.org",
        "yj6jurm5qqkye5.org", "ewujsfb1dp5ran.org", "8doj8uvx604eck.org",
        "kwywztxoo2xdot.org", "ky1d1p1daahe5t.org", "ovh1kn1tcqw5kp.org",
        "6cimu4mc085em8.org", "5ka8rxp6t6eup2.org", "ks501oz9nm3v05.org",
        "v5rjsdqogstopr.org"
    )
    BumbleBeeIPs     = @("188.40.187.145", "109.205.195.211", "171.22.183.43", "192.121.22.94", "194.127.178.21")
    AdaptixC2IP      = "172.96.137.160"
    ReverseSSHIP     = "193.242.184.150"
    ExfilServerIP    = "185.174.100.203"
    SEODomains       = @("opmanager.pro", "download-center.online", "ip-scanner.org")
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
        Write-EventLog -LogName "Application" -Source "AkiraSim" -EventId $EventId -Message $Message -EntryType $EntryType
    } catch {}
}

function Test-DomainJoined {
    return (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
}

function New-DecoyBinary {
    <#
        Writes a random-byte placeholder binary. Used any time the report
        references a malware component we do not want to reconstruct/execute
        for real (BumbleBee DLL, AdaptixC2 shellcode carrier, Akira core, etc).
        The resulting file is inert but carries a realistic PE-ish size profile
        and a recognizable filename/path for artifact and IOC-matching purposes.
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
