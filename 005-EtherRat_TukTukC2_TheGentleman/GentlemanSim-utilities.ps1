# ============================================================================
# ETHERRAT / TUKTUK / THE GENTLEMEN SIMULATION - UTILITY FUNCTIONS
# ============================================================================
# Source: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
# Utility functions shared by all GentlemanSim phase scripts.
# ============================================================================

function Confirm-Execution {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " WARNING: This script simulates a real malicious intrusion chain" -ForegroundColor Red
    Write-Host " (trojanized RAMMap MSI -> EtherRAT w/ EtherHiding C2 -> TukTuk" -ForegroundColor Red
    Write-Host " multi-channel SaaS C2 -> Kerberoasting/NTDS dumping -> GoTo" -ForegroundColor Red
    Write-Host " Resolve RMM lateral movement -> Rclone exfil to Wasabi -> The" -ForegroundColor Red
    Write-Host " Gentlemen ransomware via malicious GPO) based on a real DFIR" -ForegroundColor Red
    Write-Host " Report investigation." -ForegroundColor Red
    Write-Host " It creates local accounts, services, scheduled tasks, registry" -ForegroundColor Red
    Write-Host " keys, dropped files, and outbound connection attempts to REAL" -ForegroundColor Red
    Write-Host " threat-actor/blockchain IOC infrastructure taken from the report." -ForegroundColor Red
    Write-Host " ONLY run this on an isolated, disposable/snapshot VM that has" -ForegroundColor Red
    Write-Host " no access to production data or networks." -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red

    $confirmation = Read-Host "Type 'EXECUTE-GENTLEMAN-SIM' (exactly) to confirm you understand the risks"
    if ($confirmation -ne "EXECUTE-GENTLEMAN-SIM") {
        Write-Host "Execution cancelled." -ForegroundColor Yellow
        exit
    }

    Write-Host "`nSimulation starting. Creating attack artifacts..." -ForegroundColor Cyan
}

function Start-SimulationLogging {
    $logPath = "$env:TEMP\GentlemanSim_execution.log"
    Start-Transcript -Path $logPath -Append | Out-Null
    Write-Host "Logging to $logPath"
    return $logPath
}

function Initialize-SimulationEnvironment {
    $simRoot = "$env:SystemDrive\GentlemanSim"
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

    if (-not [System.Diagnostics.EventLog]::SourceExists("GentlemanSim")) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource("GentlemanSim", "Application")
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

# Real threat-actor / abused-SaaS infrastructure named in the DFIR Report -
# used only for outbound connection attempts, to generate authentic DNS/
# network telemetry. Connections are expected to fail/timeout from an
# isolated lab (no attacker-controlled infra reachable) - that is fine and
# intentional; it still produces real Sysmon/Zeek/firewall/DNS artifacts.
$Global:GentlemanIOCs = @{
    EtherHidingRPC       = "1rpc.io"
    TryCloudflareDomains = @(
        "witch-skins-lip-coal.trycloudflare.com",
        "fields-pct-easier-vancouver.trycloudflare.com",
        "howto-tar-naturals-coordination.trycloudflare.com",
        "workshop-lighting-protective-customs.trycloudflare.com",
        "afford-effect-construct-tricks.trycloudflare.com",
        "rapids-lil-lending-charleston.trycloudflare.com",
        "when-architectural-cdna-faster.trycloudflare.com",
        "mode-exit-legendary-trusted.trycloudflare.com",
        "seasonal-estimation-heating-necessarily.trycloudflare.com",
        "entered-medications-motherboard-advanced.trycloudflare.com",
        "walt-messaging-affairs-occurring.trycloudflare.com"
    )
    SupabaseDomain       = "vefbdzzuaadnascpeqcn.supabase.co"
    ClickHouseDomain     = "k135neflez.westus3.azure.clickhouse.cloud"
    FallbackHttpC2       = "borjumaniya.store"
    RelatedClickHouse    = "vngz3ntdrb.us-east1.gcp.clickhouse.cloud"
    RelatedSupabase      = "muurfzqprzmdkzoibxaz.supabase.co"
    RelatedNeon          = "ep-lively-cherry-a80bmwii.eastus2.azure.neon.tech"
    ArweaveGateways      = @("goldsky.arweave.net", "arweave.net", "g8way.io")
    ArweaveDriveId       = "a6278417-39f4-407e-90bf-599f74726e66"
    EthereumContracts    = @(
        "0xdf0b529043ef7a2bb9111bad26de624a326bacf9",
        "0x5953f27F044779a3AFCd2BF56a4B712583Dd2E4e"
    )
    NodeJsDownload       = "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"
    GoToResolveDomain    = "gotoresolve.com"
    WasabiExfilDomain    = "wasabisys.com"
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
        Write-EventLog -LogName "Application" -Source "GentlemanSim" -EventId $EventId -Message $Message -EntryType $EntryType
    } catch {}
}

function Test-DomainJoined {
    return (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
}

function New-DecoyBinary {
    <#
        Writes a random-byte placeholder binary. Used any time the report
        references a malware component we do not want to reconstruct/execute
        for real (EtherRAT node.exe payload, TukTuk sideloaded DLL, The
        Gentlemen locker, etc). The resulting file is inert but carries a
        realistic PE-ish size profile and a recognizable filename/path for
        artifact and IOC-matching purposes.
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
