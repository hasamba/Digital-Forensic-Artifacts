#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ZeroQbotSimId = '055-Qbot_Zerologon_Cobalt_RDP_Exfil'
$script:ZeroQbotSimUrl = 'https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/'
$script:ZeroQbotSimAnchor = (Get-Date).ToUniversalTime().AddHours(-18)

function Get-ZeroQbotSimPaths {
    $root = Join-Path $env:PUBLIC 'ZeroQbotSim'
    [ordered]@{
        Root = $root
        Beachhead = Join-Path $root 'BEACHHEAD-01'
        Registry = Join-Path $root 'registry-canaries'
        Payloads = Join-Path $root 'payload-canaries'
        Hosts = Join-Path $root 'generated-hosts'
        Staging = Join-Path $root 'staging'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.ZeroQbotSim.owner'
    }
}

function Assert-ZeroQbotSimSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4, 5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-ZeroQbotSimManifest {
    param([string]$Type, [string]$Path, [string]$Action, [hashtable]$Details = @{})
    $paths = Get-ZeroQbotSimPaths
    [ordered]@{ timestampUtc = (Get-Date).ToUniversalTime().ToString('o'); scenarioId = $script:ZeroQbotSimId; type = $Type; path = $Path; action = $Action; details = $Details } |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-ZeroQbotSimEnvironment {
    $paths = Get-ZeroQbotSimPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:ZeroQbotSimId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root, $paths.Beachhead, $paths.Registry, $paths.Payloads, $paths.Hosts, $paths.Staging, $paths.Evidence)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $paths.Owner -Value $script:ZeroQbotSimId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-ZeroQbotSimManifest directory $paths.Root created-or-reused @{ cleanup = 'separate owned-root cleanup' }
    $paths
}

function Write-ZeroQbotSimFile {
    param([string]$Path, [AllowEmptyString()][string]$Content, [string]$Purpose = 'artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-ZeroQbotSimManifest file $Path created @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-ZeroQbotSimDecoy {
    param([string]$Path, [string]$Role, [string]$PublishedSha256 = 'NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-ZeroQbotSimManifest executable-decoy $Path copied-signed-cmd @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; publishedHashAsReported = $PublishedSha256; publishedHashIsWellFormedSha256 = [bool]($PublishedSha256 -match '^[0-9A-Fa-f]{64}$'); hashMatch = $false }
}

function Invoke-ZeroQbotSimDecoy {
    param([string]$FilePath, [string]$ReportedCommandLine, [string]$ReportedParent = 'explorer.exe')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'ZERO-QBOT-CANARY')
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-ZeroQbotSimManifest process $FilePath executed-signed-decoy @{ reportedParent = $ReportedParent; reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); reportedOnly = $true }
}

function Invoke-ZeroQbotSimLoopback {
    param([int]$Port, [string]$ReportedTarget, [string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try { $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null); $null = $async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-ZeroQbotSimManifest network "127.0.0.1:$Port" loopback-only @{ role = $Role; reportedTarget = $ReportedTarget; remote = $false; proxy = $false; bytesTransferred = 0 }
}

function Add-ZeroQbotSimTimeline {
    param([double]$OffsetHours, [string]$Phase, [string]$Event, [hashtable]$Details = @{})
    $paths = Get-ZeroQbotSimPaths
    [ordered]@{ timestampUtc = $script:ZeroQbotSimAnchor.AddHours($OffsetHours).ToString('o'); offsetHours = $OffsetHours; phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-ZeroQbotSimSummary {
    param($Paths)
    Write-ZeroQbotSimFile $Paths.Summary "ZeroQbotSim complete.`nSource: $script:ZeroQbotSimUrl`nQbot, minute-30 Zerologon, multi-host pivot, and the reported exfiltration window are preserved.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo malware, registry/task persistence, process injection, exploit, domain-controller password/hash/credential access, Kerberos request, service/RDP/pipe/remote action, real discovery, collection, IOC contact, or exfiltration occurred." 'operator summary'
}
