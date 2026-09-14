#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Year2021SimId = '054-2021_YearInReview_Composite_Trends'
$script:Year2021SimUrl = 'https://thedfirreport.com/2022/03/07/2021-year-in-review/'
$script:Year2021SimAnchor = (Get-Date).ToUniversalTime().AddHours(-24)

function Get-Year2021SimPaths {
    $root = Join-Path $env:PUBLIC 'YearReview2021Sim'
    [ordered]@{
        Root = $root
        Cases = Join-Path $root 'synthetic-case-lanes'
        Tooling = Join-Path $root 'tool-canaries'
        Evidence = Join-Path $root 'evidence'
        Impact = Join-Path $root 'impact-canaries'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\aggregate-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.YearReview2021Sim.owner'
    }
}

function Assert-Year2021SimSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4, 5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-Year2021SimManifest {
    param([string]$Type, [string]$Path, [string]$Action, [hashtable]$Details = @{})
    $paths = Get-Year2021SimPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:Year2021SimId
        aggregateComposite = $true
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-Year2021SimEnvironment {
    $paths = Get-Year2021SimPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:Year2021SimId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root, $paths.Cases, $paths.Tooling, $paths.Evidence, $paths.Impact)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:Year2021SimId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-Year2021SimManifest directory $paths.Root created-or-reused @{ cleanup = 'separate owned-root cleanup'; publicCasesReviewed = 20 }
    $paths
}

function Write-Year2021SimFile {
    param([string]$Path, [AllowEmptyString()][string]$Content, [string]$Purpose = 'artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-Year2021SimManifest file $Path created @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-Year2021SimDecoy {
    param([string]$Path, [string]$Role)
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-Year2021SimManifest executable-decoy $Path copied-signed-cmd @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function Invoke-Year2021SimDecoy {
    param([string]$FilePath, [string]$ReportedCommandLine, [string]$ReportedParent = 'beacon.exe')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'YEAR-2021-CANARY')
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-Year2021SimManifest process $FilePath executed-signed-decoy @{ reportedParent = $ReportedParent; reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); reportedOnly = $true }
}

function Invoke-Year2021SimLoopback {
    param([int]$Port, [string]$ReportedTarget, [string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {
    } finally {
        $client.Dispose()
    }
    Add-Year2021SimManifest network "127.0.0.1:$Port" loopback-only @{ role = $Role; reportedTarget = $ReportedTarget; remote = $false; proxy = $false; bytesTransferred = 0 }
}

function Add-Year2021SimTimeline {
    param([double]$OffsetHours, [string]$Phase, [string]$Event, [hashtable]$Details = @{})
    $paths = Get-Year2021SimPaths
    [ordered]@{
        timestampUtc = $script:Year2021SimAnchor.AddHours($OffsetHours).ToString('o')
        offsetHours = $OffsetHours
        aggregateComposite = $true
        phase = $Phase
        event = $Event
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
}

function Write-Year2021SimSummary {
    param($Paths)
    $content = @"
YearReview2021Sim complete.
Source: $script:Year2021SimUrl
This is a synthetic aggregate composite of trends from 20 public cases, not one observed intrusion.
Root: $($Paths.Root)
Artifacts remain; cleanup is separate.
No phishing, exploit, malware, persistence, account, RMM, security-control change, process injection, credential/LSASS/NTDS/hive access, directory/share query, port scan, lateral movement, remote action, collection, exfiltration, cryptomining, or ransomware encryption occurred.
"@
    Write-Year2021SimFile $Paths.Summary $content 'operator summary'
}
