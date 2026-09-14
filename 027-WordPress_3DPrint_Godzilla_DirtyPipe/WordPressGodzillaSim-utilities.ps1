#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WordPressGodzillaId = '027-WordPress_3DPrint_Godzilla_DirtyPipe'
$script:WordPressGodzillaUrl = 'https://thedfirreport.com/2024/03/04/threat-brief-wordpress-exploit-leads-to-godzilla-web-shell-discovery-new-cve/'
$script:WordPressGodzillaAnchor = (Get-Date).ToUniversalTime().AddHours(-6)

function Get-WordPressGodzillaPaths {
    $root = Join-Path $env:PUBLIC 'WordPressGodzillaSim'
    $linux = Join-Path $root 'linux-root'
    [ordered]@{
        Root = $root
        Linux = $linux
        WebRoot = Join-Path $linux 'var\www\html'
        Plugin = Join-Path $linux 'var\www\html\wp-content\plugins\3dprint-lite'
        Upload = Join-Path $linux 'var\www\html\wp-content\uploads\p3d'
        ApacheLog = Join-Path $linux 'var\log\apache2\access.log'
        Evidence = Join-Path $root 'evidence'
        Process = Join-Path $root 'process-telemetry'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.WordPressGodzillaSim.owner'
    }
}

function Assert-WordPressGodzillaSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4, 5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-WordPressGodzillaManifest {
    param([string]$Type, [string]$Path, [string]$Action, [hashtable]$Details = @{})
    $paths = Get-WordPressGodzillaPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:WordPressGodzillaId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 9 -Compress | Add-Content $paths.Manifest -Encoding UTF8
}

function Initialize-WordPressGodzillaEnvironment {
    $paths = Get-WordPressGodzillaPaths
    if (Test-Path $paths.Root) {
        if (-not (Test-Path $paths.Owner) -or (Get-Content $paths.Owner -Raw).Trim() -ne $script:WordPressGodzillaId) {
            throw 'Refusing unowned root'
        }
    }
    foreach ($directory in @($paths.Root, $paths.Linux, $paths.WebRoot, $paths.Plugin, $paths.Upload, $paths.Evidence, $paths.Process, (Split-Path -Parent $paths.ApacheLog))) {
        New-Item $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content $paths.Owner $script:WordPressGodzillaId -Encoding ASCII
    if (-not (Test-Path $paths.Manifest)) { New-Item $paths.Manifest -ItemType File -Force | Out-Null }
    Add-WordPressGodzillaManifest directory $paths.Root created-or-reused @{ cleanup = 'separate owned-root cleanup' }
    return $paths
}

function Write-WordPressGodzillaFile {
    param([string]$Path, [AllowEmptyString()][string]$Content, [string]$Purpose = 'artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path $directory)) { New-Item $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-WordPressGodzillaManifest file $Path created @{ purpose = $Purpose; sha256 = (Get-FileHash $Path -Algorithm SHA256).Hash }
}

function New-WordPressGodzillaDecoy {
    param([string]$Path, [string]$Role)
    New-Item (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') $Path -Force
    Add-WordPressGodzillaManifest executable-decoy $Path copied-signed-cmd @{ role = $Role; actualSha256 = (Get-FileHash $Path -Algorithm SHA256).Hash; reportedMalware = $false }
}

function Invoke-WordPressGodzillaDecoy {
    param([string]$FilePath, [string]$ReportedCommandLine)
    $escaped = $ReportedCommandLine.Replace('^', '^^').Replace('&', '^&').Replace('|', '^|').Replace('<', '^<').Replace('>', '^>').Replace('(', '^(').Replace(')', '^)')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'WORDPRESS-GODZILLA-CANARY', $escaped)
    $process = Start-Process $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-WordPressGodzillaManifest process $FilePath executed-signed-decoy @{ reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); escaped = $true }
}

function Invoke-WordPressGodzillaLoopback {
    param([int]$Port, [string]$ReportedTarget, [string]$Protocol = 'tcp')
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {
    } finally {
        $client.Dispose()
    }
    Add-WordPressGodzillaManifest network "127.0.0.1:$Port" loopback-only @{ reportedTarget = $ReportedTarget; protocol = $Protocol; remote = $false; proxy = $false; bytesTransferred = 0 }
}

function Add-WordPressGodzillaTimeline {
    param([int]$OffsetMinutes, [string]$Phase, [string]$Event, [hashtable]$Details = @{})
    $paths = Get-WordPressGodzillaPaths
    [ordered]@{
        timestampUtc = $script:WordPressGodzillaAnchor.AddMinutes($OffsetMinutes).ToString('o')
        offsetMinutes = $OffsetMinutes
        phase = $Phase
        event = $Event
        details = $Details
    } | ConvertTo-Json -Depth 9 -Compress | Add-Content $paths.Timeline -Encoding UTF8
}

function Write-WordPressGodzillaSummary {
    param($Paths)
    $content = @"
WordPressGodzillaSim complete.
Source: $script:WordPressGodzillaUrl
Simulated dwell: approximately six hours.
Root: $($Paths.Root)
Artifacts remain for investigation; cleanup is separate.
No PHP payload was executed, Linux command was run, credential file was read, privilege escalation was attempted, remote IP was contacted, or artifact was deleted.
"@
    Write-WordPressGodzillaFile $Paths.Summary $content 'operator summary'
}
