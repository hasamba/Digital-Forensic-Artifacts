Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BengalScenarioId = '010-BengalSEO_MayaBot_SEO_Poisoning'
$script:BengalSourceUrl = 'https://thedfirreport.com/2026/08/24/bengalseo-part-1-anatomy-of-the-operation/'

function Get-BengalPaths {
    $root = Join-Path $env:PUBLIC 'BengalSEOSim'
    [ordered]@{
        Root       = $root
        Lure       = Join-Path $root 'lure'
        Tds        = Join-Path $root 'tds'
        Payload    = Join-Path $root 'payload'
        MayaCache  = Join-Path $env:LOCALAPPDATA 'MayaCache'
        Evidence   = Join-Path $root 'evidence'
        Downloads  = Join-Path $env:USERPROFILE 'Downloads'
        Manifest   = Join-Path $root 'artifact-manifest.jsonl'
        Summary    = Join-Path $root 'operator-summary.txt'
    }
}

function Assert-BengalLabSafety {
    param([switch]$LabConfirmed)

    if ($env:OS -ne 'Windows_NT') {
        throw 'BengalSEOSim only runs on Windows.'
    }
    if (-not $LabConfirmed) {
        throw "Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab."
    }

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) {
        throw 'Domain-controller refusal: this scenario must not run on a backup or primary domain controller.'
    }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        throw 'Domain-controller refusal: the NTDS service is present.'
    }
}

function Add-BengalManifestEntry {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Details = @{}
    )

    $paths = Get-BengalPaths
    $entry = [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId   = $script:BengalScenarioId
        type         = $Type
        path         = $Path
        action       = $Action
        details      = $Details
    }
    $entry | ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-BengalEnvironment {
    $paths = Get-BengalPaths
    foreach ($directory in @($paths.Root, $paths.Lure, $paths.Tds, $paths.Payload, $paths.MayaCache, $paths.Evidence, $paths.Downloads)) {
        if (-not (Test-Path -LiteralPath $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest)) {
        New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null
    }
    Add-BengalManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Remove only the scenario-owned roots listed by Cleanup-BengalSEOSim.ps1.' }
    return $paths
}

function Write-BengalEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content,
        [string]$Purpose = 'forensic artifact'
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-BengalManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function ConvertTo-BengalTrackingToken {
    param([Parameter(Mandatory)][string]$Value)
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Invoke-BengalLoopbackRequest {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [string]$Path = '/'
    )

    $paths = Get-BengalPaths
    $safeHost = $HostName.Replace('[.]', '.')
    $url = "https://${safeHost}:${Port}${Path}"
    $resolve = "${safeHost}:${Port}:127.0.0.1"
    $arguments = @('--noproxy', '*', '--resolve', $resolve, '--connect-timeout', '1', '--max-time', '2', '--silent', '--show-error', '--insecure', '--output', 'NUL', $url)
    $commandRecord = "curl.exe " + ($arguments -join ' ')

    Add-Content -LiteralPath (Join-Path $paths.Evidence 'loopback-network-command-lines.log') -Value $commandRecord -Encoding UTF8
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try {
            Start-Process -FilePath 'curl.exe' -ArgumentList $arguments -Wait -NoNewWindow -ErrorAction Stop
        } catch {
            # A refused loopback connection is expected when no listener exists.
        }
    }
    Add-BengalManifestEntry -Type 'network-telemetry' -Path $url -Action 'loopback-only-attempt' -Details @{
        forcedAddress = '127.0.0.1'
        proxyDisabled = $true
        commandLine   = $commandRecord
    }
}

function Write-BengalPhaseMarker {
    param([Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Description)
    $paths = Get-BengalPaths
    $line = "{0}`t{1}`t{2}" -f (Get-Date).ToUniversalTime().ToString('o'), $Phase, $Description
    Add-Content -LiteralPath (Join-Path $paths.Evidence 'phase-timeline.tsv') -Value $line -Encoding UTF8
    Add-BengalManifestEntry -Type 'phase' -Path $Phase -Action 'completed' -Details @{ description = $Description }
}

function Write-BengalSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
BengalSEOSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:BengalSourceUrl
Scenario root: $($Paths.Root)
Runtime manifest: $($Paths.Manifest)

Artifacts intentionally remain in place for forensic acquisition.
Run Cleanup-BengalSEOSim.ps1 separately after the investigation.
All IOC-bearing requests used curl --resolve to force 127.0.0.1 and --noproxy '*'.
"@
    Write-BengalEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
