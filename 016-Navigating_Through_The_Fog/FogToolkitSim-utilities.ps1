Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FogScenarioId = '016-Navigating_Through_The_Fog'
$script:FogSourceUrl = 'https://thedfirreport.com/2025/04/28/navigating-through-the-fog/'
$script:FogAnchor = (Get-Date).ToUniversalTime()

function Get-FogPaths {
    $root = Join-Path $env:PUBLIC 'FogOpenDirectorySim'
    [ordered]@{
        Root = $root
        OpenDirectory = Join-Path $root '194.48.154.79-open-directory'
        Evidence = Join-Path $root 'evidence'
        WindowsHost = Join-Path $root 'windows-host-canary'
        SyntheticNetwork = Join-Path $root 'synthetic-network'
        Credentials = Join-Path $root 'generated-credentials'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\capability-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.FogOpenDirectorySim.owner'
    }
}

function Assert-FogLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'FogOpenDirectorySim only runs on Windows.' }
    if (-not $LabConfirmed) {
        throw 'Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab.'
    }
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4, 5) { throw 'Domain-controller refusal: this scenario must not run on a domain controller.' }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { throw 'Domain-controller refusal: the NTDS service is present.' }
}

function Add-FogManifestEntry {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Action, [hashtable]$Details = @{})
    $paths = Get-FogPaths
    [ordered]@{ timestampUtc = (Get-Date).ToUniversalTime().ToString('o'); scenarioId = $script:FogScenarioId; type = $Type; path = $Path; action = $Action; details = $Details } |
        ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-FogEnvironment {
    $paths = Get-FogPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:FogScenarioId) {
            throw "Refusing to reuse an unowned scenario root: $($paths.Root)"
        }
    }
    foreach ($directory in @($paths.Root, $paths.OpenDirectory, $paths.Evidence, $paths.WindowsHost, $paths.SyntheticNetwork, $paths.Credentials)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:FogScenarioId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-FogManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Separate, ownership-checked Cleanup-FogToolkitSim.ps1' }
    return $paths
}

function Write-FogEvidenceFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content, [string]$Purpose = 'forensic artifact', [datetime]$Timestamp = $script:FogAnchor)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(1)
    Add-FogManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-FogBinaryDecoy {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Role)
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-FogManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; liveTool = $false }
}

function Invoke-FogDecoyProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$ReportedCommandLine)
    $safe = $ReportedCommandLine.Replace('^', '^^').Replace('&', '^&').Replace('|', '^|').Replace('<', '^<').Replace('>', '^>').Replace('(', '^(').Replace(')', '^)')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'FOG-CANARY', $safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-FogManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{ reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); metacharactersEscaped = $true }
}

function Invoke-FogLoopbackPort {
    param([ValidateRange(1, 65535)][int]$Port, [Parameter(Mandatory)][string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try { $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null); $null = $async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-FogManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; remoteSystemsContacted = $false; proxyUsed = $false }
}

function Add-FogTimelineEvent {
    param([Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Event, [hashtable]$Details = @{}, [datetime]$Timestamp = $script:FogAnchor)
    $paths = Get-FogPaths
    [ordered]@{ timestampUtc = $Timestamp.ToUniversalTime().ToString('o'); phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
}

function Write-FogSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    Write-FogEvidenceFile -Path $Paths.Summary -Content @"
FogOpenDirectorySim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:FogSourceUrl
Root: $($Paths.Root)
Manifest: $($Paths.Manifest)
Artifacts remain until Cleanup-FogToolkitSim.ps1 is run separately.

No live tool, report infrastructure, VPN, account, DPAPI/credential source, AD CS,
Kerberos, domain controller, remote share, proxy, reverse shell, or ransomware was accessed.
"@ -Purpose 'operator handoff summary'
}
