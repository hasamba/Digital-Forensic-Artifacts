Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ElpacoScenarioId = '015-Another_Confluence_ELPACO_Team_Ransomware'
$script:ElpacoSourceUrl = 'https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/'
$script:ElpacoAnchor = (Get-Date).ToUniversalTime()
$script:ElpacoLaunchCounter = 0

function Get-ElpacoPaths {
    $root = Join-Path $env:PUBLIC 'ElpacoConfluenceSim'
    [ordered]@{
        Root          = $root
        Evidence      = Join-Path $root 'evidence'
        Confluence    = Join-Path $root 'Program Files\Atlassian\Confluence'
        Temp          = Join-Path $root 'Windows\ServiceProfiles\NetworkService\AppData\Local\Temp'
        AnyDesk       = Join-Path $root 'Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk'
        Desktop       = Join-Path $root 'Users\noname\Desktop'
        Tools         = Join-Path $root 'Users\noname\Desktop\Attacker\share'
        Share         = Join-Path $root 'share'
        Hosts         = Join-Path $root 'synthetic-hosts'
        RansomTemp    = Join-Path $root 'Users\noname\AppData\Local\Temp\5\7ZipSfx.000'
        RansomHome    = Join-Path $root 'Users\noname\AppData\Local\F6A3737E-E3B0-8956-8261-0121C68105F3'
        Impact        = Join-Path $root 'impact-canary'
        Manifest      = Join-Path $root 'artifact-manifest.jsonl'
        Timeline      = Join-Path $root 'evidence\sixty-two-hour-timeline.jsonl'
        Summary       = Join-Path $root 'operator-summary.txt'
        Owner         = Join-Path $root '.ElpacoConfluenceSim.owner'
    }
}

function Get-ElpacoTimeline {
    $initial = $script:ElpacoAnchor.AddHours(-62)
    [ordered]@{
        Initial = $initial
        Meterpreter = $initial.AddMinutes(20)
        AnyDesk = $initial.AddMinutes(23)
        Day2 = $initial.AddHours(24)
        Day3 = $initial.AddHours(48)
        Credential = $initial.AddHours(49)
        Lateral = $initial.AddHours(50)
        Impact = $initial.AddHours(62)
    }
}

function Assert-ElpacoLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'ElpacoConfluenceSim only runs on Windows.' }
    if (-not $LabConfirmed) {
        throw 'Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) { throw 'Domain-controller refusal: this scenario must not run on a domain controller.' }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { throw 'Domain-controller refusal: the NTDS service is present.' }
}

function Add-ElpacoManifestEntry {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Action, [hashtable]$Details = @{})
    $paths = Get-ElpacoPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:ElpacoScenarioId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-ElpacoEnvironment {
    $paths = Get-ElpacoPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:ElpacoScenarioId) {
            throw "Refusing to reuse an unowned scenario root: $($paths.Root)"
        }
    }
    foreach ($directory in @($paths.Root, $paths.Evidence, $paths.Confluence, $paths.Temp, $paths.AnyDesk, $paths.Desktop, $paths.Tools, $paths.Share, $paths.Hosts, $paths.RansomTemp, $paths.RansomHome, $paths.Impact)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:ElpacoScenarioId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-ElpacoManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Cleanup-ElpacoSim.ps1 validates this ownership marker.' }
    return $paths
}

function Set-ElpacoArtifactTime {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$Timestamp)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(1)
    $item.LastAccessTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(2)
}

function Write-ElpacoEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [string]$Purpose = 'forensic artifact',
        [datetime]$Timestamp
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    if ($PSBoundParameters.ContainsKey('Timestamp')) { Set-ElpacoArtifactTime -Path $Path -Timestamp $Timestamp }
    Add-ElpacoManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-ElpacoBinaryDecoy {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Role, [string]$ReportedSha256 = 'NOT-PUBLISHED')
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Path -Force
    Add-ElpacoManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; reportedSha256 = $ReportedSha256; hashMatchExpected = $false }
}

function Invoke-ElpacoDecoyProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$ReportedCommandLine)
    $safeEcho = $ReportedCommandLine.Replace('^', '^^').Replace('&', '^&').Replace('|', '^|').Replace('<', '^<').Replace('>', '^>').Replace('(', '^(').Replace(')', '^)')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'ELPACO-CANARY', $safeEcho)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    $script:ElpacoLaunchCounter++
    Add-ElpacoManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{ sequence = $script:ElpacoLaunchCounter; reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); metacharactersEscaped = $true }
}

function Invoke-ElpacoLoopbackPort {
    param([ValidateRange(1, 65535)][int]$Port, [Parameter(Mandatory)][string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-ElpacoManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; proxyUsed = $false; remoteSystemsContacted = $false }
}

function Add-ElpacoTimelineEvent {
    param([Parameter(Mandatory)][datetime]$Timestamp, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Event, [hashtable]$Details = @{})
    $paths = Get-ElpacoPaths
    [ordered]@{ timestampUtc = $Timestamp.ToUniversalTime().ToString('o'); phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
}

function Write-ElpacoSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
ElpacoConfluenceSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:ElpacoSourceUrl
Scenario root: $($Paths.Root)
Manifest: $($Paths.Manifest)
Timeline: $($Paths.Timeline)

Artifacts remain for investigation. Run Cleanup-ElpacoSim.ps1 separately.
No live malware, external IOC, real account, credential source, LSASS/NTDS data, domain
controller, remote host, service, registry policy, firewall, VM, event log, or user file was touched.
"@
    Write-ElpacoEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
