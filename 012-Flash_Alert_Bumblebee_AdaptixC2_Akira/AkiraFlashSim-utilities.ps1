Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AkiraScenarioId = '012-Flash_Alert_Bumblebee_AdaptixC2_Akira'
$script:AkiraSourceUrl = 'https://thedfirreport.com/2025/08/05/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/'
$script:AkiraTimelineAnchor = (Get-Date).ToUniversalTime()
$script:AkiraLaunchCounter = 0

function Get-AkiraFlashPaths {
    $root = Join-Path $env:PUBLIC 'AkiraFlashSim'
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    [ordered]@{
        Root           = $root
        Evidence       = Join-Path $root 'evidence'
        Tools          = Join-Path $root 'tools'
        Payloads       = Join-Path $root 'payloads'
        SyntheticAD    = Join-Path $root 'directory-canary'
        SyntheticDC    = Join-Path $root 'DC-canary'
        Veeam          = Join-Path $root 'Veeam-canary'
        Staging        = Join-Path $root 'ProgramData-canary'
        CanaryData     = Join-Path $root 'enterprise-data-canary'
        Downloads      = $downloads
        Installer      = Join-Path $downloads 'ManageEngine-OpManager.msi'
        InstallerOwner = Join-Path $downloads 'ManageEngine-OpManager.msi.AkiraFlashSim.owner'
        Manifest       = Join-Path $root 'artifact-manifest.jsonl'
        Timeline       = Join-Path $root 'evidence\attack-timeline.jsonl'
        Summary        = Join-Path $root 'operator-summary.txt'
    }
}

function Get-AkiraFlashTimeline {
    $initial = $script:AkiraTimelineAnchor.AddHours(-92)
    [ordered]@{
        InitialAccess = $initial
        Adaptix       = $initial.AddHours(5)
        FirstWave     = $initial.AddHours(43).AddMinutes(50)
        SecondWave    = $initial.AddHours(91).AddMinutes(50)
    }
}

function Assert-AkiraFlashLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'AkiraFlashSim only runs on Windows.' }
    if (-not $LabConfirmed -or $env:DFIR_LAB_CONFIRMATION -ne 'I_UNDERSTAND_THIS_IS_A_LAB') {
        throw 'Lab gate refused execution. Set DFIR_LAB_CONFIRMATION=I_UNDERSTAND_THIS_IS_A_LAB and pass -LabConfirmed.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) { throw 'Domain-controller refusal: this scenario must not run on a domain controller.' }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { throw 'Domain-controller refusal: the NTDS service is present.' }
}

function Add-AkiraFlashManifestEntry {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Details = @{}
    )
    $paths = Get-AkiraFlashPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:AkiraScenarioId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-AkiraFlashEnvironment {
    $paths = Get-AkiraFlashPaths
    foreach ($directory in @(
        $paths.Root, $paths.Evidence, $paths.Tools, $paths.Payloads, $paths.SyntheticAD,
        $paths.SyntheticDC, $paths.Veeam, $paths.Staging, $paths.CanaryData, $paths.Downloads
    )) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    if ((Test-Path -LiteralPath $paths.Installer) -and -not (Test-Path -LiteralPath $paths.InstallerOwner)) {
        throw "Refusing to overwrite an existing installer: $($paths.Installer)"
    }
    Add-AkiraFlashManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Cleanup-AkiraFlashSim.ps1 removes only fixed scenario-owned targets.' }
    return $paths
}

function Set-AkiraFlashArtifactTime {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$Timestamp)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(2)
    $item.LastAccessTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(3)
}

function Write-AkiraFlashEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [string]$Purpose = 'forensic artifact',
        [datetime]$Timestamp
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    if ($PSBoundParameters.ContainsKey('Timestamp')) { Set-AkiraFlashArtifactTime -Path $Path -Timestamp $Timestamp }
    Add-AkiraFlashManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-AkiraFlashBinaryDecoy {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Role,
        [string]$ReportedSha256 = 'NOT-PUBLISHED-IN-FLASH-ALERT'
    )
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Path -Force
    Add-AkiraFlashManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{
        role = $Role
        actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        reportedSha256 = $ReportedSha256
        hashMatchExpected = $false
    }
}

function Invoke-AkiraFlashDecoyProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$ReportedCommandLine)
    $arguments = @('/d', '/c', 'echo', 'AKIRA-FLASH-CANARY', $ReportedCommandLine)
    $paths = Get-AkiraFlashPaths
    $script:AkiraLaunchCounter++
    $shortcutPath = Join-Path $paths.Evidence ('launch-{0:d3}-{1}.lnk' -f $script:AkiraLaunchCounter, ([IO.Path]::GetFileName($FilePath)))
    $launchMethod = 'direct-fallback'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $FilePath
        $shortcut.Arguments = ($arguments -join ' ')
        $shortcut.WorkingDirectory = Split-Path -Parent $FilePath
        $shortcut.Description = "AkiraFlashSim inert launch: $ReportedCommandLine"
        $shortcut.Save()
        Start-Process -FilePath $shortcutPath | Out-Null
        Start-Sleep -Seconds 1
        $launchMethod = 'shell-shortcut-explorer-brokered'
        Add-AkiraFlashManifestEntry -Type 'file' -Path $shortcutPath -Action 'created' -Details @{ purpose = 'ShellExecute process-ancestry artifact'; target = $FilePath }
    } catch {
        $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
        $null = $process.ExitCode
    }
    Add-AkiraFlashManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{ reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); launchMethod = $launchMethod }
}

function Invoke-AkiraFlashLoopbackEndpoint {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [string]$Path = '/'
    )
    $paths = Get-AkiraFlashPaths
    $cleanHost = $HostName.Replace('[.]', '.')
    $parsedAddress = $null
    $routeArguments = if ([Net.IPAddress]::TryParse($cleanHost, [ref]$parsedAddress)) {
        @('--connect-to', "${cleanHost}:${Port}:127.0.0.1:${Port}")
    } else {
        @('--resolve', "${cleanHost}:${Port}:127.0.0.1")
    }
    $arguments = @('--noproxy', '*') + $routeArguments + @('--connect-timeout', '1', '--max-time', '2', '--silent', '--show-error', '--insecure', '--output', 'NUL', "https://${cleanHost}:${Port}${Path}")
    $commandLine = 'curl.exe ' + ($arguments -join ' ')
    Add-Content -LiteralPath (Join-Path $paths.Evidence 'loopback-network-command-lines.log') -Value $commandLine -Encoding UTF8
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try { Start-Process -FilePath 'curl.exe' -ArgumentList $arguments -Wait -NoNewWindow } catch {}
    }
    Add-AkiraFlashManifestEntry -Type 'network-telemetry' -Path "${cleanHost}:${Port}" -Action 'loopback-only-attempt' -Details @{ forcedAddress = '127.0.0.1'; proxyDisabled = $true; commandLine = $commandLine }
}

function Invoke-AkiraFlashLoopbackPort {
    param([ValidateRange(1, 65535)][int]$Port, [Parameter(Mandatory)][string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-AkiraFlashManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; remoteSystemsContacted = $false }
}

function Add-AkiraFlashTimelineEvent {
    param([Parameter(Mandatory)][datetime]$Timestamp, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Event, [hashtable]$Details = @{})
    $paths = Get-AkiraFlashPaths
    [ordered]@{ timestampUtc = $Timestamp.ToUniversalTime().ToString('o'); phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
}

function Write-AkiraFlashSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
AkiraFlashSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:AkiraSourceUrl
Scenario root: $($Paths.Root)
Manifest: $($Paths.Manifest)
Timeline: $($Paths.Timeline)

Artifacts intentionally remain for investigation. Use Cleanup-AkiraFlashSim.ps1 separately.
No malware, real IOC, credential store, LSASS/NTDS data, Veeam database, remote host,
security control, shadow copy, backup, or non-canary document was accessed or modified.
"@
    Write-AkiraFlashEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
