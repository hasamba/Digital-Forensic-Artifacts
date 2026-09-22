Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RansomHubScenarioId = '014-Hide_Your_RDP_RansomHub_Deployment'
$script:RansomHubSourceUrl = 'https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/'
$script:RansomHubAnchor = (Get-Date).ToUniversalTime()
$script:RansomHubLaunchCounter = 0

function Get-RansomHubPaths {
    $root = Join-Path $env:PUBLIC 'RansomHubRdpSim'
    $desktopRoot = Join-Path ([Environment]::GetFolderPath('Desktop')) 'RansomHubSim'
    [ordered]@{
        Root          = $root
        Evidence      = Join-Path $root 'evidence'
        Tools         = Join-Path $root 'tools'
        DesktopRoot   = $desktopRoot
        DesktopOwner  = Join-Path $desktopRoot '.RansomHubRdpSim.owner'
        SyntheticNet  = Join-Path $root 'network-canary'
        SyntheticAD   = Join-Path $root 'directory-canary'
        Rmm           = Join-Path $root 'RMM-canary'
        VeeamStaging  = Join-Path $root 'ProgramData\Veeam'
        Collection    = Join-Path $root 'collection-canary'
        Impact        = Join-Path $root 'impact-canary'
        Manifest      = Join-Path $root 'artifact-manifest.jsonl'
        Timeline      = Join-Path $root 'evidence\six-day-timeline.jsonl'
        Summary       = Join-Path $root 'operator-summary.txt'
    }
}

function Get-RansomHubTimeline {
    $initial = $script:RansomHubAnchor.AddHours(-118)
    [ordered]@{
        SprayStart = $initial.AddHours(-8)
        SprayEnd   = $initial.AddHours(-4)
        Day1       = $initial
        Day2       = $initial.AddHours(24)
        Day3       = $initial.AddHours(48)
        Day5       = $initial.AddHours(96)
        Day6       = $initial.AddHours(118)
    }
}

function Assert-RansomHubLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'RansomHubRdpSim only runs on Windows.' }
    if (-not $LabConfirmed) {
        throw 'Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) { throw 'Domain-controller refusal: this scenario must not run on a domain controller.' }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { throw 'Domain-controller refusal: the NTDS service is present.' }
}

function Add-RansomHubManifestEntry {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Action, [hashtable]$Details = @{})
    $paths = Get-RansomHubPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:RansomHubScenarioId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
    Write-Host ("  [{0}] {1}: {2}" -f $Type, $Action, $Path) -ForegroundColor DarkGray
}

function Initialize-RansomHubEnvironment {
    $paths = Get-RansomHubPaths
    foreach ($directory in @($paths.Root, $paths.Evidence, $paths.Tools, $paths.SyntheticNet, $paths.SyntheticAD, $paths.Rmm, $paths.VeeamStaging, $paths.Collection, $paths.Impact)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    if (Test-Path -LiteralPath $paths.DesktopRoot) {
        $owned = (Test-Path -LiteralPath $paths.DesktopOwner) -and ((Get-Content -LiteralPath $paths.DesktopOwner -Raw).Trim() -eq $script:RansomHubScenarioId)
        if (-not $owned) { throw "Refusing to reuse existing non-scenario Desktop folder: $($paths.DesktopRoot)" }
    } else {
        New-Item -Path $paths.DesktopRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $paths.DesktopOwner -Value $script:RansomHubScenarioId -Encoding ASCII
    }
    Add-RansomHubManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Cleanup-RansomHubSim.ps1 uses fixed roots and ownership markers.' }
    Add-RansomHubManifestEntry -Type 'directory' -Path $paths.DesktopRoot -Action 'created-or-reused' -Details @{ ownerMarker = $paths.DesktopOwner }
    return $paths
}

function Set-RansomHubArtifactTime {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$Timestamp)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(2)
    $item.LastAccessTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(3)
}

function Write-RansomHubEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [string]$Purpose = 'forensic artifact',
        [datetime]$Timestamp
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    if ($PSBoundParameters.ContainsKey('Timestamp')) { Set-RansomHubArtifactTime -Path $Path -Timestamp $Timestamp }
    Add-RansomHubManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-RansomHubBinaryDecoy {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Role, [string]$ReportedSha256 = 'NOT-PUBLISHED')
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Path -Force
    Add-RansomHubManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; reportedSha256 = $ReportedSha256; hashMatchExpected = $false }
}

function Invoke-RansomHubDecoyProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$ReportedCommandLine)
    $safeEcho = $ReportedCommandLine.Replace('^', '^^').Replace('&', '^&').Replace('|', '^|').Replace('<', '^<').Replace('>', '^>').Replace('(', '^(').Replace(')', '^)')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'RANSOMHUB-CANARY', $safeEcho)
    $paths = Get-RansomHubPaths
    $script:RansomHubLaunchCounter++
    $shortcutPath = Join-Path $paths.Evidence ('launch-{0:d3}-{1}.lnk' -f $script:RansomHubLaunchCounter, ([IO.Path]::GetFileName($FilePath)))
    $launchMethod = 'direct-fallback'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $FilePath
        $shortcut.Arguments = ($arguments -join ' ')
        $shortcut.WorkingDirectory = Split-Path -Parent $FilePath
        $shortcut.Description = "RansomHubRdpSim inert launch: $ReportedCommandLine"
        $shortcut.Save()
        Start-Process -FilePath $shortcutPath | Out-Null
        Start-Sleep -Seconds 1
        $launchMethod = 'shell-shortcut-explorer-brokered'
        Add-RansomHubManifestEntry -Type 'file' -Path $shortcutPath -Action 'created' -Details @{ purpose = 'ShellExecute process-ancestry artifact'; target = $FilePath }
    } catch {
        $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
        $null = $process.ExitCode
    }
    Add-RansomHubManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{ reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); cmdMetacharactersEscaped = $true; launchMethod = $launchMethod }
}

function Remove-RansomHubGeneratedFile {
    param([Parameter(Mandatory)][string]$Path, [int]$MaxAttempts = 20, [int]$DelayMilliseconds = 500, [switch]$WarnOnFailure)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            Write-Host "  [file] deleted: $Path" -ForegroundColor DarkGray
            return
        } catch {
            if ($attempt -eq $MaxAttempts) {
                if ($WarnOnFailure) {
                    Write-Warning "Could not delete $Path after $MaxAttempts attempts (likely still held by antivirus real-time scanning of the renamed decoy binary). Leaving it for Cleanup-RansomHubSim.ps1 to remove later."
                    return
                }
                throw
            }
            Start-Sleep -Milliseconds ([Math]::Min($DelayMilliseconds * $attempt, 2000))
        }
    }
}

function Invoke-RansomHubLoopbackPort {
    param([ValidateRange(1, 65535)][int]$Port, [Parameter(Mandatory)][string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-RansomHubManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; remoteSystemsContacted = $false }
}

function Add-RansomHubTimelineEvent {
    param([Parameter(Mandatory)][datetime]$Timestamp, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Event, [hashtable]$Details = @{})
    $paths = Get-RansomHubPaths
    [ordered]@{ timestampUtc = $Timestamp.ToUniversalTime().ToString('o'); phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
    Write-Host ("  [timeline] {0}: {1}" -f $Phase, $Event) -ForegroundColor Cyan
}

function Write-RansomHubSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
RansomHubRdpSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:RansomHubSourceUrl
Scenario root: $($Paths.Root)
Manifest: $($Paths.Manifest)
Timeline: $($Paths.Timeline)

Artifacts remain for investigation. Use Cleanup-RansomHubSim.ps1 separately.
No real password spray, credential source, LSASS, domain, RMM service, remote host,
SFTP server, VM, shadow copy, event log, symlink policy, or user file was modified.
"@
    Write-RansomHubEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
