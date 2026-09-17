Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:InterlockScenarioId = '013-KongTuke_FileFix_Interlock_RAT_PHP'
$script:InterlockSourceUrl = 'https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/'
$script:InterlockAnchor = (Get-Date).ToUniversalTime()
$script:InterlockLaunchCounter = 0
$script:InterlockRunValue = 'InterlockRatCanary'

function Get-InterlockPaths {
    $root = Join-Path $env:PUBLIC 'InterlockFileFixSim'
    $phpRoot = Join-Path $env:APPDATA 'php'
    [ordered]@{
        Root         = $root
        Evidence     = Join-Path $root 'evidence'
        Web          = Join-Path $root 'compromised-web-canary'
        Payloads     = Join-Path $root 'payloads'
        C2Commands   = Join-Path $root 'c2-command-canaries'
        Discovery    = Join-Path $root 'discovery'
        PhpRoot      = $phpRoot
        PhpOwner     = Join-Path $phpRoot '.InterlockFileFixSim.owner'
        PhpExe       = Join-Path $phpRoot 'php.exe'
        Config       = Join-Path $phpRoot 'wefs.cfg'
        AltConfig    = Join-Path $phpRoot 'wefs-alt.cfg'
        Manifest     = Join-Path $root 'artifact-manifest.jsonl'
        Timeline     = Join-Path $root 'evidence\attack-timeline.jsonl'
        Summary      = Join-Path $root 'operator-summary.txt'
        RunKey       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    }
}

function Get-InterlockTimeline {
    $initial = $script:InterlockAnchor.AddHours(-2)
    [ordered]@{
        WebInject  = $initial
        FileFix    = $initial.AddMinutes(4)
        PhpRat     = $initial.AddMinutes(8)
        Discovery  = $initial.AddMinutes(10)
        HandsOn    = $initial.AddMinutes(28)
        Persistence = $initial.AddMinutes(36)
    }
}

function Get-InterlockExpectedRunCommand {
    $paths = Get-InterlockPaths
    return "`"$($paths.PhpExe)`" /d /c `"echo INTERLOCK-RUN-CANARY`" --config `"$($paths.Config)`""
}

function Assert-InterlockLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'InterlockFileFixSim only runs on Windows.' }
    if (-not $LabConfirmed) {
        throw 'Lab gate refused execution. Pass -LabConfirmed to confirm this is a dedicated lab.'
    }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -in 4, 5) { throw 'Domain-controller refusal: this scenario must not run on a domain controller.' }
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) { throw 'Domain-controller refusal: the NTDS service is present.' }
}

function Add-InterlockManifestEntry {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Details = @{}
    )
    $paths = Get-InterlockPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:InterlockScenarioId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-InterlockEnvironment {
    $paths = Get-InterlockPaths
    $phpWasOwned = if (Test-Path -LiteralPath $paths.PhpOwner) {
        (Get-Content -LiteralPath $paths.PhpOwner -Raw).Trim() -eq $script:InterlockScenarioId
    } else { $false }
    $existingRun = $null
    if (Test-Path -LiteralPath $paths.RunKey) {
        $runProperties = Get-ItemProperty -LiteralPath $paths.RunKey -ErrorAction Stop
        $runProperty = $runProperties.PSObject.Properties[$script:InterlockRunValue]
        if ($null -ne $runProperty) {
            $existingRun = $runProperty.Value
        }
    }
    if ($null -ne $existingRun) {
        $expectedRun = Get-InterlockExpectedRunCommand
        if (-not $phpWasOwned -or $existingRun -ne $expectedRun) {
            throw "Refusing to overwrite existing or changed Run value: $script:InterlockRunValue"
        }
    }
    foreach ($directory in @($paths.Root, $paths.Evidence, $paths.Web, $paths.Payloads, $paths.C2Commands, $paths.Discovery)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }

    if (Test-Path -LiteralPath $paths.PhpRoot) {
        if (-not $phpWasOwned) {
            throw "Refusing to reuse an existing non-scenario AppData PHP directory: $($paths.PhpRoot)"
        }
    } else {
        New-Item -Path $paths.PhpRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $paths.PhpOwner -Value $script:InterlockScenarioId -Encoding ASCII
    }

    Add-InterlockManifestEntry -Type 'directory' -Path $paths.Root -Action 'created-or-reused' -Details @{ cleanup = 'Cleanup-InterlockSim.ps1 uses fixed roots and ownership markers.' }
    Add-InterlockManifestEntry -Type 'directory' -Path $paths.PhpRoot -Action 'created-or-reused' -Details @{ ownerMarker = $paths.PhpOwner }
    return $paths
}

function Set-InterlockArtifactTime {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][datetime]$Timestamp)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $item.CreationTimeUtc = $Timestamp.ToUniversalTime()
    $item.LastWriteTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(1)
    $item.LastAccessTimeUtc = $Timestamp.ToUniversalTime().AddMinutes(2)
}

function Write-InterlockEvidenceFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [string]$Purpose = 'forensic artifact',
        [datetime]$Timestamp
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    if ($PSBoundParameters.ContainsKey('Timestamp')) { Set-InterlockArtifactTime -Path $Path -Timestamp $Timestamp }
    Add-InterlockManifestEntry -Type 'file' -Path $Path -Action 'created' -Details @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-InterlockSizedConfigCanary {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][string]$ReportedSha256,
        [Parameter(Mandatory)][datetime]$Timestamp
    )
    $header = "INTERLOCK-PHP-CONFIG-CANARY`nReportedSHA256=$ReportedSha256`nNo executable PHP or attacker commands are present.`n"
    $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
    if ($headerBytes.Length -gt $Size) { throw 'Config canary size is smaller than its safety header.' }
    $bytes = New-Object byte[] $Size
    for ($index = 0; $index -lt $bytes.Length; $index++) { $bytes[$index] = 0x20 }
    [Array]::Copy($headerBytes, $bytes, $headerBytes.Length)
    [IO.File]::WriteAllBytes($Path, $bytes)
    Set-InterlockArtifactTime -Path $Path -Timestamp $Timestamp
    Add-InterlockManifestEntry -Type 'config-canary' -Path $Path -Action 'created-exact-size' -Details @{ size = $Size; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; reportedSha256 = $ReportedSha256; hashMatchExpected = $false }
}

function New-InterlockBinaryDecoy {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Role)
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Path -Force
    Add-InterlockManifestEntry -Type 'executable-decoy' -Path $Path -Action 'copied-signed-cmd' -Details @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; maliciousContent = $false }
}

function Invoke-InterlockDecoyProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$ReportedCommandLine)
    # Keep attacker-shaped commands as evidence, never as actual process arguments.
    $arguments = @('/d', '/v:off', '/c', 'echo', 'INTERLOCK-CANARY')
    $paths = Get-InterlockPaths
    $script:InterlockLaunchCounter++
    $shortcutPath = Join-Path $paths.Evidence ('launch-{0:d3}-{1}.lnk' -f $script:InterlockLaunchCounter, ([IO.Path]::GetFileName($FilePath)))
    $launchMethod = 'direct-fallback'
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $FilePath
        $shortcut.Arguments = ($arguments -join ' ')
        $shortcut.WorkingDirectory = Split-Path -Parent $FilePath
        $shortcut.Description = "InterlockFileFixSim inert launch: $ReportedCommandLine"
        $shortcut.Save()
        Start-Process -FilePath $shortcutPath | Out-Null
        Start-Sleep -Seconds 1
        $launchMethod = 'shell-shortcut-explorer-brokered'
        Add-InterlockManifestEntry -Type 'file' -Path $shortcutPath -Action 'created' -Details @{ purpose = 'ShellExecute process-ancestry artifact'; target = $FilePath }
    } catch {
        $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
        $null = $process.ExitCode
    }
    Add-InterlockManifestEntry -Type 'process' -Path $FilePath -Action 'executed-signed-decoy' -Details @{ reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); reportedCommandLineIsMetadataOnly = $true; launchMethod = $launchMethod }
}

function Invoke-InterlockLoopbackEndpoint {
    param([Parameter(Mandatory)][string]$HostName, [ValidateRange(1, 65535)][int]$Port = 443, [string]$Path = '/')
    $paths = Get-InterlockPaths
    $cleanHost = $HostName.Replace('[.]', '.')
    $parsed = $null
    $route = if ([Net.IPAddress]::TryParse($cleanHost, [ref]$parsed)) {
        @('--connect-to', "${cleanHost}:${Port}:127.0.0.1:${Port}")
    } else {
        @('--resolve', "${cleanHost}:${Port}:127.0.0.1")
    }
    $arguments = @('--noproxy', '*') + $route + @('--connect-timeout', '1', '--max-time', '2', '--silent', '--show-error', '--insecure', '--output', 'NUL', "https://${cleanHost}:${Port}${Path}")
    $commandLine = 'curl.exe ' + ($arguments -join ' ')
    Add-Content -LiteralPath (Join-Path $paths.Evidence 'loopback-network-command-lines.log') -Value $commandLine -Encoding UTF8
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        try { Start-Process -FilePath 'curl.exe' -ArgumentList $arguments -Wait -NoNewWindow } catch {}
    }
    Add-InterlockManifestEntry -Type 'network-telemetry' -Path "${cleanHost}:${Port}" -Action 'loopback-only-attempt' -Details @{ forcedAddress = '127.0.0.1'; proxyDisabled = $true; commandLine = $commandLine }
}

function Invoke-InterlockLoopbackPort {
    param([ValidateRange(1, 65535)][int]$Port, [Parameter(Mandatory)][string]$ReportedTarget)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-InterlockManifestEntry -Type 'network-telemetry' -Path "127.0.0.1:$Port" -Action 'loopback-only-attempt' -Details @{ reportedTarget = $ReportedTarget; remoteSystemsContacted = $false }
}

function Add-InterlockTimelineEvent {
    param([Parameter(Mandatory)][datetime]$Timestamp, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$Event, [hashtable]$Details = @{})
    $paths = Get-InterlockPaths
    [ordered]@{ timestampUtc = $Timestamp.ToUniversalTime().ToString('o'); phase = $Phase; event = $Event; details = $Details } |
        ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-InterlockSummary {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $content = @"
InterlockFileFixSim completed at $((Get-Date).ToUniversalTime().ToString('o'))
Source: $script:InterlockSourceUrl
Scenario root: $($Paths.Root)
Manifest: $($Paths.Manifest)
Timeline: $($Paths.Timeline)

Artifacts remain for investigation. Use Cleanup-InterlockSim.ps1 separately.
No live PHP code, malware, real C2, domain directory, remote host, credential source,
scheduled task, security control, or non-scenario Run value was accessed or modified.
"@
    Write-InterlockEvidenceFile -Path $Paths.Summary -Content $content -Purpose 'operator handoff summary'
}
