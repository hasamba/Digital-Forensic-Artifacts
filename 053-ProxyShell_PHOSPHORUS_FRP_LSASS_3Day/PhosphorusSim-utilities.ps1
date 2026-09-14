#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:PhosphorusSimId = '053-ProxyShell_PHOSPHORUS_FRP_LSASS_3Day'
$script:PhosphorusSimUrl = 'https://thedfirreport.com/2022/03/21/phosphorus-automates-initial-access-using-proxyshell/'
$script:PhosphorusSimAnchor = (Get-Date).ToUniversalTime().AddHours(-72)

function Get-PhosphorusSimPaths {
    $root = Join-Path $env:PUBLIC 'PhosphorusSim'
    [ordered]@{
        Root = $root
        Exchange = Join-Path $root 'exchange-canaries'
        WebRoot = Join-Path $root 'inetpub\wwwroot\aspnet_client\system_web'
        Windows = Join-Path $root 'Windows'
        Temp = Join-Path $root 'Windows\Temp'
        Payloads = Join-Path $root 'payload-canaries'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.PhosphorusSim.owner'
    }
}

function Assert-PhosphorusSimSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4, 5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-PhosphorusSimManifest {
    param([string]$Type, [string]$Path, [string]$Action, [hashtable]$Details = @{})
    $paths = Get-PhosphorusSimPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:PhosphorusSimId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8
}

function Initialize-PhosphorusSimEnvironment {
    $paths = Get-PhosphorusSimPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:PhosphorusSimId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root, $paths.Exchange, $paths.WebRoot, $paths.Windows, $paths.Temp, $paths.Payloads, $paths.Evidence)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:PhosphorusSimId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-PhosphorusSimManifest directory $paths.Root created-or-reused @{ cleanup = 'separate owned-root cleanup' }
    $paths
}

function Write-PhosphorusSimFile {
    param([string]$Path, [AllowEmptyString()][string]$Content, [string]$Purpose = 'artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-PhosphorusSimManifest file $Path created @{ purpose = $Purpose; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

function New-PhosphorusSimDecoy {
    param([string]$Path, [string]$Role, [string]$PublishedSha256 = 'NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-PhosphorusSimManifest executable-decoy $Path copied-signed-cmd @{ role = $Role; actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash; publishedSha256 = $PublishedSha256; hashMatch = $false }
}

function Invoke-PhosphorusSimDecoy {
    param([string]$FilePath, [string]$ReportedCommandLine, [string]$ReportedParent = 'w3wp.exe')
    $arguments = @('/d', '/v:off', '/c', 'echo', 'PHOSPHORUS-CANARY')
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-PhosphorusSimManifest process $FilePath executed-signed-decoy @{ reportedParent = $ReportedParent; reportedCommandLine = $ReportedCommandLine; actualArguments = ($arguments -join ' '); reportedOnly = $true }
}

function Invoke-PhosphorusSimLoopback {
    param([int]$Port, [string]$ReportedTarget, [string]$Protocol = 'tcp')
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {
    } finally {
        $client.Dispose()
    }
    Add-PhosphorusSimManifest network "127.0.0.1:$Port" loopback-only @{ reportedTarget = $ReportedTarget; protocol = $Protocol; remote = $false; proxy = $false; bytesTransferred = 0 }
}

function Add-PhosphorusSimTimeline {
    param([double]$OffsetHours, [string]$Phase, [string]$Event, [hashtable]$Details = @{})
    $paths = Get-PhosphorusSimPaths
    [ordered]@{
        timestampUtc = $script:PhosphorusSimAnchor.AddHours($OffsetHours).ToString('o')
        offsetHours = $OffsetHours
        phase = $Phase
        event = $Event
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
}

function Write-PhosphorusSimSummary {
    param($Paths)
    $content = @"
PhosphorusSim complete.
Source: $script:PhosphorusSimUrl
The two automated bursts and their approximately two-day separation are preserved on a generated 72-hour axis.
Root: $($Paths.Root)
Artifacts remain; cleanup is separate.
No ProxyShell exploit, Exchange role or mailbox operation, executable download, malware, scheduled task, account or group change, Defender/firewall/service/registry change, credential or LSASS access, archive/exfiltration, remote connection, or IOC contact occurred.
"@
    Write-PhosphorusSimFile $Paths.Summary $content 'operator summary'
}
