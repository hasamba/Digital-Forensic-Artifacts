#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:RSId = '083-Bazar_Cobalt_Zerologon_Ryuk_3h'
$script:RSUrl = 'https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/'
$script:RSAnchor = (Get-Date).ToUniversalTime().AddMinutes(-180)

function Get-RSPaths {
    $root = Join-Path $env:PUBLIC 'RyukSpeedSim'
    [ordered]@{
        Root = $root
        Landing = Join-Path $root 'phishing-landing'
        Payloads = Join-Path $root 'payload-canaries'
        Evidence = Join-Path $root 'evidence'
        Hosts = Join-Path $root 'generated-hosts'
        Staging = Join-Path $root 'staging'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\exercise-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.RyukSpeedSim.owner'
    }
}

function Assert-RSSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-RSManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details = @{})
    $p = Get-RSPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:RSId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath $p.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-RSEnvironment {
    $p = Get-RSPaths
    if (Test-Path -LiteralPath $p.Root) {
        if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:RSId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($p.Root,$p.Landing,$p.Payloads,$p.Evidence,$p.Hosts,$p.Staging)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $p.Owner -Value $script:RSId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $p.Manifest)) { New-Item -Path $p.Manifest -ItemType File -Force | Out-Null }
    Add-RSManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $p
}

function Write-RSFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose = 'artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-RSManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function Write-RSJson {
    param([string]$Path,[object]$Object,[string]$Purpose = 'evidence')
    Write-RSFile -Path $Path -Content ($Object | ConvertTo-Json -Depth 12) -Purpose $Purpose
}

function New-RSDecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256 = '')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-RSManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatchExpected=$false}
}

function Invoke-RSDecoy {
    param([string]$FilePath,[string]$Reported,[string]$Parent,[string]$Label = 'RYUK-SPEED-CANARY')
    $arguments = @('/d','/v:off','/c','echo',$Label)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    $null = $process.ExitCode
    Add-RSManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$Reported;reportedParent=$Parent;actualArguments=($arguments -join ' ');reportedOnly=$true}
}

function Invoke-RSLoopback {
    param([int]$Port,[string]$Target,[string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        $null = $pending.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-RSManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$Target;role=$Role;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-RSTimeline {
    param([double]$Minutes,[string]$Phase,[string]$Event,[hashtable]$Details = @{})
    $p = Get-RSPaths
    [ordered]@{timestampUtc=$script:RSAnchor.AddMinutes($Minutes).ToString('o');offsetMinutes=$Minutes;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath $p.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function New-RSHostTree {
    param([string]$Name,[string]$Role)
    $p = Get-RSPaths
    $hostRoot = Join-Path $p.Hosts $Name
    foreach ($directory in @('C$\Finance','C$\Operations','C$\ProgramData','ADMIN$')) { New-Item -Path (Join-Path $hostRoot $directory) -ItemType Directory -Force | Out-Null }
    Write-RSFile -Path (Join-Path $hostRoot 'host-profile.json') -Content (@{hostname=$Name;role=$Role;generated=$true;remoteSystem=$false} | ConvertTo-Json) -Purpose generated-host
    foreach ($seed in @('Finance\quarterly-plan.docx.canary','Operations\dispatch.xlsx.canary')) {
        Write-RSFile -Path (Join-Path $hostRoot "C$\$seed") -Content "INERT GENERATED DATA FOR $Name. This is not user data." -Purpose generated-canary-data
    }
    $hostRoot
}

function Write-RSSummary {
    param($Paths)
    $text = @"
RyukSpeedSim complete.
Source: $script:RSUrl
Internal case: 1007
The report's exact three-hour incident axis is preserved: ransomware deployment begins around minute 120 and domain-wide impact is reported by minute 180.
Artifacts remain; cleanup is separate.
No malware, external IOC connection, credential access, Zerologon action, process injection, remote movement, service/task/registry change, process/service termination, ACL change, or user-data encryption occurred.
"@
    Write-RSFile -Path $Paths.Summary -Content $text.Trim() -Purpose summary
}
