#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:IRId = '074-IcedID_Cobalt_Rclone_REvil_4h30m'
$script:IRUrl = 'https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/'
$script:IRAnchor = (Get-Date).ToUniversalTime().AddMinutes(-270)

function Get-IRPaths {
    $root = Join-Path $env:PUBLIC 'IcedRevilSim'
    [ordered]@{
        Root = $root
        Payloads = Join-Path $root 'payload-canaries'
        Profile = Join-Path $root 'generated-profile'
        Hosts = Join-Path $root 'generated-hosts'
        Shares = Join-Path $root 'generated-shares'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\exercise-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.IcedRevilSim.owner'
    }
}

function Assert-IRSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-IRManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $paths = Get-IRPaths
    [ordered]@{
        timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        scenarioId = $script:IRId
        type = $Type
        path = $Path
        action = $Action
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-IREnvironment {
    $paths = Get-IRPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:IRId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root,$paths.Payloads,$paths.Profile,$paths.Hosts,$paths.Shares,$paths.Evidence)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:IRId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-IRManifest directory $paths.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $paths
}

function Write-IRFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-IRManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-IRDecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-IRManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatchExpected=$false}
}

function Invoke-IRDecoy {
    param([string]$FilePath,[string]$Reported,[string]$Parent)
    $arguments = @('/d','/v:off','/c','echo','ICED-REVIL-CANARY')
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    $null = $process.ExitCode
    Add-IRManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$Reported;reportedParent=$Parent;actualArguments=($arguments -join ' ');reportedOnly=$true}
}

function Invoke-IRLoopback {
    param([int]$Port,[string]$Target,[string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        $null = $pending.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-IRManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$Target;role=$Role;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-IRTimeline {
    param([double]$Minutes,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $paths = Get-IRPaths
    [ordered]@{
        timestampUtc = $script:IRAnchor.AddMinutes($Minutes).ToString('o')
        offsetMinutes = $Minutes
        phase = $Phase
        event = $Event
        details = $Details
    } | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-IRSummary {
    param($Paths)
    Write-IRFile $Paths.Summary "IcedRevilSim complete.`nSource: $script:IRUrl`nInternal case: 1051`nReport duration: 4.5 hours; timestamps preserve the reported relative chronology.`nArtifacts remain; cleanup is separate.`nNo malware, external IOC contact, injection, task/registry/boot/GPO/service change, credential or LSASS access, remote movement, security impairment, user-data access, or encryption occurred." summary
}
