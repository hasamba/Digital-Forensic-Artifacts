#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BAId = '075-Bazar_Cobalt_AnchorDNS_5Day'
$script:BAUrl = 'https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/'
$script:BAAnchor = (Get-Date).ToUniversalTime().AddDays(-5)

function Get-BAPaths {
    $root = Join-Path $env:PUBLIC 'BazarAnchorSim'
    [ordered]@{Root=$root;Payloads=Join-Path $root 'payload-canaries';Profile=Join-Path $root 'generated-profile';Hosts=Join-Path $root 'generated-hosts';Honey=Join-Path $root 'generated-honey-docs';Evidence=Join-Path $root 'evidence';Manifest=Join-Path $root 'artifact-manifest.jsonl';Timeline=Join-Path $root 'evidence\exercise-timeline.jsonl';Summary=Join-Path $root 'operator-summary.txt';Owner=Join-Path $root '.BazarAnchorSim.owner'}
}

function Assert-BASafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-BAManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $paths = Get-BAPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:BAId;type=$Type;path=$Path;action=$Action;details=$Details} | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-BAEnvironment {
    $paths = Get-BAPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:BAId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root,$paths.Payloads,$paths.Profile,$paths.Hosts,$paths.Honey,$paths.Evidence)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $paths.Owner -Value $script:BAId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-BAManifest directory $paths.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $paths
}

function Write-BAFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-BAManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-BADecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-BAManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatchExpected=$false}
}

function Invoke-BADecoy {
    param([string]$FilePath,[string]$Reported,[string]$Parent)
    $arguments = @('/d','/v:off','/c','echo','BAZAR-ANCHOR-CANARY')
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    $null = $process.ExitCode
    Add-BAManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$Reported;reportedParent=$Parent;actualArguments=($arguments -join ' ');reportedOnly=$true}
}

function Invoke-BALoopback {
    param([int]$Port,[string]$Target,[string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try {$pending=$client.BeginConnect('127.0.0.1',$Port,$null,$null);$null=$pending.AsyncWaitHandle.WaitOne(500)} catch {} finally {$client.Dispose()}
    Add-BAManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$Target;role=$Role;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-BATimeline {
    param([double]$Hours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $paths = Get-BAPaths
    [ordered]@{timestampUtc=$script:BAAnchor.AddHours($Hours).ToString('o');offsetHours=$Hours;phase=$Phase;event=$Event;details=$Details} | ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-BASummary {
    param($Paths)
    Write-BAFile $Paths.Summary "BazarAnchorSim complete.`nSource: $script:BAUrl`nInternal case: 1017`nThe five-day axis preserves the report's relative timing and interrupted outcome.`nArtifacts remain; cleanup is separate.`nNo malware, macro, injection, external IOC/DNS request, task, discovery/scan, credential or LSASS access, remote movement, user-data access, exfiltration, or ransomware impact occurred." summary
}
