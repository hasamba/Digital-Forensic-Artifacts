#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:R5Id = '084-Bazar_Zerologon_WMI_RDP_Ryuk_5h'
$script:R5Url = 'https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/'
$script:R5Anchor = (Get-Date).ToUniversalTime().AddMinutes(-300)

function Get-R5Paths {
    $root = Join-Path $env:PUBLIC 'RyukFiveHourSim'
    [ordered]@{Root=$root;Payloads=Join-Path $root 'payload-canaries';Evidence=Join-Path $root 'evidence';Hosts=Join-Path $root 'generated-hosts';Staging=Join-Path $root 'staging';Manifest=Join-Path $root 'artifact-manifest.jsonl';Timeline=Join-Path $root 'evidence\exercise-timeline.jsonl';Summary=Join-Path $root 'operator-summary.txt';Owner=Join-Path $root '.RyukFiveHourSim.owner'}
}

function Assert-R5Safety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-R5Manifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p = Get-R5Paths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:R5Id;type=$Type;path=$Path;action=$Action;details=$Details} | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath $p.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-R5Environment {
    $p = Get-R5Paths
    if (Test-Path -LiteralPath $p.Root) { if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:R5Id) { throw 'Refusing unowned root' } }
    foreach ($directory in @($p.Root,$p.Payloads,$p.Evidence,$p.Hosts,$p.Staging)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $p.Owner -Value $script:R5Id -Encoding ASCII
    if (-not (Test-Path -LiteralPath $p.Manifest)) { New-Item -Path $p.Manifest -ItemType File -Force | Out-Null }
    Add-R5Manifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $p
}

function Write-R5File {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-R5Manifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function Write-R5Json {
    param([string]$Path,[object]$Object,[string]$Purpose='evidence')
    Write-R5File -Path $Path -Content ($Object | ConvertTo-Json -Depth 12) -Purpose $Purpose
}

function New-R5Decoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-R5Manifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatchExpected=$false}
}

function Invoke-R5Decoy {
    param([string]$FilePath,[string]$Reported,[string]$Parent,[string]$Label='RYUK-FIVE-HOUR-CANARY')
    $arguments = @('/d','/v:off','/c','echo',$Label)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    $null = $process.ExitCode
    Add-R5Manifest process $FilePath executed-signed-decoy @{reportedCommandLine=$Reported;reportedParent=$Parent;actualArguments=($arguments -join ' ');reportedOnly=$true}
}

function Invoke-R5Loopback {
    param([int]$Port,[string]$Target,[string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try { $pending=$client.BeginConnect('127.0.0.1',$Port,$null,$null);$null=$pending.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-R5Manifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$Target;role=$Role;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-R5Timeline {
    param([double]$Minutes,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p = Get-R5Paths
    [ordered]@{timestampUtc=$script:R5Anchor.AddMinutes($Minutes).ToString('o');offsetMinutes=$Minutes;phase=$Phase;event=$Event;details=$Details} | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath $p.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function New-R5HostTree {
    param([string]$Name,[string]$Role)
    $p = Get-R5Paths
    $hostRoot = Join-Path $p.Hosts $Name
    foreach ($directory in @('C$\Finance','C$\Operations','C$\PerfLogs','ADMIN$')) { New-Item -Path (Join-Path $hostRoot $directory) -ItemType Directory -Force | Out-Null }
    Write-R5Json -Path (Join-Path $hostRoot 'host-profile.json') -Object ([ordered]@{hostname=$Name;role=$Role;generated=$true;remoteSystem=$false}) -Purpose generated-host
    Write-R5File -Path (Join-Path $hostRoot 'C$\Finance\budget.xlsx.canary') -Content "INERT GENERATED DATA FOR $Name. This is not user data." -Purpose generated-canary-data
    $hostRoot
}

function Write-R5Summary {
    param($Paths)
    Write-R5File -Path $Paths.Summary -Content "RyukFiveHourSim complete.`nSource: $script:R5Url`nInternal case: 1006`nThe report's exact five-hour axis is preserved: Zerologon before hour two, readiness at hour four, backup-server pivot at 4h10m, ransomware activity around 4h30m, and completion at hour five.`nArtifacts remain; cleanup is separate.`nNo malware, external connection, credential reset, named pipe, process injection, WMI, SMB/RDP, GPO change, AD query, DLL registration, or user-data encryption occurred." -Purpose summary
}
