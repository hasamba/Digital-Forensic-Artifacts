#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:NitrogenId = '021-Nitrogen_Sliver_CobaltStrike_BlackCat'
$script:NitrogenUrl = 'https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/'
$script:NitrogenAnchor = (Get-Date).ToUniversalTime().AddHours(-156)

function Get-NitrogenPaths {
    $root = Join-Path $env:PUBLIC 'NitrogenBlackCatSim'
    [ordered]@{
        Root = $root
        Initial = Join-Path $root 'beachhead'
        Notepad = Join-Path $root 'beachheadAppDataRoamingNotepad'
        PublicDownloads = Join-Path $root 'beachheadPublicDownloads'
        Evidence = Join-Path $root 'evidence'
        Lateral = Join-Path $root 'generated-hosts'
        Shares = Join-Path $root 'generated-file-serverShares'
        Exfil = Join-Path $root 'restic-staging'
        Impact = Join-Path $root 'impact-canary'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidenceintrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.NitrogenBlackCatSim.owner'
    }
}

function Assert-NitrogenSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-NitrogenManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p = Get-NitrogenPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:NitrogenId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content $p.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-NitrogenEnvironment {
    $p = Get-NitrogenPaths
    if (Test-Path $p.Root) {
        if (-not (Test-Path $p.Owner) -or (Get-Content $p.Owner -Raw).Trim() -ne $script:NitrogenId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($p.Root,$p.Initial,$p.Notepad,$p.PublicDownloads,$p.Evidence,$p.Lateral,$p.Shares,$p.Exfil,$p.Impact)) {
        New-Item $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content $p.Owner $script:NitrogenId -Encoding ASCII
    if (-not (Test-Path $p.Manifest)) { New-Item $p.Manifest -ItemType File -Force | Out-Null }
    Add-NitrogenManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    return $p
}

function Write-NitrogenFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path $directory)) { New-Item $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-NitrogenManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash $Path -Algorithm SHA256).Hash}
}

function New-NitrogenDecoy {
    param([string]$Path,[string]$Role,[string]$ReportedSha256='NOT-PUBLISHED')
    New-Item (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $env:SystemRoot 'System32\cmd.exe') $Path -Force
    Add-NitrogenManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash $Path -Algorithm SHA256).Hash;reportedSha256=$ReportedSha256;match=$false}
}

function Invoke-NitrogenDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine)
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','NITROGEN-BLACKCAT-CANARY',$safe)
    $process = Start-Process $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-NitrogenManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-NitrogenLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client = New-Object Net.Sockets.TcpClient
    try {
        $attempt = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        $null = $attempt.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-NitrogenManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-NitrogenTimeline {
    param([int]$OffsetMinutes,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p = Get-NitrogenPaths
    [ordered]@{timestampUtc=$script:NitrogenAnchor.AddMinutes($OffsetMinutes).ToString('o');offsetMinutes=$OffsetMinutes;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content $p.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-NitrogenSummary {
    param($Paths)
    Write-NitrogenFile $Paths.Summary "NitrogenBlackCatSim complete.`nSource: $script:NitrogenUrl`nSimulated dwell: 156 hours across eight calendar days.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nAll payloads are signed Windows decoys or text canaries. IOC connections were rewritten to 127.0.0.1 with proxy use disabled. No credential access, remote execution, account change, task/service/registry mutation, log clearing, shadow-copy deletion, reboot, encryption, or live malware occurred." 'operator summary'
}
