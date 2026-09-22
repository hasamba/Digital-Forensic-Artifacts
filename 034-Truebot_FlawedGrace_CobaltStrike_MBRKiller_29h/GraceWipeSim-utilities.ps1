#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GraceWipeId = '034-Truebot_FlawedGrace_CobaltStrike_MBRKiller_29h'
$script:GraceWipeUrl = 'https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/'
$script:GraceWipeAnchor = (Get-Date).ToUniversalTime().AddHours(-29)

function Get-GraceWipePaths {
    $root = Join-Path $env:PUBLIC 'GraceWipeSim'
    [ordered]@{
        Root = $root
        Lure = Join-Path $root 'email-tds-lure'
        Beach = Join-Path $root 'BEACHHEAD'
        Hosts = Join-Path $root 'generated-hosts'
        Payloads = Join-Path $root 'payload-canaries'
        Staging = Join-Path $root 'ProgramData-staging-replica'
        Evidence = Join-Path $root 'evidence'
        Impact = Join-Path $root 'disk-impact-canaries'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.GraceWipeSim.owner'
    }
}

function Assert-GraceWipeSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-GraceWipeManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $paths = Get-GraceWipePaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:GraceWipeId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-GraceWipeEnvironment {
    $paths = Get-GraceWipePaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:GraceWipeId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root,$paths.Lure,$paths.Beach,$paths.Hosts,$paths.Payloads,$paths.Staging,$paths.Evidence,$paths.Impact)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:GraceWipeId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-GraceWipeManifest directory $paths.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $paths
}

function Write-GraceWipeFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-GraceWipeManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-GraceWipeDecoy {
    param([string]$Path,[string]$Role,[string]$ReportedSha256='NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-GraceWipeManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;reportedSha256=$ReportedSha256;hashMatch=$false}
}

function Invoke-GraceWipeDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine)
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','GRACE-WIPE-CANARY',$safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    $null = $process.ExitCode
    Add-GraceWipeManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-GraceWipeLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-GraceWipeManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-GraceWipeTimeline {
    param([double]$OffsetHours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $paths = Get-GraceWipePaths
    [ordered]@{timestampUtc=$script:GraceWipeAnchor.AddHours($OffsetHours).ToString('o');offsetHours=$OffsetHours;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-GraceWipeSummary {
    param($Paths)
    Write-GraceWipeFile $Paths.Summary "GraceWipeSim complete.`nSource: $script:GraceWipeUrl`nTime to destructive impact: 29 hours.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo malware, account/group change, task, registry/service change, injection, credential access, remote execution, exfiltration, raw-disk access, reboot, or destructive wipe occurred." 'operator summary'
}
