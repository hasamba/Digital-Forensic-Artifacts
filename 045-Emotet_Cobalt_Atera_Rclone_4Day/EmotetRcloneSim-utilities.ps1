#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:EmotetRcloneId = '045-Emotet_Cobalt_Atera_Rclone_4Day'
$script:EmotetRcloneUrl = 'https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/'
$script:EmotetRcloneAnchor = (Get-Date).ToUniversalTime().AddHours(-96)

function Get-EmotetRclonePaths {
    $root = Join-Path $env:PUBLIC 'EmotetRcloneSim'
    [ordered]@{
        Root = $root
        Lure = Join-Path $root 'phishing-lure'
        AppData = Join-Path $root 'generated-appdata\Acvpna'
        Payloads = Join-Path $root 'payload-canaries'
        Staging = Join-Path $root 'staging'
        Mail = Join-Path $root 'generated-mail'
        Shares = Join-Path $root 'generated-shares'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.EmotetRcloneSim.owner'
    }
}

function Assert-EmotetRcloneSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-EmotetRcloneManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p = Get-EmotetRclonePaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:EmotetRcloneId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Manifest -Encoding UTF8
}

function Initialize-EmotetRcloneEnvironment {
    $p = Get-EmotetRclonePaths
    if (Test-Path -LiteralPath $p.Root) {
        if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:EmotetRcloneId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($p.Root,$p.Lure,$p.AppData,$p.Payloads,$p.Staging,$p.Mail,$p.Shares,$p.Evidence)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $p.Owner -Value $script:EmotetRcloneId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $p.Manifest)) { New-Item -Path $p.Manifest -ItemType File -Force | Out-Null }
    Add-EmotetRcloneManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $p
}

function Write-EmotetRcloneFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-EmotetRcloneManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-EmotetRcloneDecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-EmotetRcloneManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatch=$false}
}

function Invoke-EmotetRcloneDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine,[string]$Parent='explorer.exe')
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','EMOTET-RCLONE-CANARY',$safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-EmotetRcloneManifest process $FilePath executed-signed-decoy @{reportedParent=$Parent;reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-EmotetRcloneLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client = New-Object Net.Sockets.TcpClient
    try { $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null); $null = $async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-EmotetRcloneManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-EmotetRcloneTimeline {
    param([double]$OffsetHours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p = Get-EmotetRclonePaths
    [ordered]@{timestampUtc=$script:EmotetRcloneAnchor.AddHours($OffsetHours).ToString('o');offsetHours=$OffsetHours;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Timeline -Encoding UTF8
}

function Write-EmotetRcloneSummary {
    param($Paths)
    Write-EmotetRcloneFile $Paths.Summary "EmotetRcloneSim complete.`nSource: $script:EmotetRcloneUrl`nFour-day relative chronology preserved.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo malware, macro, registry persistence, injection, credential access, ticket request, remote action, SMTP, directory/share query, RMM install, real collection/exfiltration, IOC contact, or impact occurred." 'operator summary'
}
