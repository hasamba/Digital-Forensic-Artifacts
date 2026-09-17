#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:OilKeyId = '038-TA452_PowerShell_AutoHotkey_Keylogger_9Day'
$script:OilKeyUrl = 'https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/'
$script:OilKeyAnchor = (Get-Date).ToUniversalTime().AddHours(-216)

function Get-OilKeyPaths {
    $root = Join-Path $env:PUBLIC 'OilKeySim'
    [ordered]@{
        Root = $root
        Lure = Join-Path $root 'lure'
        Update = Join-Path $root 'Users\analyst\AppData\Local\Microsoft\Windows\Update'
        Modules = Join-Path $root 'keylogger-stack'
        Collection = Join-Path $root 'collection'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.OilKeySim.owner'
    }
}

function Assert-OilKeySafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-OilKeyManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $paths = Get-OilKeyPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:OilKeyId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-OilKeyEnvironment {
    $paths = Get-OilKeyPaths
    if (Test-Path -LiteralPath $paths.Root) {
        if (-not (Test-Path -LiteralPath $paths.Owner) -or (Get-Content -LiteralPath $paths.Owner -Raw).Trim() -ne $script:OilKeyId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($paths.Root,$paths.Lure,$paths.Update,$paths.Modules,$paths.Collection,$paths.Evidence)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $script:OilKeyId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File -Force | Out-Null }
    Add-OilKeyManifest directory $paths.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $paths
}

function Write-OilKeyFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-OilKeyManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-OilKeyDecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-OilKeyManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatch=$false}
}

function Invoke-OilKeyDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine,[string]$Parent='WINWORD.EXE')
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','OILKEY-CANARY',$safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-OilKeyManifest process $FilePath executed-signed-decoy @{reportedParent=$Parent;reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-OilKeyLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Method='GET')
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        $null = $async.AsyncWaitHandle.WaitOne(500)
    } catch {} finally { $client.Dispose() }
    Add-OilKeyManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;method=$Method;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-OilKeyTimeline {
    param([double]$OffsetHours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $paths = Get-OilKeyPaths
    [ordered]@{timestampUtc=$script:OilKeyAnchor.AddHours($OffsetHours).ToString('o');offsetHours=$OffsetHours;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 9 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-OilKeySummary {
    param($Paths)
    Write-OilKeyFile $Paths.Summary "OilKeySim complete.`nSource: $script:OilKeyUrl`nObserved window represented: nine days.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo malware, scheduled task, keyboard hook, registry change, screenshot, real discovery/collection, IOC contact, exfiltration, or destructive impact occurred." 'operator summary'
}
