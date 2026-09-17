#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ShareFinderId = '039-ShareFinder_NetworkShare_Discovery_Profile'
$script:ShareFinderUrl = 'https://thedfirreport.com/2023/01/23/sharefinder-how-threat-actors-discover-file-shares/'
$script:ShareFinderAnchor = (Get-Date).ToUniversalTime().AddMinutes(-30)

function Get-ShareFinderPaths {
    $root = Join-Path $env:PUBLIC 'ShareFinderSim'
    [ordered]@{
        Root=$root;Tool=Join-Path $root 'tool-canary';Hosts=Join-Path $root 'generated-hosts';Evidence=Join-Path $root 'evidence';Logs=Join-Path $root 'generated-event-logs';Manifest=Join-Path $root 'artifact-manifest.jsonl';Timeline=Join-Path $root 'evidence\profile-timeline.jsonl';Summary=Join-Path $root 'operator-summary.txt';Owner=Join-Path $root '.ShareFinderSim.owner'
    }
}

function Assert-ShareFinderSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-ShareFinderManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $paths=Get-ShareFinderPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:ShareFinderId;type=$Type;path=$Path;action=$Action;details=$Details}|ConvertTo-Json -Depth 9 -Compress|Add-Content -LiteralPath $paths.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-ShareFinderEnvironment {
    $paths=Get-ShareFinderPaths
    if(Test-Path -LiteralPath $paths.Root){if(-not(Test-Path -LiteralPath $paths.Owner)-or(Get-Content -LiteralPath $paths.Owner -Raw).Trim()-ne$script:ShareFinderId){throw'Refusing unowned root'}}
    foreach($directory in @($paths.Root,$paths.Tool,$paths.Hosts,$paths.Evidence,$paths.Logs)){New-Item -Path $directory -ItemType Directory -Force|Out-Null}
    Set-Content -LiteralPath $paths.Owner -Value $script:ShareFinderId -Encoding ASCII
    if(-not(Test-Path -LiteralPath $paths.Manifest)){New-Item -Path $paths.Manifest -ItemType File -Force|Out-Null}
    Add-ShareFinderManifest directory $paths.Root created-or-reused @{cleanup='separate owned-root cleanup';techniqueProfile=$true}
    $paths
}

function Write-ShareFinderFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory=Split-Path -Parent $Path
    if(-not(Test-Path -LiteralPath $directory)){New-Item -Path $directory -ItemType Directory -Force|Out-Null}
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-ShareFinderManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function Add-ShareFinderJsonLine {
    param([string]$Path,[hashtable]$Record,[string]$Purpose='generated event')
    $directory=Split-Path -Parent $Path
    if(-not(Test-Path -LiteralPath $directory)){New-Item -Path $directory -ItemType Directory -Force|Out-Null}
    $Record|ConvertTo-Json -Depth 9 -Compress|Add-Content -LiteralPath $Path -Encoding UTF8
    Add-ShareFinderManifest generated-event $Path appended @{purpose=$Purpose;synthetic=$true}
}

function New-ShareFinderDecoy {
    param([string]$Path,[string]$Role)
    New-Item -Path(Split-Path -Parent $Path)-ItemType Directory -Force|Out-Null
    Copy-Item -LiteralPath(Join-Path $env:SystemRoot 'System32\cmd.exe')-Destination $Path -Force
    Add-ShareFinderManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function Invoke-ShareFinderDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine,[string]$Parent='beacon.exe')
    $safe=$ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments=@('/d','/v:off','/c','echo','SHAREFINDER-CANARY',$safe)
    $process=Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null=$process.ExitCode
    Add-ShareFinderManifest process $FilePath executed-signed-decoy @{reportedParent=$Parent;reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments-join' ');shareEnumerationExecuted=$false}
}

function Invoke-ShareFinderLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='SMB')
    $client=New-Object Net.Sockets.TcpClient
    try{$async=$client.BeginConnect('127.0.0.1',$Port,$null,$null);$null=$async.AsyncWaitHandle.WaitOne(500)}catch{}finally{$client.Dispose()}
    Add-ShareFinderManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-ShareFinderTimeline {
    param([double]$OffsetMinutes,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $paths=Get-ShareFinderPaths
    [ordered]@{timestampUtc=$script:ShareFinderAnchor.AddMinutes($OffsetMinutes).ToString('o');offsetMinutes=$OffsetMinutes;techniqueProfile=$true;phase=$Phase;event=$Event;details=$Details}|ConvertTo-Json -Depth 9 -Compress|Add-Content -LiteralPath $paths.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-ShareFinderSummary {
    param($Paths)
    Write-ShareFinderFile $Paths.Summary "ShareFinderSim complete.`nSource: $script:ShareFinderUrl`nThis is a synthetic technique/detection profile, not one observed intrusion.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo PowerView code, LDAP query, ICMP packet, remote SMB connection, share access, file collection, or exfiltration occurred." 'operator summary'
}
