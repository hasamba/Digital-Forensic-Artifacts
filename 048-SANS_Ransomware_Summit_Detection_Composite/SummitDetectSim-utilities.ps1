#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:SummitDetectId = '048-SANS_Ransomware_Summit_Detection_Composite'
$script:SummitDetectUrl = 'https://thedfirreport.com/2022/06/16/sans-ransomware-summit-2022-can-you-detect-this/'
$script:SummitDetectAnchor = (Get-Date).ToUniversalTime().AddHours(-8)

function Get-SummitDetectPaths {
    $root = Join-Path $env:PUBLIC 'SummitDetectSim'
    [ordered]@{
        Root = $root
        Delivery = Join-Path $root 'delivery-canaries'
        Payloads = Join-Path $root 'payload-canaries'
        Staging = Join-Path $root 'staging'
        Collection = Join-Path $root 'generated-collection'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\detection-sequence.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.SummitDetectSim.owner'
    }
}

function Assert-SummitDetectSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-SummitDetectManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p = Get-SummitDetectPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:SummitDetectId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-SummitDetectEnvironment {
    $p = Get-SummitDetectPaths
    if (Test-Path -LiteralPath $p.Root) {
        if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:SummitDetectId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($p.Root,$p.Delivery,$p.Payloads,$p.Staging,$p.Collection,$p.Evidence)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $p.Owner -Value $script:SummitDetectId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $p.Manifest)) { New-Item -Path $p.Manifest -ItemType File -Force | Out-Null }
    Add-SummitDetectManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $p
}

function Write-SummitDetectFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-SummitDetectManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-SummitDetectDecoy {
    param([string]$Path,[string]$Role)
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-SummitDetectManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedHash='none in source';hashMatch=$false}
}

function Invoke-SummitDetectDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine,[string]$Parent='explorer.exe')
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','SUMMIT-DETECTION-CANARY',$safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-SummitDetectManifest process $FilePath executed-signed-decoy @{reportedParent=$Parent;reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-SummitDetectLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client = New-Object Net.Sockets.TcpClient
    try { $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null); $null = $async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-SummitDetectManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-SummitDetectTimeline {
    param([double]$OffsetHours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p = Get-SummitDetectPaths
    [ordered]@{timestampUtc=$script:SummitDetectAnchor.AddHours($OffsetHours).ToString('o');offsetHours=$OffsetHours;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-SummitDetectSummary {
    param($Paths)
    Write-SummitDetectFile $Paths.Summary "SummitDetectSim complete.`nSource: $script:SummitDetectUrl`nThis is a detection composite, not a reconstruction of one victim intrusion or asserted chronology.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo ISO mount, malware, task/BITS/web-shell/RMM persistence, privilege escalation, credential access, security impairment, directory/remote action, real collection/exfiltration, IOC contact, log or shadow deletion, encryption, or impact occurred." 'operator summary'
}
