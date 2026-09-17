#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:MsiPlinkId = '049-ManageEngine_Msiexec_WebShell_Plink_Exfil_8Day'
$script:MsiPlinkUrl = 'https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/'
$script:MsiPlinkAnchor = (Get-Date).ToUniversalTime().AddHours(-192)

function Get-MsiPlinkPaths {
    $root = Join-Path $env:PUBLIC 'MsiPlinkSim'
    [ordered]@{
        Root = $root
        ManageEngine = Join-Path $root 'ManageEngine\SupportCenterPlus'
        Web = Join-Path $root 'ManageEngine\SupportCenterPlus\custom\login'
        Payloads = Join-Path $root 'payload-canaries'
        Temp = Join-Path $root 'Windows\Temp'
        Collection = Join-Path $root 'generated-collection'
        Evidence = Join-Path $root 'evidence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\intrusion-timeline.jsonl'
        Summary = Join-Path $root 'operator-summary.txt'
        Owner = Join-Path $root '.MsiPlinkSim.owner'
    }
}

function Assert-MsiPlinkSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed) { throw 'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Add-MsiPlinkManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p = Get-MsiPlinkPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:MsiPlinkId;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Manifest -Encoding UTF8;Write-Host ("  [{0}] {1}: {2}" -f $Type,$Action,$Path) -ForegroundColor DarkGray
}

function Initialize-MsiPlinkEnvironment {
    $p = Get-MsiPlinkPaths
    if (Test-Path -LiteralPath $p.Root) {
        if (-not (Test-Path -LiteralPath $p.Owner) -or (Get-Content -LiteralPath $p.Owner -Raw).Trim() -ne $script:MsiPlinkId) { throw 'Refusing unowned root' }
    }
    foreach ($directory in @($p.Root,$p.ManageEngine,$p.Web,$p.Payloads,$p.Temp,$p.Collection,$p.Evidence)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $p.Owner -Value $script:MsiPlinkId -Encoding ASCII
    if (-not (Test-Path -LiteralPath $p.Manifest)) { New-Item -Path $p.Manifest -ItemType File -Force | Out-Null }
    Add-MsiPlinkManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    $p
}

function Write-MsiPlinkFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-MsiPlinkManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function New-MsiPlinkDecoy {
    param([string]$Path,[string]$Role,[string]$PublishedSha256='NOT-PUBLISHED')
    New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $Path -Force
    Add-MsiPlinkManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;publishedSha256=$PublishedSha256;hashMatch=$false}
}

function Invoke-MsiPlinkDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine,[string]$Parent='java.exe')
    $safe = $ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $arguments = @('/d','/v:off','/c','echo','MSI-PLINK-CANARY',$safe)
    $process = Start-Process -FilePath $FilePath -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    $null = $process.ExitCode
    Add-MsiPlinkManifest process $FilePath executed-signed-decoy @{reportedParent=$Parent;reportedCommandLine=$ReportedCommandLine;actualArguments=($arguments -join ' ');escaped=$true}
}

function Invoke-MsiPlinkLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client = New-Object Net.Sockets.TcpClient
    try { $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null); $null = $async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-MsiPlinkManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}

function Add-MsiPlinkTimeline {
    param([double]$OffsetHours,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p = Get-MsiPlinkPaths
    [ordered]@{timestampUtc=$script:MsiPlinkAnchor.AddHours($OffsetHours).ToString('o');offsetHours=$OffsetHours;phase=$Phase;event=$Event;details=$Details} |
        ConvertTo-Json -Depth 10 -Compress | Add-Content -LiteralPath $p.Timeline -Encoding UTF8;Write-Host ("  [timeline] {0}: {1}" -f $Phase,$Event) -ForegroundColor Cyan
}

function Write-MsiPlinkSummary {
    param($Paths)
    Write-MsiPlinkFile $Paths.Summary "MsiPlinkSim complete.`nSource: $script:MsiPlinkUrl`nEight-day chronology preserves the source's day-seven and following-day milestones.`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo ManageEngine exploit, web shell, SYSTEM execution, registry/WDigest change, credential or LSASS access, download, SSH/RDP tunnel, remote action, real file/certificate access, exfiltration, IOC contact, deletion, or impact occurred." 'operator summary'
}
