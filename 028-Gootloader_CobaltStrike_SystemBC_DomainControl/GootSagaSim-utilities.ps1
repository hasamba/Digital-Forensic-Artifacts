#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GootSagaId = '028-Gootloader_CobaltStrike_SystemBC_DomainControl'
$script:GootSagaUrl = 'https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/'
$script:GootSagaAnchor = (Get-Date).ToUniversalTime().AddHours(-25)

function Get-GootSagaPaths {
    $root = Join-Path $env:PUBLIC 'GootloaderSagaSim'
    [ordered]@{Root=$root;Lure=Join-Path $root 'seo-lure';Beachhead=Join-Path $root 'BEACHHEAD';Registry=Join-Path $root 'virtual-registry';Hosts=Join-Path $root 'generated-hosts';Shares=Join-Path $root 'generated-shares';Evidence=Join-Path $root 'evidence';Manifest=Join-Path $root 'artifact-manifest.jsonl';Timeline=Join-Path $root 'evidence\intrusion-timeline.jsonl';Summary=Join-Path $root 'operator-summary.txt';Owner=Join-Path $root '.GootloaderSagaSim.owner'}
}
function Assert-GootSagaSafety {
    param([switch]$LabConfirmed)
    if($env:OS-ne'Windows_NT'){throw'Windows only'}
    if(-not$LabConfirmed){throw'Lab gate refused. Pass -LabConfirmed to confirm this is a dedicated lab.'}
    $system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if([int]$system.DomainRole-in 4,5-or(Get-Service NTDS -ErrorAction SilentlyContinue)){throw'Domain-controller refusal'}
}
function Add-GootSagaManifest {
    param([string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    $p=Get-GootSagaPaths
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$script:GootSagaId;type=$Type;path=$Path;action=$Action;details=$Details}|ConvertTo-Json -Depth 9 -Compress|Add-Content $p.Manifest -Encoding UTF8
}
function Initialize-GootSagaEnvironment {
    $p=Get-GootSagaPaths
    if(Test-Path $p.Root){if(-not(Test-Path $p.Owner)-or(Get-Content $p.Owner -Raw).Trim()-ne$script:GootSagaId){throw'Refusing unowned root'}}
    foreach($d in @($p.Root,$p.Lure,$p.Beachhead,$p.Registry,$p.Hosts,$p.Shares,$p.Evidence)){New-Item $d -ItemType Directory -Force|Out-Null}
    Set-Content $p.Owner $script:GootSagaId -Encoding ASCII
    if(-not(Test-Path $p.Manifest)){New-Item $p.Manifest -ItemType File -Force|Out-Null}
    Add-GootSagaManifest directory $p.Root created-or-reused @{cleanup='separate owned-root cleanup'}
    return $p
}
function Write-GootSagaFile {
    param([string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $d=Split-Path -Parent $Path;if(-not(Test-Path $d)){New-Item $d -ItemType Directory -Force|Out-Null}
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-GootSagaManifest file $Path created @{purpose=$Purpose;sha256=(Get-FileHash $Path -Algorithm SHA256).Hash}
}
function New-GootSagaDecoy {
    param([string]$Path,[string]$Role,[string]$ReportedSha256='NOT-PUBLISHED')
    New-Item(Split-Path -Parent $Path)-ItemType Directory -Force|Out-Null
    Copy-Item(Join-Path $env:SystemRoot 'System32\cmd.exe')$Path -Force
    Add-GootSagaManifest executable-decoy $Path copied-signed-cmd @{role=$Role;actualSha256=(Get-FileHash $Path -Algorithm SHA256).Hash;reportedSha256=$ReportedSha256;hashMatch=$false}
}
function Invoke-GootSagaDecoy {
    param([string]$FilePath,[string]$ReportedCommandLine)
    $safe=$ReportedCommandLine.Replace('^','^^').Replace('&','^&').Replace('|','^|').Replace('<','^<').Replace('>','^>').Replace('(','^(').Replace(')','^)')
    $args=@('/d','/v:off','/c','echo','GOOT-SAGA-CANARY',$safe)
    $proc=Start-Process $FilePath -ArgumentList $args -PassThru -Wait -WindowStyle Hidden;$null=$proc.ExitCode
    Add-GootSagaManifest process $FilePath executed-signed-decoy @{reportedCommandLine=$ReportedCommandLine;actualArguments=($args-join' ');escaped=$true}
}
function Invoke-GootSagaLoopback {
    param([int]$Port,[string]$ReportedTarget,[string]$Protocol='tcp')
    $client=New-Object Net.Sockets.TcpClient
    try{$a=$client.BeginConnect('127.0.0.1',$Port,$null,$null);$null=$a.AsyncWaitHandle.WaitOne(500)}catch{}finally{$client.Dispose()}
    Add-GootSagaManifest network "127.0.0.1:$Port" loopback-only @{reportedTarget=$ReportedTarget;protocol=$Protocol;remote=$false;proxy=$false;bytesTransferred=0}
}
function Add-GootSagaTimeline {
    param([int]$OffsetMinutes,[string]$Phase,[string]$Event,[hashtable]$Details=@{})
    $p=Get-GootSagaPaths
    [ordered]@{timestampUtc=$script:GootSagaAnchor.AddMinutes($OffsetMinutes).ToString('o');offsetMinutes=$OffsetMinutes;phase=$Phase;event=$Event;details=$Details}|ConvertTo-Json -Depth 9 -Compress|Add-Content $p.Timeline -Encoding UTF8
}
function Write-GootSagaSummary {
    param($Paths)
    Write-GootSagaFile $Paths.Summary "GootloaderSagaSim complete.`nSource: $script:GootSagaUrl`nRoot: $($Paths.Root)`nArtifacts remain; cleanup is separate.`nNo malware, registry persistence, scheduled task, injection, LSASS access, Defender change, remote service, directory query, RDP, WinRM, share access, network scan, data collection, or exfiltration occurred." 'operator summary'
}
