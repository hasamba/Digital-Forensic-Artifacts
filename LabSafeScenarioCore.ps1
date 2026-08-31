#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-DFIRLabSafety {
    param([switch]$LabConfirmed)
    if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
    if (-not $LabConfirmed -or $env:DFIR_LAB_CONFIRMATION -ne 'I_UNDERSTAND_THIS_IS_A_LAB') { throw 'Lab gate refused' }
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$system.DomainRole -in 4,5 -or (Get-Service NTDS -ErrorAction SilentlyContinue)) { throw 'Domain-controller refusal' }
}

function Get-DFIRLabPaths {
    param([Parameter(Mandatory)][object]$Config)
    $root = Join-Path $env:PUBLIC $Config.RootName
    [ordered]@{
        Root = $root
        Payloads = Join-Path $root 'payload-canaries'
        Evidence = Join-Path $root 'evidence'
        Hosts = Join-Path $root 'generated-hosts'
        Persistence = Join-Path $root 'generated-persistence'
        Manifest = Join-Path $root 'artifact-manifest.jsonl'
        Timeline = Join-Path $root 'evidence\exercise-timeline.jsonl'
        Owner = Join-Path $root ('.' + $Config.RootName + '.owner')
    }
}

function Add-DFIRLabManifest {
    param([object]$Config,[object]$Paths,[string]$Type,[string]$Path,[string]$Action,[hashtable]$Details=@{})
    [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');scenarioId=$Config.Id;type=$Type;path=$Path;action=$Action;details=$Details} |
        ConvertTo-Json -Depth 15 -Compress | Add-Content -LiteralPath $Paths.Manifest -Encoding UTF8
}

function Initialize-DFIRLabEnvironment {
    param([object]$Config)
    $paths = Get-DFIRLabPaths $Config
    if (Test-Path $paths.Root) {
        if (-not (Test-Path $paths.Owner) -or (Get-Content $paths.Owner -Raw).Trim() -ne $Config.Id) { throw 'Refusing unowned scenario root' }
    }
    foreach ($directory in @($paths.Root,$paths.Payloads,$paths.Evidence,$paths.Hosts,$paths.Persistence)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Set-Content -LiteralPath $paths.Owner -Value $Config.Id -Encoding ASCII
    if (-not (Test-Path $paths.Manifest)) { New-Item -Path $paths.Manifest -ItemType File | Out-Null }
    Add-DFIRLabManifest $Config $paths directory $paths.Root created-or-reused @{cleanup='separate exact-root cleanup'}
    $paths
}

function Write-DFIRLabFile {
    param([object]$Config,[object]$Paths,[string]$Path,[AllowEmptyString()][string]$Content,[string]$Purpose='artifact')
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
    Add-DFIRLabManifest $Config $Paths file $Path created @{purpose=$Purpose;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}

function Write-DFIRLabJson {
    param([object]$Config,[object]$Paths,[string]$Path,[object]$Object,[string]$Purpose='evidence')
    Write-DFIRLabFile $Config $Paths $Path ($Object | ConvertTo-Json -Depth 20) $Purpose
}

function New-DFIRLabDecoy {
    param([object]$Config,[object]$Paths,[string]$RelativePath,[string]$Role,[string]$PublishedHash='none')
    $path = Join-Path $Paths.Root $RelativePath
    $parent = Split-Path $path -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $path -Force
    Add-DFIRLabManifest $Config $Paths executable-decoy $path copied-signed-cmd @{role=$Role;publishedHash=$PublishedHash;actualSha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    $path
}

function Invoke-DFIRLabDecoy {
    param([object]$Config,[object]$Paths,[string]$RelativePath,[string]$Reported,[string]$Parent)
    $path = Join-Path $Paths.Root $RelativePath
    if (-not (Test-Path $path)) { $null = New-DFIRLabDecoy $Config $Paths $RelativePath 'command stand-in' }
    $arguments = @('/d','/v:off','/c','echo','DFIR-LAB-SAFE-CANARY')
    $process = Start-Process -FilePath $path -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    $null = $process.ExitCode
    Add-DFIRLabManifest $Config $Paths process $path executed-signed-decoy @{reportedCommandLine=$Reported;reportedParent=$Parent;actualArguments=($arguments -join ' ');reportedOnly=$true}
}

function Invoke-DFIRLabLoopback {
    param([object]$Config,[object]$Paths,[int]$Port,[string]$Target,[string]$Role)
    $client = New-Object Net.Sockets.TcpClient
    try { $async=$client.BeginConnect('127.0.0.1',$Port,$null,$null);$null=$async.AsyncWaitHandle.WaitOne(500) } catch {} finally { $client.Dispose() }
    Add-DFIRLabManifest $Config $Paths network "127.0.0.1:$Port" loopback-only @{reportedTarget=$Target;role=$Role;remote=$false;proxy=$false;bytesTransferred=0}
}

function Invoke-DFIRLabScenario {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Config,[switch]$LabConfirmed)
    Assert-DFIRLabSafety -LabConfirmed:$LabConfirmed
    $paths = Initialize-DFIRLabEnvironment $Config
    foreach ($file in $Config.Files) { $null = New-DFIRLabDecoy $Config $paths $file.path $file.role $file.publishedHash }
    foreach ($artifact in $Config.Artifacts) { Write-DFIRLabFile $Config $paths (Join-Path $paths.Root $artifact.path) $artifact.content $artifact.purpose }
    foreach ($command in $Config.Commands) { Invoke-DFIRLabDecoy $Config $paths $command.file $command.reported $command.parent }
    foreach ($network in $Config.Network) { Invoke-DFIRLabLoopback $Config $paths $network.port $network.target $network.role }
    $anchor = (Get-Date).ToUniversalTime().AddMinutes(-[double]$Config.DurationMinutes)
    foreach ($event in $Config.Timeline) {
        [ordered]@{timestampUtc=$anchor.AddMinutes([double]$event.offset).ToString('o');offsetMinutes=$event.offset;phase=$event.phase;event=$event.event;details=$event.details} |
            ConvertTo-Json -Depth 15 -Compress | Add-Content -LiteralPath $paths.Timeline -Encoding UTF8
    }
    Write-DFIRLabJson $Config $paths (Join-Path $paths.Evidence 'scenario-source-and-safety.json') ([ordered]@{
        source=$Config.Source;reportTitle=$Config.Title;timelineNote=$Config.TimelineNote;publishedIOCs=$Config.IOCs
        negative=[ordered]@{liveMalware=0;externalConnections=0;bytesTransferred=0;credentialsAccessed=0;lsassOrNtdsAccess=0;remoteSystemsAccessed=0;securityControlsChanged=0;logsCleared=0;shadowCopiesDeleted=0;userDataEncrypted=0}
    }) 'source and safety evidence'
    Write-DFIRLabFile $Config $paths (Join-Path $paths.Root 'operator-summary.txt') ("$($Config.Title) lab-safe scenario complete.`r`nSource: $($Config.Source)`r`n$($Config.TimelineNote)`r`nNo live malware, real IOC connection, credential access, remote action, security impairment, log/shadow deletion, or user-data encryption occurred.`r`nArtifacts remain; cleanup is separate.") 'operator summary'
    Write-Host "Complete. Evidence remains at $($paths.Root); cleanup is separate."
}

function Remove-DFIRLabScenario {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param([Parameter(Mandatory)][object]$Config,[switch]$LabConfirmed)
    Assert-DFIRLabSafety -LabConfirmed:$LabConfirmed
    $paths = Get-DFIRLabPaths $Config
    $expected = Join-Path $env:PUBLIC $Config.RootName
    if ($paths.Root -ne $expected) { throw 'Cleanup root mismatch' }
    if (-not (Test-Path $paths.Root)) { return }
    if (-not (Test-Path $paths.Owner) -or (Get-Content $paths.Owner -Raw).Trim() -ne $Config.Id) { throw 'Refusing unowned scenario root' }
    if ($PSCmdlet.ShouldProcess($paths.Root,'Remove scenario-owned artifact tree')) { Remove-Item -LiteralPath $paths.Root -Recurse -Force;Write-Host "Removed $($paths.Root)" }
}
