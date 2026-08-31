function Invoke-InterlockC2PersistenceCapabilities {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-InterlockTimeline

    $endpoints = @(
        'existed-bunch-balance-councils.trycloudflare.com',
        'ferrari-rolling-facilities-lounge.trycloudflare.com',
        'galleries-physicians-psp-wv.trycloudflare.com',
        'evidence-deleted-procedure-bringing.trycloudflare.com',
        'nowhere-locked-manor-hs.trycloudflare.com',
        'ranked-accordingly-ab-hired.trycloudflare.com',
        '64.95.12.71',
        '184.95.51.165'
    )
    foreach ($endpoint in $endpoints) { Invoke-InterlockLoopbackEndpoint -HostName $endpoint -Port 443 -Path '/api/rat' }

    $exePayload = Join-Path $Paths.C2Commands 'update.exe'
    New-InterlockBinaryDecoy -Path $exePayload -Role 'RAT EXE command downloaded-payload canary'
    Invoke-InterlockDecoyProcess -FilePath $exePayload -ReportedCommandLine 'update.exe --interlock-c2-command EXE (generated signed decoy)'

    $dllPayload = Join-Path $Paths.C2Commands 'module.dll'
    Write-InterlockEvidenceFile -Path $dllPayload -Content 'MZ-INTERLOCK-CANARY - inert DLL command payload.' -Purpose 'RAT DLL command payload-shaped canary' -Timestamp $time.Persistence.AddMinutes(-3)
    $rundll32 = Join-Path $Paths.C2Commands 'rundll32.exe'
    New-InterlockBinaryDecoy -Path $rundll32 -Role 'rundll32 process-name canary for RAT DLL command'
    Invoke-InterlockDecoyProcess -FilePath $rundll32 -ReportedCommandLine "rundll32.exe `"$dllPayload`",EntryPoint (inert DLL command canary)"

    $runCommand = Get-InterlockExpectedRunCommand
    New-Item -Path $Paths.RunKey -Force | Out-Null
    New-ItemProperty -LiteralPath $Paths.RunKey -Name $script:InterlockRunValue -PropertyType String -Value $runCommand -Force | Out-Null
    Add-InterlockManifestEntry -Type 'registry' -Path "$($Paths.RunKey)\$script:InterlockRunValue" -Action 'created-inert-run-value' -Details @{ value = $runCommand; targetExecutable = 'signed cmd decoy named php.exe'; targetConfigExecutable = $false }

    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    Invoke-InterlockDecoyProcess -FilePath $cmd -ReportedCommandLine 'cmd.exe /s /c "whoami && dir %appdata%" (RAT CMD canary)'
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.C2Commands 'OFF-command.json') -Content '{"command":"OFF","reportedAction":"shut down RAT","actualAction":"marker only"}' -Purpose 'RAT OFF command marker' -Timestamp $time.Persistence.AddMinutes(2)

    $mstsc = Join-Path $Paths.C2Commands 'mstsc.exe'
    New-InterlockBinaryDecoy -Path $mstsc -Role 'RDP lateral-movement process-name canary'
    Invoke-InterlockDecoyProcess -FilePath $mstsc -ReportedCommandLine 'mstsc.exe /v:LAB-REMOTE01 (actual network target 127.0.0.1 only)'
    Invoke-InterlockLoopbackPort -Port 3389 -ReportedTarget 'victim environment RDP target'

    $capabilityMatrix = [ordered]@{
        EXE = [ordered]@{ reported = 'download executable to temp and run'; represented = 'signed local update.exe decoy'; download = $false }
        DLL = [ordered]@{ reported = 'download DLL and run with rundll32'; represented = 'inert module.dll plus rundll32 decoy'; dllLoaded = $false }
        AUTORUN = [ordered]@{ reported = 'add HKCU Run entry'; represented = $script:InterlockRunValue; inertTarget = $true }
        CMD = [ordered]@{ reported = 'execute arbitrary shell command'; represented = 'escaped echo-only command'; arbitraryExecution = $false }
        OFF = [ordered]@{ reported = 'shut RAT down'; represented = 'JSON marker only' }
    }
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.C2Commands 'capability-matrix.json') -Content ($capabilityMatrix | ConvertTo-Json -Depth 7) -Purpose 'Interlock RAT command capability mapping' -Timestamp $time.Persistence.AddMinutes(3)

    Add-InterlockTimelineEvent -Timestamp $time.HandsOn.AddMinutes(5) -Phase 'Command and Control' -Event 'Cloudflare Tunnel domains and fallback IPs attempted through curl with forced loopback routing and proxy bypass.' -Details @{ endpointCount = $endpoints.Count; realC2 = $false; actualDestination = '127.0.0.1' }
    Add-InterlockTimelineEvent -Timestamp $time.Persistence -Phase 'Persistence' -Event 'Interlock RAT AUTORUN command created a real HKCU Run value targeting an inert php.exe/config pair.' -Details @{ runValue = $script:InterlockRunValue; executableMalicious = $false; cleanup = 'separate explicit script' }
    Add-InterlockTimelineEvent -Timestamp $time.Persistence.AddMinutes(2) -Phase 'Execution and Lateral Movement' -Event 'EXE, DLL, CMD, OFF, and RDP capabilities represented with local decoys and loopback only.' -Details @{ downloaded = $false; dllLoaded = $false; remoteCommand = $false; remoteRdp = $false }
}
