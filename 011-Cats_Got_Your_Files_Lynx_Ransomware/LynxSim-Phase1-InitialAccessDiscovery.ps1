function Invoke-LynxInitialAccessDiscovery {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-LynxTimeline

    $securityEvents = @(
        [ordered]@{ TimeCreated = $time.Day1.ToString('o'); EventId = 4624; LogonType = 3; IpAddress = '195.211.190.189'; WorkstationName = 'DESKTOP-BUL6K1U'; ElevatedToken = $true; Account = 'LAB\labanalyst'; Note = 'Synthetic event record; not written to the Security log.' },
        [ordered]@{ TimeCreated = $time.Day1.AddSeconds(8).ToString('o'); EventId = 4624; LogonType = 10; IpAddress = '195.211.190.189'; WorkstationName = 'DESKTOP-BUL6K1U'; ElevatedToken = $true; Account = 'LAB\labanalyst'; Note = 'Synthetic event record; source IP is metadata only.' }
    )
    $eventPath = Join-Path $Paths.Evidence 'security-4624-rdp-canary.json'
    Write-LynxEvidenceFile -Path $eventPath -Content ($securityEvents | ConvertTo-Json -Depth 5) -Purpose 'reported RDP logon evidence represented without a real external logon' -Timestamp $time.Day1

    Invoke-LynxNativeCommand -FilePath 'ipconfig.exe' -Label 'system network configuration discovery'
    Invoke-LynxNativeCommand -FilePath 'route.exe' -ArgumentList @('print') -Label 'system network configuration discovery'
    Invoke-LynxNativeCommand -FilePath 'systeminfo.exe' -Label 'system information discovery'

    $netscanPath = Join-Path $Paths.Desktop000 'netscan.exe'
    New-LynxCommandDecoy -Path $netscanPath -ReportedSha256 '517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37' -Role 'SoftPerfect Network Scanner v7.2.7 process-name canary'

    $netscanConfig = @'
<?xml version="1.0"?>
<netscan-canary version="7.2.7">
  <safety actual-target="127.0.0.1" reported-range="REDACTED/24" remote-write-checks="disabled" />
  <ports>135,445,1433,3389</ports>
  <checks>accounts,disk-drives,lan-group,logged-users,os-version,uptime,shares</checks>
  <hotkeys rdp="CTRL+R" computer-management="CTRL+M" />
  <credentials>LAB-CANARY-NO-REAL-CREDENTIALS</credentials>
</netscan-canary>
'@
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Desktop000 'netscan.xml') -Content $netscanConfig -Purpose 'inert NetScan configuration matching reported scan categories' -Timestamp $time.Day1.AddMinutes(8)
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Desktop000 'netscan.lic') -Content 'LAB-LICENSE-CANARY - no commercial or cracked license material' -Purpose 'inert NetScan license-shaped artifact' -Timestamp $time.Day1.AddMinutes(8)

    Invoke-LynxDecoyProcess -FilePath $netscanPath -ReportedCommandLine 'netscan.exe (GUI scan of victim /24; actual canary target 127.0.0.1 only)'
    foreach ($port in @(135, 445, 1433, 3389)) {
        Invoke-LynxLoopbackPortAttempt -Port $port -ReportedTarget 'victim /24 range (redacted in report)'
    }

    $shareTargets = @(
        (Join-Path $Paths.Shares 'FILE01\Finance'),
        (Join-Path $Paths.Shares 'FILE02\Legal')
    )
    foreach ($share in $shareTargets) {
        New-Item -Path $share -ItemType Directory -Force | Out-Null
        $writeCheck = Join-Path $share 'delete.me'
        Set-Content -LiteralPath $writeCheck -Value 'NetScan write-check canary' -Encoding ASCII
        Add-LynxManifestEntry -Type 'file' -Path $writeCheck -Action 'created-then-deleted' -Details @{ purpose = 'generate local MFT/USN write-check evidence only'; remoteShare = $false }
        Remove-Item -LiteralPath $writeCheck -Force
        Write-LynxEvidenceFile -Path (Join-Path $share 'delete.me.tombstone.json') -Content ('{"reportedName":"delete.me","action":"created-then-deleted","remote":false}') -Purpose 'portable tombstone for the local canary deletion' -Timestamp $time.Day1.AddMinutes(14)
    }

    $scanResults = @'
<?xml version="1.0"?>
<scan-results actual-scope="127.0.0.1" reported-scope="REDACTED/24">
  <host name="DC01" ip="10.77.0.10" role="metadata-only" ports="445,3389" />
  <host name="HV01" ip="10.77.0.20" role="metadata-only" ports="443,3389" />
  <host name="FILE01" ip="10.77.0.30" role="metadata-only" ports="445" />
</scan-results>
'@
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Desktop000 'ss.xml') -Content $scanResults -Purpose 'NetScan result artifact with non-routable metadata targets' -Timestamp $time.Day1.AddMinutes(17)

    Add-LynxTimelineEvent -Timestamp $time.Day1 -Phase 'Initial Access' -Event 'Successful valid-account RDP represented by synthetic 4624 type 3 and type 10 records.' -Details @{ sourceIpIoc = '195.211.190.189'; workstation = 'DESKTOP-BUL6K1U'; realRdp = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day1.AddMinutes(6) -Phase 'Discovery' -Event 'Native discovery commands and NetScan v7.2.7 process-name canary.' -Details @{ actualNetworkScope = '127.0.0.1'; remoteTargets = $false }
}
