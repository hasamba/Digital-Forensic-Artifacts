function Invoke-RansomHubInitialAccessDiscovery {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-RansomHubTimeline

    $accounts = @('helpdesk', 'svc_backup', 'administrator', 'j.smith', 'finance', 'operations')
    $sprayEvents = @()
    for ($index = 0; $index -lt 24; $index++) {
        $sprayEvents += [ordered]@{
            TimeCreated = $time.SprayStart.AddMinutes($index * 10).ToString('o')
            EventId = 4625
            LogonType = 10
            IpAddress = if ($index % 2 -eq 0) { '185.190.24.54' } else { '185.190.24.33' }
            TargetUserName = $accounts[$index % $accounts.Count]
            Status = '0xC000006D'
            Note = 'Synthetic password-spray event; no authentication attempted.'
        }
    }
    foreach ($account in $accounts) {
        $sprayEvents += [ordered]@{ TimeCreated = $time.SprayEnd.AddMinutes(-8).ToString('o'); EventId = 4624; LogonType = 10; IpAddress = '185.190.24.54'; TargetUserName = $account; ElevatedToken = $false; Note = 'Synthetic success record only.' }
    }
    $sprayEvents += [ordered]@{ TimeCreated = $time.Day1.ToString('o'); EventId = 4624; LogonType = 10; IpAddress = '164.138.90.2'; TargetUserName = 'helpdesk'; ElevatedToken = $true; Note = 'Synthetic threat-actor initial session; source IP is metadata only.' }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'security-rdp-spray-and-logons.json') -Content ($sprayEvents | ConvertTo-Json -Depth 6) -Purpose 'four-hour password spray and valid-account RDP event canaries' -Timestamp $time.SprayStart
    foreach ($source in @('185.190.24.54', '185.190.24.33', '164.138.90.2')) { Invoke-RansomHubLoopbackPort -Port 3389 -ReportedTarget "$source -> exposed RDP server" }

    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    foreach ($command in @(
        'nslookup LAB-DOMAIN-CANARY',
        'net user /domain',
        'net group "domain admins" /domain',
        'net group "enterprise admins" /domain',
        'net accounts /domain',
        'nltest /domain_trusts',
        'ipconfig /all',
        'route print',
        'ping DC01.lab.invalid'
    )) { Invoke-RansomHubDecoyProcess -FilePath $cmd -ReportedCommandLine $command }

    $advancedScanner = Join-Path $Paths.DesktopRoot 'Advanced_IP_Scanner.exe'
    New-RansomHubBinaryDecoy -Path $advancedScanner -Role 'Advanced IP Scanner process-name canary' -ReportedSha256 'NOT-PUBLISHED-FOR-EXECUTABLE'
    Invoke-RansomHubDecoyProcess -FilePath $advancedScanner -ReportedCommandLine 'Advanced_IP_Scanner.exe /range LAB-SUBNET (actual scope 127.0.0.1 only)'

    $netscan = Join-Path $Paths.DesktopRoot 'netscan.exe'
    New-RansomHubBinaryDecoy -Path $netscan -Role 'SoftPerfect NetScan process-name canary' -ReportedSha256 'e14ba0fb92e16bb7db3b1efac4b13aee178542c6994543e7535d8efaa589870c'
    Invoke-RansomHubDecoyProcess -FilePath $netscan -ReportedCommandLine 'netscan.exe /range LAB-SUBNET /shares (actual scope 127.0.0.1 only)'
    foreach ($port in @(53, 80, 88, 135, 137, 139, 389, 443, 445, 464, 636, 1433, 3389, 5432, 5985, 8080)) {
        Invoke-RansomHubLoopbackPort -Port $port -ReportedTarget 'synthetic victim subnet'
    }
    foreach ($hostName in @('BACKUP01', 'FILE01', 'HV01', 'WS001')) {
        $share = Join-Path $Paths.SyntheticNet "$hostName\Share"
        New-Item -Path $share -ItemType Directory -Force | Out-Null
        $writeCheck = Join-Path $share 'delete.me'
        Set-Content -LiteralPath $writeCheck -Value 'NetScan local write-check canary' -Encoding ASCII
        Add-RansomHubManifestEntry -Type 'file' -Path $writeCheck -Action 'created-then-deleted' -Details @{ remoteShare = $false; purpose = 'local MFT/USN NetScan share-write cue' }
        Remove-Item -LiteralPath $writeCheck -Force
        Write-RansomHubEvidenceFile -Path (Join-Path $share 'delete.me.tombstone.json') -Content '{"name":"delete.me","action":"created-then-deleted","remote":false}' -Purpose 'portable NetScan write-check tombstone' -Timestamp $time.Day1.AddMinutes(58)
    }
    $scanResults = [ordered]@{
        actualScope = '127.0.0.1'
        reportedHosts = @('DC01', 'DC02', 'BACKUP01', 'FILE01', 'HV01', 'WS001')
        ports = @(53, 80, 88, 135, 137, 139, 389, 443, 445, 464, 636, 1433, 3389, 5432, 5985, 8080)
        remoteDnsQueries = $false
    }
    Write-RansomHubEvidenceFile -Path (Join-Path $Paths.Evidence 'netscan-results.json') -Content ($scanResults | ConvertTo-Json -Depth 5) -Purpose 'network map canary' -Timestamp $time.Day1.AddHours(1)

    Add-RansomHubTimelineEvent -Timestamp $time.SprayStart -Phase 'Initial Access' -Event 'Two public IPs conducted a four-hour RDP password spray against multiple accounts.' -Details @{ sourceIps = @('185.190.24.54', '185.190.24.33'); authenticationAttempted = $false; synthetic4625 = 24 }
    Add-RansomHubTimelineEvent -Timestamp $time.Day1 -Phase 'Initial Access' -Event 'Threat actor logged in from 164.138.90.2 using an elevated valid account.' -Details @{ realRdp = $false; elevatedTokenRecord = $true }
    Add-RansomHubTimelineEvent -Timestamp $time.Day1.AddMinutes(40) -Phase 'Discovery' -Event 'Living-off-the-land discovery, Advanced IP Scanner, and NetScan represented with escaped commands, signed decoys, and loopback scanning.' -Details @{ remoteSystemsContacted = $false; domainQueried = $false }
}
