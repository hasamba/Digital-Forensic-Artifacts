function Invoke-LynxPersistenceAndLateralMovement {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-LynxTimeline
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'

    $directoryObjects = [ordered]@{
        disclaimer = 'Synthetic directory records only. No AD cmdlet, domain, GPO, or remote system is modified.'
        accounts = @(
            [ordered]@{ samAccountName = 'administratr'; mimics = 'administrator'; userAccountControl = @('NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD'); memberOf = @('Domain Admins', 'Group Policy Creator Owners') },
            [ordered]@{ samAccountName = 'svc-backupl'; mimics = 'svc-backup1'; userAccountControl = @('NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD'); memberOf = @('Domain Admins') },
            [ordered]@{ samAccountName = 'hv-adminl'; mimics = 'hv-admin1'; userAccountControl = @('NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD'); memberOf = @('LAB-Hypervisor-Admins') }
        )
    }
    Write-LynxEvidenceFile -Path (Join-Path $Paths.SyntheticAD 'directory-objects.json') -Content ($directoryObjects | ConvertTo-Json -Depth 7) -Purpose 'look-alike privileged domain-account canaries' -Timestamp $time.Day1.AddMinutes(24)

    foreach ($reportedCommand in @(
        'net user administratr LabOnly-Canary-2025 /add /domain',
        'net group "Domain Admins" administratr /add /domain',
        'net group "Group Policy Creator Owners" administratr /add /domain',
        'net user svc-backupl LabOnly-Canary-2025 /add /domain',
        'net group "Domain Admins" svc-backupl /add /domain'
    )) {
        Invoke-LynxDecoyProcess -FilePath $cmd -ReportedCommandLine $reportedCommand
    }

    $anyDeskDirectory = Join-Path $Paths.Profile 'DC01\ProgramData\AnyDesk'
    $anyDeskPath = Join-Path $anyDeskDirectory 'AnyDesk.exe'
    New-LynxCommandDecoy -Path $anyDeskPath -ReportedSha256 'NOT-PUBLISHED-IN-REPORT' -Role 'AnyDesk service-install process-name canary'
    Invoke-LynxDecoyProcess -FilePath $anyDeskPath -ReportedCommandLine 'AnyDesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win --silent'
    $serviceRecord = [ordered]@{
        ServiceName = 'AnyDesk'
        ImagePath = 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe --service'
        StartType = 'Automatic'
        State = 'Synthetic - service not installed'
        RemoteAccessEnabled = $false
    } | ConvertTo-Json -Depth 4
    Write-LynxEvidenceFile -Path (Join-Path $anyDeskDirectory 'service-install-canary.json') -Content $serviceRecord -Purpose 'AnyDesk persistence evidence without installing a service' -Timestamp $time.Day1.AddMinutes(36)

    foreach ($target in @('DC01', 'HV01', 'HV02')) {
        Invoke-LynxRdpLoopback -ReportedTarget $target -ReportedAccount 'LAB\administratr'
    }

    $followUpRdp = @(
        [ordered]@{ TimeCreated = $time.Day8.ToString('o'); EventId = 4624; LogonType = 3; IpAddress = '77.90.153.30'; WorkstationName = 'DESKTOP-BUL6K1U'; Account = 'LAB\administratr'; Note = 'Synthetic event record; source IP is metadata only.' },
        [ordered]@{ TimeCreated = $time.Day8.AddSeconds(6).ToString('o'); EventId = 4624; LogonType = 10; IpAddress = '77.90.153.30'; WorkstationName = 'DESKTOP-BUL6K1U'; Account = 'LAB\administratr'; Note = 'Synthetic follow-up RDP record; no external logon occurred.' }
    )
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Evidence 'security-4624-rdp-followup-canary.json') -Content ($followUpRdp | ConvertTo-Json -Depth 5) -Purpose 'reported day-eight RDP evidence represented without a real external logon' -Timestamp $time.Day8

    Invoke-LynxNativeCommand -FilePath 'reg.exe' -ArgumentList @('query', 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters') -Label 'Hyper-V hostname discovery query'

    $nxcPath = Join-Path $Paths.Desktop000 'nxc.exe'
    New-LynxCommandDecoy -Path $nxcPath -ReportedSha256 '6285d32a9491a0084da85a384a11e15e203badf67b1deed54155f02b7338b108' -Role 'NetExec process-name and command-line canary'
    Invoke-LynxDecoyProcess -FilePath $nxcPath -ReportedCommandLine 'nxc.exe smb 127.0.0.1/32 -u LAB\administratr -p LabOnly-Canary-2025'
    Invoke-LynxLoopbackPortAttempt -Port 445 -ReportedTarget 'victim /24 range (metadata only)'

    $nxcWorkspace = Join-Path $Paths.Profile '.nxc\workspaces'
    $nxcConfig = @'
[nxc]
workspace = default
last_used_db = smb
pwn3d_label = Pwn3d!
audit_mode = True
reveal_chars_of_pwd = 0
log_mode = False
ignore_opsec = False
[BloodHound]
bh_enabled = False
bh_uri = 127.0.0.1
bh_port = 7687
[Safety]
actual_smb_scope = 127.0.0.1/32
real_credentials = False
remote_modules = False
'@
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Profile '.nxc\nxc.conf') -Content $nxcConfig -Purpose 'NetExec configuration artifact constrained to loopback' -Timestamp $time.Day6.AddMinutes(21)
    $smbDbCanary = @'
SQLite format 3 CANARY
workspace=default
protocol=smb
actual_host=127.0.0.1
reported_hosts=DC01,DC02,FILE01,FILE02
credentials=LAB-CANARY-NOT-REAL
'@
    Write-LynxEvidenceFile -Path (Join-Path $nxcWorkspace 'smb.db') -Content $smbDbCanary -Purpose 'SQLite-shaped NetExec result canary; not a functional credential database' -Timestamp $time.Day6.AddMinutes(23)
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Desktop000 'nxc.txt') -Content 'NetExec canary results: 127.0.0.1 only. Reported victim hosts retained in scenario metadata.' -Purpose 'manual NetExec output review artifact' -Timestamp $time.Day6.AddMinutes(25)

    $secpolPath = Join-Path $Paths.Evidence 'secpol.cfg'
    Invoke-LynxNativeCommand -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', $secpolPath, '/quiet') -Label 'read-only local security policy export'
    if (Test-Path -LiteralPath $secpolPath) {
        Add-LynxManifestEntry -Type 'file' -Path $secpolPath -Action 'created-by-secedit-export' -Details @{ localOnly = $true; modifiedPolicy = $false }
        Set-LynxArtifactTime -Path $secpolPath -Timestamp $time.Day8.AddMinutes(16)
    }

    Add-LynxTimelineEvent -Timestamp $time.Day1.AddMinutes(10) -Phase 'Lateral Movement' -Event 'RDP pivot to DC represented by mstsc loopback attempt.' -Details @{ intendedTarget = 'DC01'; actualTarget = '127.0.0.1'; credentials = 'canary only' }
    Add-LynxTimelineEvent -Timestamp $time.Day1.AddMinutes(24) -Phase 'Persistence' -Event 'Three look-alike directory accounts and privileged memberships represented as JSON and inert command lines.' -Details @{ domainModified = $false; groupModified = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day1.AddMinutes(36) -Phase 'Persistence' -Event 'AnyDesk installation represented by a signed command decoy and service record.' -Details @{ serviceInstalled = $false; remoteAccess = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day2 -Phase 'Privilege Validation' -Event 'Look-alike privileged account logons to hypervisor targets represented through loopback RDP attempts.' -Details @{ accounts = @('administratr', 'svc-backupl', 'hv-adminl'); actualTargets = '127.0.0.1 only'; remoteAuthentication = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day6.AddMinutes(20) -Phase 'Discovery' -Event 'NetExec SMB enumeration represented by nxc.exe decoy, loopback port attempt, config, and database-shaped artifacts.' -Details @{ actualScope = '127.0.0.1/32'; passwordSpray = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day8 -Phase 'Return Activity' -Event 'Second reported RDP source and local policy/hypervisor discovery artifacts.' -Details @{ sourceIpIoc = '77.90.153.30'; workstation = 'DESKTOP-BUL6K1U'; realExternalRdp = $false }
}
