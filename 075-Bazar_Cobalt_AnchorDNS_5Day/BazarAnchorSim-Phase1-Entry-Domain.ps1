#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarAnchorSim-utilities.ps1"
Assert-BASafety -LabConfirmed:$LabConfirmed
$paths = Initialize-BAEnvironment

Write-BAFile (Join-Path $paths.Payloads 'request_form_1612805504.xls') 'INERT DOCUSIGN XLS-NAME CANARY. Plain text; no Excel structure, formula, macro, or code.' lure
$loader = Join-Path $paths.Payloads '14wfa5dfs.exe'
$werfault = Join-Path $paths.Payloads 'WerFault.exe'
$cobalt = Join-Path $paths.Payloads '~tmp01925d3f.exe'
$adjuster = Join-Path $paths.Payloads 'anchorAsjuster_x64.exe'
$anchorDns = Join-Path $paths.Payloads 'anchorDNS_x64.exe'
$anchor = Join-Path $paths.Payloads 'anchor_x64.exe'
New-BADecoy $loader 'manually executed Bazar Loader stand-in' '2065157b834e1116abdd5d67167c77c6348361e04a8085aa382909500f1bbe69'
New-BADecoy $werfault 'Bazar-injected WerFault stand-in'
New-BADecoy $cobalt 'Cobalt Beacon stand-in' '10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63'
New-BADecoy $adjuster 'Anchor adjuster stand-in' '3ab8a1ee10bd1b720e1c8a8795e78cdc09fec73a6bb91526c0ccd2dc2cfbc28d'
New-BADecoy $anchorDns 'AnchorDNS stand-in' '9fdbd76141ec43b6867f091a2dca503edb2a85e4b98a4500611f5fe484109513'
New-BADecoy $anchor 'Anchor stand-in' 'ca72600f50c76029b6fb71f65423afc44e4e2d93257c3f95fb994adc602f3e1b'
Invoke-BADecoy $loader 'User manually executes 14wfa5dfs.exe after XLS retrieval fails' 'explorer.exe'
Invoke-BADecoy $werfault 'Bazar Loader injects into WerFault.exe for C2' '14wfa5dfs.exe'
Invoke-BADecoy $cobalt '~tmp01925d3f.exe Cobalt Beacon launched by injected WerFault about one hour later' 'WerFault.exe'
Invoke-BADecoy $adjuster 'cmd.exe /C C:\Windows\Temp\adf\anchorAsjuster_x64.exe --source=anchorDNS_x64.exe --target=anchor_x64.exe --domain=xyskencevli.com,sluaknhbsoe.com --period=2 --lasthope=2 -guid' 'Cobalt Strike'
Invoke-BADecoy $anchorDns 'anchorDNS_x64.exe performs DNS C2' 'anchorAsjuster_x64.exe'
Invoke-BADecoy $anchor 'anchor_x64.exe uses adjusted Anchor configuration' 'anchorAsjuster_x64.exe'

$commands = @('net view /all','net view /all /domain','nltest.exe /domain_trusts /all_trusts','net localgroup "administrator"','net group "domain admins" /domain','systeminfo','whoami','reg query hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /v "DisplayName" /s','reg query hklm\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall /v "DisplayName" /s','reg query hkcu\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /v "DisplayName" /s','reg query hkcu\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall /v "DisplayName" /s','net group "enterprise admins" /domain')
foreach ($command in $commands) { Invoke-BADecoy $werfault $command 'Bazar or Cobalt Beacon' }
Write-BAFile (Join-Path $paths.Evidence 'early-discovery.json') (@{reportedCommands=$commands;reportTiming='within 10 minutes';commandsActuallyRun=@('/d /v:off /c echo BAZAR-ANCHOR-CANARY');discoveryPerformed=$false} | ConvertTo-Json -Depth 6) discovery

foreach ($hostName in @('BEACHHEAD-01','DC-CANARY-01','FILE-CANARY-01','APP-CANARY-01')) { Write-BAFile (Join-Path $paths.Hosts "$hostName\host-role.txt") "GENERATED HOST CANARY: $hostName. Local directory only; not a remote system." generated-host }
Write-BAFile (Join-Path $paths.Evidence 'dc-discovery-movement.json') (@{
    reportedCommands=@('nltest /dclist:DOMAIN.EXAMPLE','nltest /domain_trusts /all_trusts','IEX loopback cradle; Get-NetSubnet','IEX loopback cradle; Get-NetComputer -ping','Import-Module ActiveDirectory; Get-ADComputer -Filter enabled; select DNSHostName IPv4Address OperatingSystem LastLogonDate','ping HOSTX')
    reportedMovement=@('PowerShell via remote service to domain controller','SMB Beacons via remote services across most domain machines','RDP to multiple machines')
    realDomainControllersTouched=0;PowerShellExecuted=$false;servicesCreated=0;smbSessions=0;rdpSessions=0;remoteHostsTouched=0
} | ConvertTo-Json -Depth 6) movement
Write-BAFile (Join-Path $paths.Evidence 'injection-credentials.json') (@{reportedInjectionTargets=@('WerFault.exe','winlogon.exe','lsass.exe via remote thread');processesInjected=0;LSASSAccessed=$false;credentialsAccessed=0;processTampering=0;smbBeaconLocks=0} | ConvertTo-Json) safety
foreach ($target in @('34.210.71.206:443','195.123.217.45:80','gloomix.com:443','xyskencevli.com:53','sluaknhbsoe.com:53')) { $port=[int]($target.Split(':')[-1]);Invoke-BALoopback $port $target 'Bazar, Cobalt, or AnchorDNS C2 marker' }
foreach ($port in @(445,3389)) { Invoke-BALoopback $port "generated movement port $port" 'movement marker' }
Write-BAFile (Join-Path $paths.Evidence 'phase1-negative.json') (@{malwarePresent=$false;documentsOpened=0;macrosExecuted=0;downloads=0;processesInjected=0;externalConnections=0;dnsQueries=0;discoveryCommandsRun=0;realDomainControllersTouched=0;servicesCreated=0;smbSessions=0;rdpSessions=0;LSASSAccessed=$false;credentialsAccessed=0} | ConvertTo-Json) safety
Add-BATimeline 0 initial-access 'DocuSign XLS opened; macro retrieval failed; follow-on Bazar Loader manually executed' @{downloads=0;macrosExecuted=0}
Add-BATimeline 0.17 discovery 'Bazar discovery burst occurs within ten minutes' @{commandsRun=0}
Add-BATimeline 1 command-and-control 'WerFault-hosted Bazar loads Cobalt, followed shortly by AnchorDNS' @{externalConnections=0;dnsQueries=0}
Add-BATimeline 1.2 credential-access 'Remote-thread LSASS credential extraction represented' @{LSASSAccessed=$false;credentialsAccessed=0}
Add-BATimeline 2 lateral-movement 'PowerShell/remote-service movement starts with a domain controller; SMB and RDP routes follow' @{remoteHostsTouched=0}
