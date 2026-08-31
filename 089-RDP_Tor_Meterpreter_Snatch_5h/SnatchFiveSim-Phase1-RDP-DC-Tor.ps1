#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SnatchFiveSim-utilities.ps1";Assert-S5Safety -LabConfirmed:$LabConfirmed;$p=Initialize-S5Environment
$entry=New-S5HostTree -Name 'ENTRY01-CANARY' -Role 'generated RDP entry host';$dc=New-S5HostTree -Name 'DC01-CANARY' -Role 'generated domain-controller representation';$shell=Join-Path $p.Payloads 'cmd.exe';$tor=Join-Path $p.Payloads 'WmiPrvSystemES.exe';$go=Join-Path $p.Payloads 'WmiPrvSystem.exe'
foreach($item in @(@($shell,'discovery shell stand-in',''),@($tor,'Tor RDP tunnel stand-in','0cd166b12f8d0f4b620a5819995bbcc2d15385117799fafbc76efd8c1e906662'),@($go,'unknown Go/uTorrent-like stand-in','97bc0e2add9be985aeb5c0b4ca654a6a9e6fca6a6bf712dc26fc454b773212b7'))){New-S5Decoy -Path $item[0] -Role $item[1] -PublishedSha256 $item[2]}
Write-S5Json -Path(Join-Path $p.Evidence 'rdp-entry.json')-Object([ordered]@{reportedSources=@('193.70.12.240','178.162.209.135');reportedAccount='Domain Administrator';generatedEntry=$entry;authenticationAttempts=0;bruteForceAttempts=0;validAccountsUsed=0;rdpSessions=0})-Purpose initial-access
foreach($command in @('arp -a','ipconfig','quser')){Invoke-S5Decoy -FilePath $shell -Reported $command -Parent 'reported RDP session' -Label 'SYNTHETIC-DISCOVERY'}
Invoke-S5Loopback -Port 3389 -Target '193.70.12.240 to entry host and entry host to DC' -Role 'RDP marker'
Invoke-S5Decoy -FilePath $tor -Reported 'WmiPrvSystemES.exe launched with .dat configuration to create a Tor RDP tunnel' -Parent 'RDP session on DC' -Label 'NO-TOR'
Invoke-S5Decoy -FilePath $go -Reported 'WmiPrvSystem.exe unknown Go executable with possible uTorrent capability' -Parent 'RDP session on DC' -Label 'NO-TUNNEL'
Write-S5File -Path(Join-Path $p.Payloads 'WmiPrvSystemES.dat')-Content 'INERT TOR-CONFIG NAME CANARY. No bridge, onion, proxy, RDP, or endpoint configuration.' -Purpose payload-canary
Write-S5Json -Path(Join-Path $p.Evidence 'dc-toolset.json')-Object([ordered]@{reportedPath='C:\Windows\wmis';reportedTools=@('WmiPrvSystemES.exe Tor RDP tunnel','WmiPrvSystem.exe unknown Go/uTorrent-like');generatedDc=$dc;torProcesses=0;tunnelsCreated=0;proxySessions=0;rdpSessions=0;remoteFilesWritten=0})-Purpose lateral-movement
Add-S5Timeline 0 initial-access '05:15 DA RDP login from 193.70.12.240 and arp -a represented' @{bruteForceAttempts=0;rdpSessions=0}
Add-S5Timeline 158 discovery '07:53 ipconfig and quser represented' @{networkQueries=0;sessionsEnumerated=0}
Add-S5Timeline 162 lateral-movement 'Minutes later, RDP to generated DC representation' @{authenticationAttempts=0;rdpSessions=0}
Add-S5Timeline 170 command-and-control 'Masqueraded Tor and Go executables in C:\Windows\wmis represented' @{torProcesses=0;tunnelsCreated=0}
Write-S5Json -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{authenticationAttempts=0;bruteForceAttempts=0;validAccountsUsed=0;rdpSessions=0;networkQueries=0;sessionsEnumerated=0;torProcesses=0;tunnelsCreated=0;proxySessions=0;remoteFilesWritten=0;externalConnections=0;bytesTransferred=0})-Purpose safety
