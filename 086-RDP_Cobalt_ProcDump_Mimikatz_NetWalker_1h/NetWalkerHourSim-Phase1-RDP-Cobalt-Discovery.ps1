#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\NetWalkerHourSim-utilities.ps1";Assert-NWSafety -LabConfirmed:$LabConfirmed;$p=Initialize-NWEnvironment
$rdpSources=@('184.58.243.205','173.239.199.73','176.126.85.39','198.181.163.103','141.98.81.191','93.179.69.154','173.232.146.37')
Write-NWJson -Path(Join-Path $p.Evidence 'rdp-entry.json')-Object([ordered]@{reportedLikelySource='198.181.163.103';allReportedLoginIps=$rdpSources;reportedAccount='DomainName\Administrator';authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0})-Purpose initial-access
Invoke-NWLoopback -Port 3389 -Target '198.181.163.103 to honeypot RDP' -Role 'initial RDP marker'
$ps=Join-Path $p.Payloads 'c37.ps1';$exe=Join-Path $p.Payloads 'c37.exe';$adfind=Join-Path $p.Payloads 'AdFind.exe';$shell=Join-Path $p.Payloads 'cmd.exe'
Write-NWFile -Path $ps -Content '# INERT C37.PS1-NAME CANARY. No obfuscation, Cobalt Strike, Windshield, SplinterRAT, or network logic.' -Purpose payload-canary
foreach($pair in @(@($exe,'Cobalt/Neshta shared-code sample stand-in','4f7dd00a005caf046dd7e494fea25be2264974264d567edfc89122242b7c41bc'),@($adfind,'AdFind stand-in',''),@($shell,'command-shell telemetry stand-in',''))){New-NWDecoy -Path $pair[0] -Role $pair[1] -PublishedSha256 $pair[2]}
Invoke-NWDecoy -FilePath $shell -Reported 'powershell.exe -File c37.ps1' -Parent 'RDP user session' -Label 'NO-POWERSHELL'
Invoke-NWDecoy -FilePath $exe -Reported 'c37.exe copied itself to a temp directory and stopped' -Parent 'RDP user session' -Label 'SYNTHETIC-COBALT'
Invoke-NWLoopback -Port 443 -Target '173.232.146.37' -Role 'Cobalt Strike default-certificate C2 marker'
Write-NWFile -Path(Join-Path $p.Payloads 'adf.bat')-Content 'INERT ADF.BAT-NAME CANARY. No directory query commands.' -Purpose payload-canary
Write-NWFile -Path(Join-Path $p.Payloads 'pcr.bat')-Content 'INERT PCR.BAT-NAME CANARY. No ping loop or host probing.' -Purpose payload-canary
$commands=@('nltest /dclist:','net group "Domain Computers" /DOMAIN','net groups "Enterprise Admins" /domain','net user Administrator')
Invoke-NWDecoy -FilePath $adfind -Reported 'AdFind.exe executed by adf.bat; output domains.txt and text files opened' -Parent 'adf.bat' -Label 'SYNTHETIC-ADFIND'
foreach($command in $commands){Invoke-NWDecoy -FilePath $shell -Reported $command -Parent 'manually typed command prompt' -Label 'SYNTHETIC-DISCOVERY'}
Write-NWFile -Path(Join-Path $p.Staging 'domains.txt')-Content "DC01-CANARY`nFS01-CANARY`nWS01-CANARY" -Purpose synthetic-discovery-output
Write-NWFile -Path(Join-Path $p.Staging 'ips.log')-Content "DC01-CANARY,192.0.2.10,synthetic-no-ping`nFS01-CANARY,192.0.2.20,synthetic-no-ping" -Purpose synthetic-ping-output
Write-NWJson -Path(Join-Path $p.Evidence 'discovery.json')-Object([ordered]@{reportedCommands=$commands;reportedFilesOpened=@('AdFind text outputs','domains.txt','ips.log');reportedPcrBehavior='ping -n 1 -4 hostnames from domains.txt';directoryQueries=0;pingPackets=0;hostsContacted=0;syntheticOutputs=$true})-Purpose discovery
Add-NWTimeline 0 initial-access 'Likely VPN-origin RDP login with Domain Administrator represented' @{authenticationAttempts=0;rdpSessions=0}
Add-NWTimeline 16 command-and-control 'c37.ps1 Cobalt-like script represented at minute 16' @{PowerShellExecuted=$false;externalConnections=0}
Add-NWTimeline 20 command-and-control 'c37.exe temp-copy behavior and confirmed Cobalt endpoint represented' @{filesCopied=0;externalConnections=0}
Add-NWTimeline 25 discovery 'AdFind, manual Net/Nltest, domains.txt, and pcr.bat discovery represented' @{actualQueries=0;pingPackets=0}
Write-NWJson -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0;PowerShellExecuted=$false;liveMalware=0;filesCopied=0;directoryQueries=0;pingPackets=0;externalConnections=0;bytesTransferred=0})-Purpose safety
