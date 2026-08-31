#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukSpeedSim-utilities.ps1"
Assert-RSSafety -LabConfirmed:$LabConfirmed
$p = Initialize-RSEnvironment

Write-RSJson -Path (Join-Path $p.Landing 'google-drive-lure.json') -Object ([ordered]@{delivery='phishing email link';reportedService='Google Docs / Google Drive';downloadName='Report-Review20-10.exe';linksOpened=0;downloads=0;externalConnections=0}) -Purpose initial-access
$loader = Join-Path $p.Payloads 'Report-Review20-10.exe.exe'
$firefox = Join-Path $p.Payloads 'Firefox.exe'
$pagefile = Join-Path $p.Payloads 'pagefilerpqy.exe'
New-RSDecoy -Path $loader -Role 'Bazar Loader stand-in' -PublishedSha256 '0d468fc1b02bbc7c3050c67e0a80b580c69abd8eea5f8dad06c7d7ff396f7789'
New-RSDecoy -Path $firefox -Role 'Bazar persistence component stand-in' -PublishedSha256 '3fc65b7e7967353f340ead51617558a23f14447ab91d974268f53ab0c17052e0'
New-RSDecoy -Path $pagefile -Role 'Bazar scheduled component stand-in' -PublishedSha256 'a4468c28e4830acf526209c0da25536ff0f682a0239ced1983a08d1ddd476963'
Write-RSFile -Path (Join-Path $p.Payloads 'pagefileU6Gl.sys') -Content 'INERT DRIVER-NAME CANARY. No PE or driver content.' -Purpose payload-canary
Write-RSFile -Path (Join-Path $p.Payloads 'pagefilerpqy.sys') -Content 'INERT DRIVER-NAME CANARY. No PE or driver content.' -Purpose payload-canary
Invoke-RSDecoy -FilePath $loader -Reported 'Report-Review20-10.exe launched by the user from the browser download path' -Parent 'explorer.exe'
Invoke-RSDecoy -FilePath $firefox -Reported 'Firefox.exe launched by Bazar Loader and created persistence' -Parent 'Report-Review20-10.exe'

$tasks = @(
    [ordered]@{name='jf0c';trigger='ONSTART';action='pagefilerpqy.exe';runLevel='normal and highest variants'},
    [ordered]@{name='9T6ukfi6';trigger='ONCE at 17:21:58';action='pagefilerpqy.exe';runLevel='normal and highest variants'}
)
Write-RSJson -Path (Join-Path $p.Evidence 'persistence-markers.json') -Object ([ordered]@{reportedTasks=$tasks;reportedRunKey=[ordered]@{hive='HKCU';path='Software\Microsoft\Windows\CurrentVersion\Run';name='microsoft update';command='SCHTASKS /run /tn 9T6ukfi6'};tasksCreated=0;registryValuesWritten=0}) -Purpose persistence

$reconCommands = @('net view /all','net view /all /domain','nltest /domain_trusts /all_trusts','net localgroup "administrator"','net group "domain admins" /dom')
foreach ($command in $reconCommands) { Invoke-RSDecoy -FilePath $pagefile -Reported $command -Parent 'pagefilerpqy.exe' -Label 'SYNTHETIC-RECON' }
Write-RSJson -Path (Join-Path $p.Evidence 'bazar-recon.json') -Object ([ordered]@{reportedCommands=$reconCommands;actualDomainQueries=0;actualTrustQueries=0;actualAccountQueries=0;results='generated metadata only'}) -Purpose discovery

Invoke-RSLoopback -Port 443 -Target 'dghns.xyz (34.222.33.48)' -Role 'Bazar C2 marker'
Invoke-RSLoopback -Port 80 -Target 'http://chaseltd.top/gate.php (161.117.191.245)' -Role 'pagefilerpqy C2 marker'
Invoke-RSLoopback -Port 443 -Target 'checktodrivers.com (45.153.240.240)' -Role 'suspected Cobalt Strike C2 marker'
Add-RSTimeline -Minutes 0 -Phase initial-access -Event 'Phishing link and Google Drive Bazar Loader download represented' -Details @{linksOpened=0;downloads=0}
Add-RSTimeline -Minutes 2 -Phase execution -Event 'Report-Review20-10 Bazar Loader and Firefox components represented' -Details @{liveMalware=$false;signedCmdDecoys=2}
Add-RSTimeline -Minutes 5 -Phase discovery -Event 'Domain, trust, administrator, and Domain Admin reconnaissance represented' -Details @{actualQueries=0}
Add-RSTimeline -Minutes 10 -Phase command-and-control -Event 'First Cobalt beacon and Bazar C2 channels represented' -Details @{externalConnections=0;bytesTransferred=0}
Add-RSTimeline -Minutes 17 -Phase persistence -Event 'Two scheduled tasks and HKCU Run key represented' -Details @{tasksCreated=0;registryValuesWritten=0}
Write-RSJson -Path (Join-Path $p.Evidence 'phase1-negative.json') -Object ([ordered]@{liveMalware=0;linksOpened=0;downloads=0;externalConnections=0;bytesTransferred=0;tasksCreated=0;registryValuesWritten=0;domainQueries=0;credentialAccess=0}) -Purpose safety
