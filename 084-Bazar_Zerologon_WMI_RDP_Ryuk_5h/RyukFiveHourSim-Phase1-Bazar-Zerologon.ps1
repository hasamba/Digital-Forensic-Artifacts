#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukFiveHourSim-utilities.ps1"
Assert-R5Safety -LabConfirmed:$LabConfirmed
$p = Initialize-R5Environment

Write-R5Json -Path (Join-Path $p.Evidence 'phishing-lure.json') -Object ([ordered]@{delivery='phishing email';payload='Report_Print.exe';userContext='Domain User with no additional permissions';linksOpened=0;downloads=0;liveMalware=$false}) -Purpose initial-access
$bazar = Join-Path $p.Payloads 'Report_Print.exe'
$shell = Join-Path $p.Payloads 'bazar-shell.exe'
New-R5Decoy -Path $bazar -Role 'Bazar Loader stand-in' -PublishedSha256 '23ac461f9b5128841cafabb4282432252ea7b57874595cf6fe8457fc1ac65007'
New-R5Decoy -Path $shell -Role 'Bazar command-shell stand-in'
Invoke-R5Decoy -FilePath $bazar -Reported 'Report_Print.exe executed by a low-privileged Domain User after phishing delivery' -Parent 'explorer.exe'
Write-R5Json -Path (Join-Path $p.Evidence 'bazar-injection-marker.json') -Object ([ordered]@{reportedTargets=@('explorer.exe','svchost.exe');processesOpened=0;memoryWritten=0;threadsCreated=0;injectionOccurred=$false;reportedShellSpawning=$true}) -Purpose defense-evasion
$commands = @('nltest /domain_trusts /all_trusts','nltest /dclist:DOMAIN','net group "Domain admins" /DOMAIN')
foreach ($command in $commands) { Invoke-R5Decoy -FilePath $shell -Reported $command -Parent 'Report_Print.exe' -Label 'SYNTHETIC-DISCOVERY' }
Write-R5Json -Path (Join-Path $p.Evidence 'beachhead-discovery.json') -Object ([ordered]@{reportedCommands=$commands;domainQueries=0;trustQueries=0;accountQueries=0;results='generated metadata only'}) -Purpose discovery
Invoke-R5Loopback -Port 443 -Target 'cstr3.com (3.137.182.114)' -Role 'Bazar C2 marker'
Write-R5Json -Path (Join-Path $p.Evidence 'zerologon-marker.json') -Object ([ordered]@{cve='CVE-2020-1472';reportedTarget='primary domain controller';reportedAction='reset machine password using all-zero value';reportedConsequence='services may have broken, leading actor to target the other DC';domainControllersContacted=0;authenticationAttempts=0;machinePasswordsReset=0;directoryChanges=0;exploitCodePresent=$false}) -Purpose privilege-escalation
Add-R5Timeline -Minutes 0 -Phase initial-access -Event 'Phishing delivery and low-privileged Bazar Loader execution represented' -Details @{downloads=0;liveMalware=$false}
Add-R5Timeline -Minutes 15 -Phase defense-evasion -Event 'Bazar explorer/svchost injection and shell spawning represented' -Details @{injectionOccurred=$false}
Add-R5Timeline -Minutes 35 -Phase discovery -Event 'Beachhead trust, DC, and Domain Admin discovery represented' -Details @{actualQueries=0}
Add-R5Timeline -Minutes 105 -Phase privilege-escalation -Event 'Zerologon password reset represented before the two-hour mark' -Details @{authenticationAttempts=0;machinePasswordsReset=0;directoryChanges=0}
Write-R5Json -Path (Join-Path $p.Evidence 'phase1-negative.json') -Object ([ordered]@{liveMalware=0;downloads=0;processInjection=0;domainQueries=0;externalConnections=0;bytesTransferred=0;ZerologonAttempts=0;machinePasswordsReset=0;credentialMaterial=0;directoryChanges=0}) -Purpose safety
