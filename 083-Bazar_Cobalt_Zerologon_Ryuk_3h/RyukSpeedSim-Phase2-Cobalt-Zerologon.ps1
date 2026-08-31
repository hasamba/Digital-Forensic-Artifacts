#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukSpeedSim-utilities.ps1"
Assert-RSSafety -LabConfirmed:$LabConfirmed
$p = Initialize-RSEnvironment

$adfind = Join-Path $p.Payloads 'AdFind.exe'
$pl64 = Join-Path $p.Payloads 'PL64.exe'
$rubeus = Join-Path $p.Payloads 'Rubeus.exe'
$servicePayload = Join-Path $p.Payloads 'ff49429.exe'
New-RSDecoy -Path $adfind -Role 'AdFind stand-in' -PublishedSha256 '68d0f5659cf3cc1cf53519e1be482ca9a63f2deebdcd2cb7ee12515adc6db0a7'
New-RSDecoy -Path $pl64 -Role 'Cobalt Strike beacon stand-in' -PublishedSha256 'a7514209db9d9c7c51927308d4f0b491464e11391af3c6ae31cb87d91fac995d'
New-RSDecoy -Path $rubeus -Role 'Rubeus Kerberoast stand-in'
New-RSDecoy -Path $servicePayload -Role 'remote-service beacon stand-in'

$adfindCommands = @(
    'AdFind.exe -f "(objectcategory=person)"',
    'AdFind.exe -f "(objectcategory=computer)"',
    'AdFind.exe -f "(objectcategory=organizationalUnit)"',
    'AdFind.exe -sc trustdmp',
    'AdFind.exe -subnets -f "(objectCategory=subnet)"',
    'AdFind.exe -f "(objectcategory=group)"',
    'AdFind.exe -gcb -sc trustdmp'
)
foreach ($command in $adfindCommands) { Invoke-RSDecoy -FilePath $adfind -Reported "echo $command | cmd.exe" -Parent 'Cobalt Strike beacon' -Label 'SYNTHETIC-ADFIND' }
Write-RSJson -Path (Join-Path $p.Staging 'adfind-output.json') -Object ([ordered]@{domain='LAB-CANARY.LOCAL';people=@('canary.operator');computers=@('DC01-CANARY','DC02-CANARY','BAK01-CANARY','FS01-CANARY');organizationalUnits=@('OU=GeneratedHosts,DC=LAB-CANARY,DC=LOCAL');trusts=@();subnets=@('192.0.2.0/24');groups=@('DFIR-Canary-Operators');synthetic=$true}) -Purpose synthetic-discovery-output
Write-RSJson -Path (Join-Path $p.Evidence 'adfind-execution.json') -Object ([ordered]@{reportedCommands=$adfindCommands;executionStyle='commands piped individually; no adf.bat observed';actualDirectoryQueries=0;syntheticOutput=(Join-Path $p.Staging 'adfind-output.json')}) -Purpose discovery

Write-RSJson -Path (Join-Path $p.Evidence 'zerologon-marker.json') -Object ([ordered]@{cve='CVE-2020-1472';reportedOutcome='domain administrator privileges';machineAccountsContacted=0;authenticationAttempts=0;passwordResets=0;directoryChanges=0;exploitCodePresent=$false}) -Purpose privilege-escalation
Invoke-RSDecoy -FilePath $rubeus -Reported 'Rubeus kerberoast /outfile:kerberoast.txt' -Parent 'Cobalt Strike beacon' -Label 'SYNTHETIC-KERBEROAST'
Write-RSJson -Path (Join-Path $p.Staging 'kerberoast.txt.json') -Object ([ordered]@{reportedTool='Rubeus';operation='Kerberoast';ticketsRequested=0;credentialsOrHashesCollected=0;content='SYNTHETIC ONLY'}) -Purpose synthetic-credential-output
Write-RSJson -Path (Join-Path $p.Evidence 'injection-marker.json') -Object ([ordered]@{reportedBehavior='Cobalt Strike process injection into svchost.exe after Zerologon';processesOpened=0;memoryWritten=0;threadsCreated=0;injectionOccurred=$false}) -Purpose defense-evasion

$dc1 = New-RSHostTree -Name 'DC01-CANARY' -Role 'generated domain controller representation'
$dc2 = New-RSHostTree -Name 'DC02-CANARY' -Role 'generated domain controller representation'
Invoke-RSDecoy -FilePath $pl64 -Reported 'Cobalt executable deployed through RDP to DC01-CANARY and DC02-CANARY' -Parent 'mstsc.exe' -Label 'SYNTHETIC-RDP-BEACON'
Invoke-RSDecoy -FilePath $servicePayload -Reported '\\HOSTNAME\ADMIN$\ff49429.exe installed as remote service ff49429' -Parent 'services.exe on remote host' -Label 'SYNTHETIC-SERVICE'
Write-RSJson -Path (Join-Path $p.Evidence 'lateral-movement.json') -Object ([ordered]@{reportedRdpTargets=@('two domain controllers');generatedTargets=@($dc1,$dc2);reportedSmbPath='\\HOSTNAME\ADMIN$\ff49429.exe';reportedService='ff49429';reportedPowerShell='Active Directory module used on domain controller';rdpSessions=0;smbSessions=0;remoteFilesWritten=0;servicesCreated=0;PowerShellExecuted=$false}) -Purpose lateral-movement
Invoke-RSLoopback -Port 443 -Target 'topservicebooster.com (108.62.12.121)' -Role 'second Cobalt Strike C2 marker'
Invoke-RSLoopback -Port 3389 -Target 'DC01-CANARY and DC02-CANARY' -Role 'RDP movement marker'
Invoke-RSLoopback -Port 445 -Target '\\HOSTNAME\ADMIN$\ff49429.exe' -Role 'SMB and SVCCTL marker'
Invoke-RSLoopback -Port 21 -Target '5.2.70.149:21' -Role 'AdFind and Rubeus output exfiltration marker'
Write-RSJson -Path (Join-Path $p.Evidence 'ftp-exfiltration.json') -Object ([ordered]@{reportedTarget='5.2.70.149:21';reportedData=@('AdFind output','Rubeus output');sourceFilesSynthetic=$true;ftpSessions=0;bytesTransferred=0;externalConnections=0}) -Purpose exfiltration
Add-RSTimeline -Minutes 20 -Phase discovery -Event 'AdFind commands represented seven minutes after Cobalt beacon activity' -Details @{directoryQueries=0;syntheticOutput=$true}
Add-RSTimeline -Minutes 40 -Phase privilege-escalation -Event 'Zerologon CVE-2020-1472 domain-admin outcome represented' -Details @{exploitAttempts=0;passwordResets=0;directoryChanges=0}
Add-RSTimeline -Minutes 60 -Phase credential-access -Event 'Rubeus Kerberoast and svchost injection represented' -Details @{ticketsRequested=0;credentialMaterial=0;injectionOccurred=$false}
Add-RSTimeline -Minutes 75 -Phase command-and-control -Event 'Second Cobalt C2 channel represented' -Details @{externalConnections=0;bytesTransferred=0}
Add-RSTimeline -Minutes 90 -Phase lateral-movement -Event 'RDP to two generated DC representations and beacon deployment represented' -Details @{rdpSessions=0;remoteFilesWritten=0}
Add-RSTimeline -Minutes 110 -Phase exfiltration -Event 'AdFind and Rubeus output transfer over FTP represented' -Details @{ftpSessions=0;bytesTransferred=0}
Write-RSJson -Path (Join-Path $p.Evidence 'phase2-negative.json') -Object ([ordered]@{ZerologonAttempts=0;machinePasswordResets=0;ticketsRequested=0;credentialsOrHashesCollected=0;processInjection=0;remoteSessions=0;remoteFilesWritten=0;servicesCreated=0;PowerShellExecuted=$false;externalConnections=0;bytesTransferred=0}) -Purpose safety
