#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukReturnSim-utilities.ps1"
Assert-RRSafety -LabConfirmed:$LabConfirmed;$p=Initialize-RREnvironment
Write-RRJson -Path(Join-Path $p.Evidence 'malspam-lure.json')-Object([ordered]@{delivery='email link';payload='Document-Preview.exe';linksOpened=0;downloads=0;liveMalware=$false})-Purpose initial-access
$bazar=Join-Path $p.Payloads 'Document-Preview.exe';$shell=Join-Path $p.Payloads 'bazar-shell.exe';$adfind=Join-Path $p.Payloads 'AdFind.exe'
New-RRDecoy -Path $bazar -Role 'Bazar/Kegtap stand-in' -PublishedSha256 '85ef348d39610c1d5f58e2524c0e929ec815a9fbe1f5924cdef7a0c05e58e5ad'
New-RRDecoy -Path $shell -Role 'Bazar command-shell stand-in'
New-RRDecoy -Path $adfind -Role 'AdFind stand-in'
Invoke-RRDecoy -FilePath $bazar -Reported 'Document-Preview.exe executed after the malspam link' -Parent 'explorer.exe'
Write-RRJson -Path(Join-Path $p.Evidence 'injection-marker.json')-Object([ordered]@{reportedTargets=@('explorer.exe','svchost.exe');reportedShell='cmd.exe';processesOpened=0;memoryWritten=0;threadsCreated=0;injectionOccurred=$false})-Purpose defense-evasion
Write-RRFile -Path(Join-Path $p.Payloads 'adf.bat')-Content 'INERT ADF.BAT-NAME CANARY. No command or directory-query logic.' -Purpose payload-canary
$commands=@('nltest /domain_trusts /all_trusts','net group "Domain admins" /DOMAIN','ping hostname.domain.local')
foreach($command in $commands){Invoke-RRDecoy -FilePath $shell -Reported $command -Parent 'Document-Preview.exe' -Label 'SYNTHETIC-DAY1-DISCOVERY'}
Invoke-RRDecoy -FilePath $adfind -Reported 'AdFind.exe invoked by adf.bat minutes after Document-Preview.exe' -Parent 'adf.bat' -Label 'SYNTHETIC-ADFIND'
Write-RRJson -Path(Join-Path $p.Staging 'day1-adfind-output.json')-Object([ordered]@{domain='LAB-CANARY.LOCAL';people=@('canary.user');computers=@('DC01-CANARY','BAK01-CANARY');groups=@('DFIR-Canary-Admins');synthetic=$true})-Purpose synthetic-discovery-output
Write-RRJson -Path(Join-Path $p.Evidence 'day1-discovery.json')-Object([ordered]@{reportedCommands=$commands;reportedAdFindBatch='adf.bat';actualDomainQueries=0;actualPingTargets=0;syntheticOutput=(Join-Path $p.Staging 'day1-adfind-output.json')})-Purpose discovery
Invoke-RRLoopback -Port 443 -Target '5.182.210.145' -Role 'Bazar C2 marker'
Add-RRTimeline 0 initial-access 'Malspam link and Document-Preview Bazar execution represented' @{downloads=0;liveMalware=$false}
Add-RRTimeline 3 defense-evasion 'Bazar injection into explorer/svchost and command-shell spawning represented' @{injectionOccurred=$false}
Add-RRTimeline 8 discovery 'Day-one Nltest, Net, Ping, AdFind, and adf.bat activity represented' @{actualQueries=0;syntheticOutput=$true}
Add-RRTimeline 20 command-and-control 'Bazar TLS channel represented' @{externalConnections=0;bytesTransferred=0}
Write-RRJson -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{liveMalware=0;downloads=0;processInjection=0;domainQueries=0;networkProbes=0;externalConnections=0;bytesTransferred=0})-Purpose safety
