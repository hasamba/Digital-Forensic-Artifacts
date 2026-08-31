#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\NetWalkerHourSim-utilities.ps1";Assert-NWSafety -LabConfirmed:$LabConfirmed;$p=Initialize-NWEnvironment
$mimi=Join-Path $p.Payloads 'mimikatz.exe';$dump=Join-Path $p.Payloads 'procdump64.exe'
New-NWDecoy -Path $mimi -Role 'Mimikatz stand-in' -PublishedSha256 'f743c0849d69b5ea2f7eaf28831c86c1536cc27ae470f20e49223cbdba9c677c'
New-NWDecoy -Path $dump -Role 'custom ProcDump stand-in' -PublishedSha256 '6a511d4178d6d2f98f8af34311d0e15dc8dc1c4b643e6943f056da6ce242e70d'
Invoke-NWDecoy -FilePath $dump -Reported 'procdump64.exe -ma lsass.exe lsass.dmp' -Parent 'RDP user shell' -Label 'NO-LSASS-ACCESS'
Invoke-NWDecoy -FilePath $mimi -Reported 'mimikatz.exe executed about one minute after the reported LSASS dump' -Parent 'RDP user shell' -Label 'NO-CREDENTIAL-ACCESS'
Write-NWJson -Path(Join-Path $p.Evidence 'credential-access-marker.json')-Object([ordered]@{reportedSequence=@('Mimikatz dropped','procdump64.exe dropped one minute later','LSASS dump command','Mimikatz run about one minute later');lsassHandlesOpened=0;processMemoryReadBytes=0;dumpFilesCreated=0;credentialsOrHashesCollected=0;passwordsCollected=0})-Purpose credential-access
$dc=New-NWHostTree -Name 'DC01-CANARY' -Role 'generated domain-controller representation'
Write-NWJson -Path(Join-Path $p.Evidence 'dc-pivot.json')-Object([ordered]@{reportedMovement='RDP to a domain controller after credential dumping';generatedTarget=$dc;reportedDrops=@('ip-list.txt','P100119.ps1','PsExec');rdpSessions=0;authenticationAttempts=0;remoteFilesWritten=0})-Purpose lateral-movement
Write-NWFile -Path(Join-Path $p.Staging 'ip-list.txt')-Content "FS01-CANARY`nWS01-CANARY`nWS02-CANARY" -Purpose synthetic-target-list
Write-NWFile -Path(Join-Path $p.Payloads 'P100119.ps1')-Content '# INERT NETWALKER-SCRIPT NAME CANARY. No share, credential, PowerShell, or ransomware logic.' -Purpose payload-canary
Invoke-NWLoopback -Port 3389 -Target 'domain controller' -Role 'post-credential RDP pivot marker'
Add-NWTimeline 35 credential-access 'ProcDump LSASS command represented without opening LSASS or creating a dump' @{lsassHandlesOpened=0;dumpFilesCreated=0}
Add-NWTimeline 36 credential-access 'Mimikatz execution represented without credential material' @{credentialsOrHashesCollected=0}
Add-NWTimeline 45 lateral-movement 'RDP to generated DC representation and final tool staging represented' @{rdpSessions=0;remoteFilesWritten=0}
Write-NWJson -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{lsassHandlesOpened=0;processMemoryReadBytes=0;dumpFilesCreated=0;credentialsOrHashesCollected=0;rdpSessions=0;authenticationAttempts=0;remoteFilesWritten=0;externalConnections=0})-Purpose safety
