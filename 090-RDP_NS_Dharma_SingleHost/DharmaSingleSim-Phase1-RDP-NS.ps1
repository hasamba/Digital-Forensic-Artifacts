#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DharmaSingleSim-utilities.ps1";Assert-DSSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DSEnvironment
$scanner=Join-Path $p.Payloads 'NS.exe';New-DSDecoy -Path $scanner -Role 'network/share enumeration stand-in' -PublishedSha256 'f47e3555461472f23ab4766e4d5b6f6fd260e335a6abc31b860e569a720a5446'
Write-DSJson -Path(Join-Path $p.Evidence 'rdp-entry.json')-Object([ordered]@{reportedTimeUtc='08:58';reportedSource='217.138.202.116';reportedAccount='local administrator';authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0})-Purpose initial-access
Invoke-DSLoopback -Port 3389 -Target '217.138.202.116 to victim RDP' -Role 'initial access marker'
Invoke-DSDecoy -FilePath $scanner -Reported '%USERPROFILE%\Desktop\Oc\NS.exe executed at 09:36 to scan/map file shares' -Parent 'RDP user session' -Label 'NO-NETWORK-SCAN'
Write-DSJson -Path(Join-Path $p.Evidence 'scanner.json')-Object([ordered]@{reportedTool='NS.exe';reportedPath='%USERPROFILE%\Desktop\Oc\NS.exe';hostsScanned=0;packetsSent=0;sharesEnumerated=0;sharesMounted=0;volumesMounted=0})-Purpose discovery
Add-DSTimeline 0 initial-access '08:58 local-administrator RDP login represented' @{authenticationAttempts=0;rdpSessions=0};Add-DSTimeline 38 discovery '09:36 NS.exe share/volume enumeration represented' @{hostsScanned=0;sharesMounted=0}
Write-DSJson -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0;hostsScanned=0;packetsSent=0;sharesEnumerated=0;sharesMounted=0;volumesMounted=0;externalConnections=0})-Purpose safety
