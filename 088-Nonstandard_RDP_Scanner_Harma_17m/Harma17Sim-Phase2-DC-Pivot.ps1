#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Harma17Sim-utilities.ps1";Assert-H17Safety -LabConfirmed:$LabConfirmed;$p=Initialize-H17Environment
$dc=New-H17HostTree -Name 'DC01-CANARY' -Role 'generated domain-controller representation';$taskmgr=Join-Path $p.Payloads 'taskmgr.exe';$scanner=Join-Path $p.Payloads 'netscan.exe'
if(-not(Test-Path -LiteralPath $taskmgr)){New-H17Decoy -Path $taskmgr -Role 'Task Manager telemetry stand-in'};if(-not(Test-Path -LiteralPath $scanner)){New-H17Decoy -Path $scanner -Role 'SoftPerfect Network Scanner stand-in'}
Invoke-H17Loopback -Port 3389 -Target 'domain controller' -Role 'RDP lateral-movement marker'
Invoke-H17Decoy -FilePath $taskmgr -Reported 'Task Manager opened on domain controller' -Parent 'RDP session from ENTRY01' -Label 'NO-SESSION-INSPECTION'
Invoke-H17Decoy -FilePath $scanner -Reported 'SoftPerfect Network Scanner dropped and run on domain controller' -Parent 'RDP session from ENTRY01' -Label 'NO-NETWORK-SCAN'
Write-H17Json -Path(Join-Path $p.Evidence 'dc-pivot.json')-Object([ordered]@{generatedTarget=$dc;reportedSequence=@('07:08 RDP into DC','07:10 Task Manager','07:10 Network Scanner');authenticationAttempts=0;rdpSessions=0;remoteFilesWritten=0;hostsScanned=0;packetsSent=0})-Purpose lateral-movement
Add-H17Timeline 8 lateral-movement '07:08 RDP to generated DC representation' @{authenticationAttempts=0;rdpSessions=0}
Add-H17Timeline 10 discovery '07:10 Task Manager and Network Scanner represented on DC' @{sessionsEnumerated=0;hostsScanned=0;packetsSent=0}
Write-H17Json -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{authenticationAttempts=0;rdpSessions=0;remoteFilesWritten=0;sessionsEnumerated=0;hostsScanned=0;packetsSent=0;externalConnections=0})-Purpose safety
