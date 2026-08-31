#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Harma17Sim-utilities.ps1";Assert-H17Safety -LabConfirmed:$LabConfirmed;$p=Initialize-H17Environment
$entry=New-H17HostTree -Name 'ENTRY01-CANARY' -Role 'generated nonstandard-port RDP entry host';$taskmgr=Join-Path $p.Payloads 'taskmgr.exe';$scanner=Join-Path $p.Payloads 'netscan.exe'
New-H17Decoy -Path $taskmgr -Role 'Task Manager telemetry stand-in';New-H17Decoy -Path $scanner -Role 'SoftPerfect Network Scanner stand-in'
Write-H17Json -Path(Join-Path $p.Evidence 'rdp-entry.json')-Object([ordered]@{reportedSource='212.102.45.98';reportedPort='nondefault RDP port (number not published)';generatedTarget=$entry;authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0})-Purpose initial-access
Invoke-H17Loopback -Port 3389 -Target '212.102.45.98 to a nonstandard RDP listener' -Role 'initial RDP marker'
Invoke-H17Decoy -FilePath $taskmgr -Reported 'Task Manager opened to inspect logged-on users' -Parent 'RDP user session' -Label 'NO-SESSION-INSPECTION'
Invoke-H17Decoy -FilePath $scanner -Reported 'SoftPerfect Network Scanner dropped and run on entry host' -Parent 'RDP user session' -Label 'NO-NETWORK-SCAN'
Write-H17Json -Path(Join-Path $p.Evidence 'entry-scanner.json')-Object([ordered]@{reportedTool='SoftPerfect Network Scanner';hostsScanned=0;packetsSent=0;portsProbed=0;results='generated metadata only'})-Purpose discovery
Add-H17Timeline 0 initial-access '07:00 RDP login from 212.102.45.98 to nonstandard port represented' @{authenticationAttempts=0;rdpSessions=0}
Add-H17Timeline 1 discovery '07:01 Task Manager user-session inspection represented' @{sessionsEnumerated=0}
Add-H17Timeline 3 discovery '07:03 Network Scanner drop/run represented on entry host' @{hostsScanned=0;packetsSent=0}
Write-H17Json -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{authenticationAttempts=0;validAccountsUsed=0;rdpSessions=0;sessionsEnumerated=0;hostsScanned=0;packetsSent=0;externalConnections=0})-Purpose safety
