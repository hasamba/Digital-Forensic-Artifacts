#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\BazarAnchorSim-utilities.ps1"
Assert-BASafety -LabConfirmed:$LabConfirmed
$paths = Initialize-BAEnvironment

$beacon = Join-Path $paths.Payloads '~tmp01925d3f.exe'
if (-not (Test-Path -LiteralPath $beacon)) { New-BADecoy $beacon 'Cobalt Beacon stand-in' '10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63' }
foreach ($day in 1..4) {
    Invoke-BADecoy $beacon "Day $day Bazar/Cobalt/Anchor active C2 heartbeat; no corresponding operator action unless separately recorded" 'dllhost.exe / WerFault.exe / AnchorDNS'
    Invoke-BALoopback 80 '195.123.217.45:80 /jquery-3.3.1.min.js' "day $day Cobalt marker"
    Invoke-BALoopback 53 'xyskencevli.com and sluaknhbsoe.com' "day $day AnchorDNS marker"
}
Write-BAFile (Join-Path $paths.Evidence 'four-day-c2.json') (@{families=@('Bazar in WerFault','Cobalt Strike','AnchorDNS');days=4;reportedCobaltPollingMs=45000;reportedCobaltJitter=37;reportedPaths=@('/jquery-3.3.1.min.js','/jquery-3.3.2.min.js');externalConnections=0;dnsQueries=0;bytesTransferred=0;proxy=$false} | ConvertTo-Json -Depth 6) command-and-control
Write-BAFile (Join-Path $paths.Evidence 'scheduled-task-unspecified.json') (@{source='report ATT&CK list includes T1053.005';reportPublishedTaskName=$false;reportPublishedTaskAction=$false;tasksCreated=0} | ConvertTo-Json) persistence

foreach ($name in @('Board-Minutes.docx','Payroll-Review.xlsx','Acquisition-Plan.pdf')) { Write-BAFile (Join-Path $paths.Honey $name) "GENERATED HONEY-DOCUMENT CANARY: $name. No user data, macro, beacon, or remote-access logic." honey-document }
Write-BAFile (Join-Path $paths.Evidence 'honey-doc-access.json') (@{reportedRemoteIp='23.94.51.80';reportedUserAgent='Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; MSOffice 12)';generatedHoneyDocuments=3;documentsReadByScenario=0;documentsExfiltrated=0;remoteOpenRequests=0;bytesTransferred=0} | ConvertTo-Json) collection

$infoRoot = Join-Path $paths.Hosts 'DC-CANARY-01\C\info'
Write-BAFile (Join-Path $infoRoot 'start.bat') 'REM INERT START.BAT-NAME CANARY. No commands.' collection
Write-BAFile (Join-Path $infoRoot 'Get-DataInfo.ps1') '# INERT GET-DATAINFO-NAME CANARY. No commands, collection, modules, or network activity.' collection
Invoke-BADecoy $beacon 'C:\Windows\system32\cmd.exe /c ""C:\info\start.bat""; wrapper launches Get-DataInfo.ps1' 'Cobalt Beacon on domain controller'
Write-BAFile (Join-Path $paths.Evidence 'get-datainfo.json') (@{reportedDay=3;reportedCollection=@('disk size','connectivity','antivirus software','backup software','detailed environment information');generatedCanaryPath=$infoRoot;scriptExecuted=$false;systemInformationRead=$false;securityProductsEnumerated=$false;backupProductsEnumerated=$false} | ConvertTo-Json -Depth 5) collection

$scanner = Join-Path $paths.Payloads 'Advanced_IP_Scanner_2.5.3850.exe'
New-BADecoy $scanner 'Advanced IP Scanner stand-in' '722fff8f38197d1449df500ae31a95bb34a6ddaba56834b13eaaff2b0f9f1c8b'
Invoke-BADecoy $scanner 'Advanced_IP_Scanner_2.5.3850.exe scans the network four days into the intrusion' 'Cobalt Beacon on domain controller'
Invoke-BALoopback 443 'checkip.amazonaws.com:443' 'reported public-IP check marker'
Write-BAFile (Join-Path $paths.Evidence 'day4-scan.json') (@{reportedTool='Advanced_IP_Scanner_2.5.3850.exe';reportedPublicIpService='checkip.amazonaws.com';scanTargets=0;packetsSent=0;hostsDiscovered=0;externalRequests=0} | ConvertTo-Json) discovery
Write-BAFile (Join-Path $paths.Evidence 'phase2-negative.json') (@{externalConnections=0;dnsQueries=0;tasksCreated=0;userFilesRead=0;honeyDocumentsOpened=0;filesExfiltrated=0;bytesTransferred=0;GetDataInfoExecuted=$false;systemInformationRead=$false;networkScans=0;packetsSent=0;remoteHostsTouched=0} | ConvertTo-Json) safety
Add-BATimeline 24 command-and-control 'Bazar, Cobalt, and AnchorDNS maintain C2 while operators go quiet' @{externalConnections=0;dnsQueries=0}
Add-BATimeline 48 collection 'Honey-document access and assessed encrypted-C2 exfiltration represented' @{documentsExfiltrated=0;bytesTransferred=0}
Add-BATimeline 72 collection 'Get-DataInfo start.bat wrapper appears on generated DC canary' @{scriptExecuted=$false;systemInformationRead=$false}
Add-BATimeline 96 discovery 'Advanced IP Scanner and repeated AWS public-IP checks represented' @{networkScans=0;externalRequests=0}
