#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShareFinderSim-utilities.ps1"
Assert-ShareFinderSafety -LabConfirmed:$LabConfirmed
$paths=Initialize-ShareFinderEnvironment

$targets=@(
    @{host='LAB-WS01';address='192.0.2.11';shares=@('IPC$','C$','ADMIN$')},
    @{host='LAB-WS02';address='192.0.2.12';shares=@('IPC$','C$','ADMIN$')},
    @{host='LAB-FILE01';address='192.0.2.21';shares=@('IPC$','C$','ADMIN$','Files')},
    @{host='LAB-DC01';address='192.0.2.31';shares=@('IPC$','C$','ADMIN$','SYSVOL')}
)
$objectLog=Join-Path $paths.Logs 'Security-5145.jsonl'
$offset=0
foreach($target in $targets){foreach($share in $target.shares){$offset+=90;Add-ShareFinderJsonLine $objectLog @{eventId=5145;timestampOffsetMs=$offset;sourceAddress='192.0.2.50';destinationHost=$target.host;shareName="\\*\$share";relativeTargetName='';accessMask='0x1';accessAttempted=$false;synthetic=$true} 'object-access canary'}}
$variants=@(
    @{name='default';parameters='-CheckShareAccess';standardShares=$true;ping=$false;delay=0;jitter=.3},
    @{name='exclude-standard';parameters='-ExcludeStandard -CheckShareAccess';standardShares=$false;ping=$false;delay=0;jitter=.3},
    @{name='slow-with-ping';parameters='-Ping -Delay 10 -Jitter 0.3';standardShares=$true;ping=$true;delay=10;jitter=.3}
)
Write-ShareFinderFile(Join-Path $paths.Evidence 'parameter-variants.json')($variants|ConvertTo-Json -Depth 6)'parameter evasion profile'
$assessment=[ordered]@{ruleInputs=@('single source to many SMB/445 targets','IPC$/C$/ADMIN$ triad','user shares such as Files','SYSVOL-name query','short burst','optional ICMP precursor','broad LDAP computer filter','PowerShell 4103/4104','Security 5145');likelyFalsePositives=@('authorized vulnerability scanner','inventory platform','share auditing platform');correlationRequired=$true;eventsAreSyntheticFiles=$true}
Write-ShareFinderFile(Join-Path $paths.Evidence 'detection-assessment.json')($assessment|ConvertTo-Json -Depth 7)'detection guidance'
Write-ShareFinderFile(Join-Path $paths.Evidence 'impact-exfiltration-negative-record.json')(@{filesRead=0;organizationalDataCollected=$false;bytesExfiltrated=0;ransomwareDeployed=$false;impactActions=0}|ConvertTo-Json)'outcome safety record'
Add-ShareFinderTimeline 7 detection 'Synthetic 5145 burst correlates one source with many hosts and default shares' @{realSecurityEventsGenerated=0;syntheticRecords=$offset/90}
Add-ShareFinderTimeline 10 detection 'ExcludeStandard, Delay, Jitter, Ping, and alternate implementation considerations recorded' @{commandsExecuted=0;correlationRequired=$true}
Add-ShareFinderTimeline 11 conclusion 'Profile ends at discovery/detection; collection, exfiltration, and impact are out of scope' @{bytesExfiltrated=0;impactActions=0}
