#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShareFinderSim-utilities.ps1"
Assert-ShareFinderSafety -LabConfirmed:$LabConfirmed
$paths=Initialize-ShareFinderEnvironment

$hosts=@(
    @{name='LAB-WS01';address='192.0.2.11';shares=@('IPC$','C$','ADMIN$')},
    @{name='LAB-WS02';address='192.0.2.12';shares=@('IPC$','C$','ADMIN$')},
    @{name='LAB-FILE01';address='192.0.2.21';shares=@('IPC$','C$','ADMIN$','Files')},
    @{name='LAB-DC01';address='192.0.2.31';shares=@('IPC$','C$','ADMIN$','SYSVOL')}
)
$ldapFilter='(&(&(&(objectClass=Computer)(dnshostname=*))(operatingsystem=*))(servicePrincipalName=*))'
$ldapLog=Join-Path $paths.Logs 'Directory-Service-1644.jsonl'
Add-ShareFinderJsonLine $ldapLog @{eventId=1644;sourceHost='LAB-CLIENT01';filter=$ldapFilter;attributes=@('dNSHostName','operatingSystem','servicePrincipalName');returnedObjects=($hosts.name);queryExecuted=$false;synthetic=$true} 'LDAP search canary'
Write-ShareFinderFile(Join-Path $paths.Hosts 'ldap-computers.json')($hosts|ConvertTo-Json -Depth 6)'generated host inventory'

$networkLog=Join-Path $paths.Logs 'zeek-sharefinder-profile.jsonl'
$sequence=0
foreach($hostRecord in $hosts){
    $sequence++
    Add-ShareFinderJsonLine $networkLog @{timestampOffsetMs=$sequence*350;source='192.0.2.50';destination=$hostRecord.address;destinationHost=$hostRecord.name;protocol='ICMP';type='echo-request';packetSent=$false;synthetic=$true} 'ICMP one-to-many canary'
    Invoke-ShareFinderLoopback 445 "$($hostRecord.name) / $($hostRecord.address):445" 'SMB marker'
    foreach($share in $hostRecord.shares){
        Add-ShareFinderJsonLine $networkLog @{timestampOffsetMs=($sequence*350)+25;source='192.0.2.50';destination=$hostRecord.address;destinationHost=$hostRecord.name;destinationPort=445;share=$share;operation='TREE_CONNECT';connectionMade=$false;shareAccessed=$false;synthetic=$true} 'SMB one-to-many canary'
    }
}
Write-ShareFinderFile(Join-Path $paths.Evidence 'network-directory-negative-record.json')(@{LDAPQueries=0;domainControllersContacted=0;ICMPPacketsSent=0;remoteSMBConnections=0;sharesEnumerated=0;sharesAccessed=0;loopbackMarkers=$hosts.Count;documentationAddressesOnly=$true}|ConvertTo-Json)'network safety record'
Add-ShareFinderTimeline 5 discovery 'Broad computer-object LDAP filter represented as synthetic Event 1644' @{directoryQueried=$false;technique='T1018'}
Add-ShareFinderTimeline 6 discovery 'One-to-many ICMP and SMB/445 pattern across generated hosts represented' @{packetsSent=0;remoteConnections=0;techniques=@('T1018','T1135')}
Add-ShareFinderTimeline 6.1 discovery 'IPC$, C$, ADMIN$, Files, and SYSVOL tree-connect records represented' @{sharesAccessed=0;gpoOrSysvolTouched=$false;technique='T1135'}
