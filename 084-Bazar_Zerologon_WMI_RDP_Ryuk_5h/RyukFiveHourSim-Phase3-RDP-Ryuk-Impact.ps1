#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukFiveHourSim-utilities.ps1"
Assert-R5Safety -LabConfirmed:$LabConfirmed
$p = Initialize-R5Environment

$roles = [ordered]@{'BAK01-CANARY'='backup server';'APP01-CANARY'='application server';'FS01-CANARY'='file server';'WS01-CANARY'='workstation';'WS02-CANARY'='workstation';'DC02-CANARY'='secondary DC representation';'DC01-CANARY'='primary DC representation'}
foreach ($entry in $roles.GetEnumerator()) { $null = New-R5HostTree -Name $entry.Key -Role $entry.Value }
$ryuk = Join-Path $p.Payloads 'xxx.exe'
New-R5Decoy -Path $ryuk -Role 'Ryuk ransomware stand-in' -PublishedSha256 'ccde47a0d315dcd4740fccfe8e8110fbb1fd85bb305734fec409f52051790c98'
Invoke-R5Decoy -FilePath $ryuk -Reported 'xxx.exe transferred through RDP from the primary domain controller, beginning with the secondary DC and backup server' -Parent 'RDP session from primary domain controller' -Label 'SYNTHETIC-RYUK'
$records = New-Object System.Collections.Generic.List[object]
foreach ($entry in $roles.GetEnumerator()) {
    $hostRoot = Join-Path $p.Hosts $entry.Key
    $note = Join-Path $hostRoot 'C$\Finance\RyukReadMe.txt'
    $marker = Join-Path $hostRoot 'C$\Finance\budget.xlsx.RYUK-CANARY'
    Write-R5File -Path $note -Content "INERT RYUK NOTE CANARY for $($entry.Key). No original file was changed." -Purpose ransom-note-canary
    Write-R5File -Path $marker -Content "INERT ENCRYPTION MARKER for generated host $($entry.Key). This is newly generated canary data." -Purpose encryption-canary
    $records.Add([ordered]@{hostname=$entry.Key;role=$entry.Value;generatedTree=$hostRoot;markers=2;userFilesRead=0;userFilesChanged=0;filesEncrypted=0})
}
Write-R5Json -Path (Join-Path $p.Evidence 'impact-summary.json') -Object ([ordered]@{reportedReadyMinutes=240;reportedBackupPivotMinutes=250;reportedRansomwareStartMinutes=270;reportedCompletionMinutes=300;reportedOrder=@('secondary domain controller and backup server','servers','workstations','primary domain controller last');generatedHosts=$records;rdpSessions=0;remoteFilesWritten=0;userFilesRead=0;userFilesChanged=0;filesEncrypted=0;generatedCanaryMarkers=14}) -Purpose impact
Invoke-R5Loopback -Port 3389 -Target 'backup server, servers, workstations, and domain controllers' -Role 'enterprise Ryuk RDP deployment marker'
Add-R5Timeline -Minutes 250 -Phase lateral-movement -Event 'RDP pivot from primary DC to backup server represented at four hours ten minutes' -Details @{rdpSessions=0;remoteFilesWritten=0}
Add-R5Timeline -Minutes 270 -Phase impact -Event 'Ryuk objectives begin around four and a half hours; secondary DC and backup targeted first' -Details @{filesEncrypted=0;generatedTargets=2}
Add-R5Timeline -Minutes 285 -Phase impact -Event 'Generated server and workstation waves represented' -Details @{filesEncrypted=0;generatedTargets=4}
Add-R5Timeline -Minutes 300 -Phase impact -Event 'Primary DC targeted last and reported attack completed at five hours' -Details @{realDomainTargets=0;userFilesChanged=0;generatedCanaryMarkers=14}
Write-R5Json -Path (Join-Path $p.Evidence 'phase3-negative.json') -Object ([ordered]@{rdpSessions=0;remoteDeployments=0;remoteFilesWritten=0;servicesStopped=0;processesTerminated=0;aclChanges=0;userFilesRead=0;userFilesChanged=0;filesEncrypted=0;securityControlsChanged=0;GposModified=0;logsCleared=0;shadowCopiesDeleted=0;externalConnections=0;bytesTransferred=0}) -Purpose safety
