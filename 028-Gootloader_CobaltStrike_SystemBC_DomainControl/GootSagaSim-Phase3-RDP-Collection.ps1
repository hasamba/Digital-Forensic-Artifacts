#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GootSagaSim-utilities.ps1";Assert-GootSagaSafety -LabConfirmed:$LabConfirmed;$p=Initialize-GootSagaEnvironment
foreach($hostName in @('WORKSTATION-01','DC-01','BACKUP-01')){New-Item(Join-Path $p.Hosts $hostName)-ItemType Directory -Force|Out-Null}
$scanner=Join-Path $p.Hosts 'DC-01\Advanced_IP_Scanner.exe';New-GootSagaDecoy $scanner 'Advanced IP Scanner filename canary';Invoke-GootSagaDecoy $scanner 'Advanced IP Scanner search for TCP/3389 on synthetic hosts only'
Write-GootSagaFile(Join-Path $p.Shares 'Passwords\environment-passwords.txt')"GENERATED CANARY ONLY`nbackup-admin = NOT-A-REAL-PASSWORD`nNo production credentials or PII."'credential-document canary'
Write-GootSagaFile(Join-Path $p.Shares 'Contracts\Implied-Employment-Agreement.txt')'GENERATED LEGAL-DOCUMENT CANARY. No customer or employee data.''sensitive-document canary'
Write-GootSagaFile(Join-Path $p.Hosts 'DC-01\payload.txt')'INERT command-transfer canary. Reported content included encoded PowerShell and Defender-disable commands; neither is reproduced or executed.''RDP clipboard/file canary'
$events=@(
    @{eventId=4624;description='new logon session using harvested credential';generatedRecordOnly=$true},
    @{eventId=4672;description='special privileges assigned';generatedRecordOnly=$true},
    @{eventId=1117;description='Defender removed compiled beacon on domain controller';generatedRecordOnly=$true},
    @{eventId=131;channel='RemoteDesktopServices-RdpCoreTS/Operational';description='RDP connection';generatedRecordOnly=$true},
    @{eventId=4778;clientName='DESKTOP-GRALDC5';description='RDP reconnect through proxy';generatedRecordOnly=$true},
    @{eventId=24;provider='Sysmon';clientName='DESKTOP-GRALDC5';description='clipboard copy from payload.txt';generatedRecordOnly=$true}
);Write-GootSagaFile(Join-Path $p.Evidence 'windows-event-replicas.json')($events|ConvertTo-Json -Depth 5)'event evidence'
$collection=[ordered]@{rdpToDomainController=$false;winRmToBackupServer=$false;advancedIpScan=$false;remoteShareAccess=$false;passwordDocumentAccess=$false;contractDocumentAccess=$false;realDataCollected=$false;exfiltrationObservedByReport='unconfirmed';actualBytesTransferred=0};Write-GootSagaFile(Join-Path $p.Evidence 'collection-negative-record.json')($collection|ConvertTo-Json -Depth 5)'collection evidence'
Add-GootSagaTimeline 720 lateral-movement 'Synthetic DC and backup-server RDP/WinRM sequence represented without remote access' @{remoteConnections=0;techniques=@('T1021.001','T1021.006')}
Add-GootSagaTimeline 780 discovery 'Advanced IP Scanner and share discovery represented against generated artifacts only' @{scanPerformed=$false;shareQueries=0;techniques=@('T1046','T1135')}
Add-GootSagaTimeline 840 collection 'Generated password and contract canaries represented as interactively viewed' @{realFilesAccessed=0;exfiltration='unconfirmed in report; zero bytes in simulation';technique='T1005'}
Add-GootSagaTimeline 1140 inactivity 'Five-hour lull represented' @{}
Add-GootSagaTimeline 1440 completion 'Second-day 0600-1100 UTC RDP activity window and subsequent eviction represented' @{attackerHosts=@('DESKTOP-GRALDC5','HOME-PC');artifactsRemain=$true}
