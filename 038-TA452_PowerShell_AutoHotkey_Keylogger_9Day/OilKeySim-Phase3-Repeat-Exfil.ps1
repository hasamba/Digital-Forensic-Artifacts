#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\OilKeySim-utilities.ps1"
Assert-OilKeySafety -LabConfirmed:$LabConfirmed
$paths = Initialize-OilKeyEnvironment

Write-OilKeyFile (Join-Path $paths.Collection 'logFileuyovaqv.cab') 'INERT CAB-NAME CANARY. Plain UTF-8 generated content; makecab was not run.' 'archive canary'
Write-OilKeyFile (Join-Path $paths.Modules 'sc.ps1') '# INERT screen-capture-name canary. No graphics or desktop APIs are invoked.' 'screen-capture script canary'
Write-OilKeyFile (Join-Path $paths.Collection 'sc.png') 'INERT PNG-NAME CANARY. Not an image and no screen was captured.' 'screen-capture output canary'
Write-OilKeyFile (Join-Path $paths.Collection 'u.xml') '<generated>INERT COLLECTION CANARY</generated>' 'staging canary'
Write-OilKeyFile (Join-Path $paths.Collection 'u.zip') 'INERT ZIP-NAME CANARY. Not an archive.' 'staging canary'
$makecabDecoy = Join-Path $paths.Modules 'makecab.exe'
New-OilKeyDecoy $makecabDecoy 'Signed cmd.exe stand-in for makecab'
Invoke-OilKeyDecoy $makecabDecoy 'makecab.exe logFileuyovaqv.bin logFileuyovaqv.cab' 'powershell.exe'

foreach ($event in @(
    @{offset=144;name='day-6 keylog CAB and screenshot';method='POST'},
    @{offset=168;name='day-7 repeated keylog collection';method='POST'},
    @{offset=216;name='day-9 repeated keylog collection';method='POST'}
)) {
    Invoke-OilKeyLoopback 80 "http://45.89.125.189/put ($($event.name))" $event.method
    Add-OilKeyTimeline $event.offset collection $event.name @{generatedDataOnly=$true;realScreenshot=$false;bytesTransferred=0;techniques=@('T1560.001','T1113','T1041')}
}
$cleanup = [ordered]@{reportedCommands=@('del logFileuyovaqv.cab','del u.zip','del u.xml');executed=$false;artifactsRemoved=0;reason='Artifacts intentionally remain for forensic investigation'}
Write-OilKeyFile (Join-Path $paths.Evidence 'reported-cleanup-negative-record.json') ($cleanup | ConvertTo-Json -Depth 5) 'cleanup evidence'
Write-OilKeyFile (Join-Path $paths.Evidence 'exfiltration-negative-record.json') (@{realDataRead=$false;realArchivesCreated=0;screensCaptured=0;realIOCContacted=$false;proxyUsed=$false;bytesTransferred=0;collectionCyclesRepresented=3} | ConvertTo-Json) 'exfiltration safety record'
Add-OilKeyTimeline 144 command-and-control 'Day 6 collection upload over existing C2 represented on loopback' @{realIOCContacted=$false;bytesTransferred=0}
Add-OilKeyTimeline 216 conclusion 'Operator activity ceased after repeated collection; no impact phase was observed' @{destructiveActions=0;artifactsLeftForInvestigation=$true}
