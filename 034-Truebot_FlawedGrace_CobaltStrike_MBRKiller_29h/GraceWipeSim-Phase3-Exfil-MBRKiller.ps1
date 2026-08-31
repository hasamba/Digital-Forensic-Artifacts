#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GraceWipeSim-utilities.ps1"
Assert-GraceWipeSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-GraceWipeEnvironment

$collection = Join-Path $paths.Staging 'generated-collection'
foreach ($name in @('Finance-Q2.csv','Operations.txt','FileServer-index.json')) { Write-GraceWipeFile (Join-Path $collection $name) "GENERATED COLLECTION CANARY: $name`nNo user or organizational data." 'generated collection canary' }
Invoke-GraceWipeLoopback 4433 '139.60.160.166 first FlawedGrace exfiltration period' 'raw TCP marker'
Invoke-GraceWipeLoopback 4433 '139.60.160.166 second FlawedGrace exfiltration period two hours later' 'raw TCP marker'
$exfil = [ordered]@{periodsRepresented=2;reportedVolume='gigabytes';destination='139.60.160.166:4433';actualDestination='127.0.0.1:4433';proxyUsed=$false;bytesTransferred=0;realDataCollected=$false}
Write-GraceWipeFile (Join-Path $paths.Evidence 'exfiltration-negative-record.json') ($exfil | ConvertTo-Json) 'exfiltration negative record'

$chrome = Join-Path $paths.Payloads 'chrome.exe'
New-GraceWipeDecoy $chrome 'MBR Killer chrome.exe stand-in' '121a1f64fff22c4bfcef3f11a23956ed403cdeb9bdb803f9c42763087bd6d94e'
Invoke-GraceWipeDecoy $chrome 'C:\ProgramData\chrome.exe; patched NSIS MBR Killer; wipe disks; force reboot'
$serverWiper = Join-Path $paths.Payloads '4f8a70d2c31e49a6b5728d09efac1357.exe'
New-GraceWipeDecoy $serverWiper '32-hex Windows Temp wiper filename stand-in' '121a1f64fff22c4bfcef3f11a23956ed403cdeb9bdb803f9c42763087bd6d94e'
Invoke-GraceWipeDecoy $serverWiper 'C:\Windows\Temp\[0-9a-f]{32}.exe on generated server'
$nsis = Join-Path $paths.Impact 'nsA1b2C.tmp\System.dll'
Write-GraceWipeFile $nsis 'INERT NSIS SYSTEM.DLL-NAME CANARY. Not a DLL.' 'NSIS extraction canary'

foreach ($hostName in @('BEACHHEAD','APP-01','FILE-01','SQL-01','WKSTN-01')) {
    $diskRoot = Join-Path $paths.Impact $hostName
    New-Item -Path $diskRoot -ItemType Directory -Force | Out-Null
    $before = Join-Path $diskRoot 'PHYSICALDRIVE0-first-sector.before.bin'
    $after = Join-Path $diskRoot 'PHYSICALDRIVE0-first-sector.after.bin'
    [byte[]]$sector = 0..255 + 0..255
    [IO.File]::WriteAllBytes($before,$sector)
    [IO.File]::WriteAllBytes($after,$sector)
    Add-GraceWipeManifest disk-canary $before generated-sector @{physicalDriveOpened=$false;bytes=512;sha256=(Get-FileHash -LiteralPath $before -Algorithm SHA256).Hash}
    Add-GraceWipeManifest disk-canary $after unchanged-sector @{physicalDriveOpened=$false;bytesWrittenToRealDisk=0;sha256=(Get-FileHash -LiteralPath $after -Algorithm SHA256).Hash}
    Write-GraceWipeFile (Join-Path $diskRoot 'BOOT-SCREEN.canary.txt') 'GENERATED BOOT-SCREEN CANARY. Host remains operational; no reboot occurred.' 'impact display canary'
}
$impact = [ordered]@{physicalDrivesOpened=0;rawDiskBytesWritten=0;mbrWiped=$false;mftWiped=$false;vbrWiped=$false;ebrWiped=$false;ZwClosePatched=$false;SeShutdownPrivilegeEnabled=$false;rebootRequested=$false;hostsImpaired=0;generatedCanarySectorsRemainIdentical=$true}
Write-GraceWipeFile (Join-Path $paths.Evidence 'mbr-killer-negative-record.json') ($impact | ConvertTo-Json) 'wiper negative record'
Add-GraceWipeTimeline 22 discovery 'Actors returned after 17-hour dormancy and enumerated shares' @{realSharesQueried=0}
Add-GraceWipeTimeline 23 exfiltration 'First of two raw-TCP exfiltration periods represented' @{bytesTransferred=0;technique='T1048'}
Add-GraceWipeTimeline 25 exfiltration 'Second exfiltration period represented' @{bytesTransferred=0;technique='T1048'}
Add-GraceWipeTimeline 29 impact 'MBR Killer deployment, disk-structure wipe, privilege change, and reboot represented with unchanged canary sectors' @{physicalDrivesOpened=0;rawDiskBytesWritten=0;reboot=$false;technique='T1561.002'}
