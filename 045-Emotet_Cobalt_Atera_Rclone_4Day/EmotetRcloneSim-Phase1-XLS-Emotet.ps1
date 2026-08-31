#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetRcloneSim-utilities.ps1"
Assert-EmotetRcloneSafety -LabConfirmed:$LabConfirmed
$p = Initialize-EmotetRcloneEnvironment

Write-EmotetRcloneFile (Join-Path $p.Lure 'info_1805.zip') 'INERT ZIP-NAME CANARY. Contains no attachment or executable content.' 'phishing archive canary'
Write-EmotetRcloneFile (Join-Path $p.Lure 'info_1805.xls') 'INERT EXCEL 4.0 MACRO-NAME CANARY. This text file has no workbook structure, formulas, or macros.' 'malicious workbook canary'
Write-EmotetRcloneFile (Join-Path $p.AppData 'hvxda.ocx') 'INERT DOWNLOAD-NAME CANARY. Not an ActiveX control or PE file.' 'macro download canary'
Write-EmotetRcloneFile (Join-Path $p.AppData 'llJyMIOvft.dll') 'INERT EMOTET DLL-NAME CANARY. Not a PE file.' 'Emotet payload canary'
$regsvr = Join-Path $p.Payloads 'regsvr32.exe'
New-EmotetRcloneDecoy $regsvr 'regsvr32/Emotet stand-in' '2b2e00ed89ce6898b9e58168488e72869f8e09f98fecb052143e15e98e5da9df'
Invoke-EmotetRcloneDecoy $regsvr 'EXCEL.EXE -> regsvr32.exe /s ..\hvxda.ocx; resolved random payload llJyMIOvft.dll' 'EXCEL.EXE'

$macroUrls = @(
    'praachichemfood.com/wp-content/Mwmos/',
    'lopespublicidade.com/cgi-bin/e5R5oG4iEaQnxQrZDh/',
    'bosny.com/aspnet_client/rnMp0ofR/',
    'seasidesolutions.com/cgi-bin/WLoO6sEzYCJ3LTlC/',
    'borgelin.org/belzebub/okwRWz1C/',
    'loa-hk.com/wp-content/ffBag/'
)
foreach ($url in $macroUrls) { Invoke-EmotetRcloneLoopback 80 $url 'reported Excel macro URL' }
Invoke-EmotetRcloneLoopback 8080 '103.8.26.17:8080; representative Emotet epoch5 second-stage endpoint' 'Emotet marker'
foreach ($command in @('systeminfo','ipconfig /all')) { Invoke-EmotetRcloneDecoy $regsvr $command 'llJyMIOvft.dll'; Add-EmotetRcloneManifest discovery-command generated-commandline-only represented @{reportedCommandLine=$command;executedDiscovery=$false} }

Write-EmotetRcloneFile (Join-Path $p.Evidence 'run-key-negative-record.json') (@{reportedPath='HKCU\Software\Microsoft\Windows\CurrentVersion\Run';registryWrites=0;sysmonEventIdsReported=@(12,13);malwareExecuted=$false} | ConvertTo-Json -Depth 5) 'persistence safety record'
$mailOffsets = @(.67,31,68)
for ($burst=0; $burst -lt $mailOffsets.Count; $burst++) {
    for ($message=1; $message -le 3; $message++) {
        $eml = "From: generated-sender-$message@invalid.example`r`nTo: generated-recipient-$message@invalid.example`r`nSubject: Invoice follow-up`r`nX-DFIR-Canary: Emotet-spreader-day-$($burst+1)`r`n`r`nGenerated mail-spread evidence only. No message was transmitted."
        Write-EmotetRcloneFile (Join-Path $p.Mail ("day{0}-message{1}.eml" -f ($burst+1),$message)) $eml 'generated EML canary'
    }
    Add-EmotetRcloneTimeline $mailOffsets[$burst] delivery "Emotet email-spreader burst for day $($burst+1) represented" @{messagesGenerated=3;messagesSent=0;SMTPConnections=0;dayBoundaryPattern=$true}
}
Write-EmotetRcloneFile (Join-Path $p.Evidence 'phishing-mail-negative-record.json') (@{attachmentsOpened=0;macrosExecuted=0;payloadsDownloaded=0;registryWrites=0;messagesSent=0;SMTPConnections=0;IOCConnections=0} | ConvertTo-Json) 'initial-access safety record'
Add-EmotetRcloneTimeline 0 initial-access 'ZIP attachment, info_1805.xls Excel 4.0 macro, six download URLs, hvxda.ocx, and random Emotet DLL represented' @{filesExecuted=0;downloads=0;techniques=@('T1566','T1566.001','T1204.002','T1218.010')}
Add-EmotetRcloneTimeline .1 persistence 'Emotet random Local AppData folder and repeated Run-key telemetry represented' @{registryWrites=0;technique='T1547.001'}
