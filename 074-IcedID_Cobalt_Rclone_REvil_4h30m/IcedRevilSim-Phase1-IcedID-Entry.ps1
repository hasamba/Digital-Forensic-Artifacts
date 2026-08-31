#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedRevilSim-utilities.ps1"
Assert-IRSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-IREnvironment

Write-IRFile (Join-Path $paths.Payloads 'malspam-attachment.xlsm') 'INERT XLSM-NAME CANARY. This is plain text with no Office structure, macro, formula, or code.' lure
Write-IRFile (Join-Path $paths.Profile 'Users\Public\microsoft.security') 'INERT ICEDID STAGE-NAME CANARY. No PE, DLL, script, or executable content.' payload
Write-IRFile (Join-Path $paths.Payloads 'index.gif') 'INERT INDEX.GIF-NAME CANARY. The report observed an executable response; this file is plain text.' payload
Write-IRFile (Join-Path $paths.Profile 'Users\analyst\AppData\Local\Temp\skull-x64.dat') 'INERT ICEDID DLL-NAME CANARY. No PE exports or code.' payload
Write-IRFile (Join-Path $paths.Profile 'Users\analyst\AppData\Local\Temp\DwarfWing\license.dat') 'INERT ICEDID LICENSE-NAME CANARY. No configuration or code.' payload

$excel = Join-Path $paths.Payloads 'excel.exe'
$wmic = Join-Path $paths.Payloads 'wmic.exe'
$regsvr = Join-Path $paths.Payloads 'regsvr32.exe'
$rundll = Join-Path $paths.Payloads 'rundll32.exe'
New-IRDecoy $excel 'Office lure execution stand-in'
New-IRDecoy $wmic 'WMIC child stand-in'
New-IRDecoy $regsvr 'regsvr32 stage stand-in'
New-IRDecoy $rundll 'IcedID rundll32 stand-in'
Invoke-IRDecoy $excel 'EXCEL.EXE opens malicious XLSM and enables macro' 'explorer.exe'
Invoke-IRDecoy $wmic "wmic.exe process call create 'regsvr32 -s C:\Users\Public\microsoft.security'" 'EXCEL.EXE'
Invoke-IRDecoy $regsvr 'regsvr32 -s C:\Users\Public\microsoft.security; reported download http://vpu03jivmm03qncgx.com/index.gif' 'wmic.exe'
Invoke-IRDecoy $rundll 'rundll32.exe "C:\Users\USERNAME\AppData\Local\Temp\skull-x64.dat",update /i:"DwarfWing\license.dat"' 'regsvr32.exe'

Write-IRFile (Join-Path $paths.Evidence 'scheduled-task.json') (@{
    name='wewouwquge_{A3112501-520A-8F32-871A-380B92917B3D}'
    reportedRegistry='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\wewouwquge_{A3112501-520A-8F32-871A-380B92917B3D}'
    tasksCreated=0
    registryChanged=$false
} | ConvertTo-Json -Depth 5) persistence

$recon = @(
    'cmd.exe /c chcp >&2',
    'WMIC.exe /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get * /Format:List',
    'ipconfig.exe /all',
    'systeminfo',
    'net config workstation',
    'nltest /domain_trusts',
    'nltest /domain_trusts /all_trusts',
    'net view /all /domain',
    'net view /all',
    'net.exe group "Domain Admins" /domain'
)
foreach ($command in $recon) { Invoke-IRDecoy $wmic $command 'IcedID/rundll32.exe' }
Write-IRFile (Join-Path $paths.Evidence 'initial-discovery.json') (@{reportedCommands=$recon;commandsActuallyRun=@('/d /v:off /c echo ICED-REVIL-CANARY');hostOrDomainDiscoveryPerformed=$false} | ConvertTo-Json -Depth 6) discovery

foreach ($target in @('206.189.10.247:80','161.35.109.168:443','cikawemoret34.space:80','nomovee.website:443')) {
    $port = if ($target -match ':80$') { 80 } else { 443 }
    Invoke-IRLoopback $port $target 'IcedID C2 marker'
}
Write-IRFile (Join-Path $paths.Evidence 'phase1-negative.json') (@{malwarePresent=$false;documentsOpened=0;macrosExecuted=0;downloads=0;externalConnections=0;tasksCreated=0;registryChanges=0;discoveryCommandsRun=0} | ConvertTo-Json) safety
Add-IRTimeline 0 initial-access 'Malspam XLSM, microsoft.security, and index.gif delivery chain represented' @{downloads=0;macrosExecuted=0}
Add-IRTimeline 1 execution 'Excel-to-WMIC-to-regsvr32 and IcedID rundll32 ancestry represented with signed decoys' @{reportedOnly=$true}
Add-IRTimeline 3 persistence 'IcedID scheduled-task and TaskCache artifacts represented' @{tasksCreated=0}
Add-IRTimeline 5 discovery 'IcedID host, domain, trust, network, and security-product discovery represented' @{discoveryCommandsRun=0}
