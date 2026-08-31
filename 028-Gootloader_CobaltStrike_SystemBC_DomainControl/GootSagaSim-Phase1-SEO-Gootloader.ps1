#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GootSagaSim-utilities.ps1";Assert-GootSagaSafety -LabConfirmed:$LabConfirmed;$p=Initialize-GootSagaEnvironment
Write-GootSagaFile(Join-Path $p.Lure 'Implied_employment_agreement_70159.zip')'INERT ZIP-NAME CANARY. No archive members or executable content.''SEO-download canary'
Write-GootSagaFile(Join-Path $p.Lure 'Implied_employment_agreement_70159.zip.Zone.Identifier')"[ZoneTransfer]`nZoneId=3"'Mark-of-the-Web evidence'
Write-GootSagaFile(Join-Path $p.Lure 'implied employment agreement 24230.js')'INERT JAVASCRIPT-NAME CANARY. No JavaScript statements.''Gootloader stage canary'
Write-GootSagaFile(Join-Path $p.Beachhead 'AppData\Roaming\Frontline Management.js')'INERT FRONTLINE MANAGEMENT CANARY. No JavaScript statements.''Gootloader persistence canary'
$runner=Join-Path $p.Beachhead 'wscript.exe';New-GootSagaDecoy $runner 'signed stand-in for Gootloader execution chain';Invoke-GootSagaDecoy $runner 'explorer.exe -> wscript.exe -> Frontline Management.js -> cscript.exe -> powershell.exe'
$task=[ordered]@{name='InfrSiRfucture Technologies';trigger='LogonTrigger';action='wscript.exe Frontline Management.js';created=$false;registered=$false};Write-GootSagaFile(Join-Path $p.Evidence 'scheduled-task-negative-record.json')($task|ConvertTo-Json)'task evidence'
$endpoints=@('hrclubphilippines.com/xmlrpc.php','mediacratia.ru/xmlrpc.php','daraltanweer.com/xmlrpc.php','ukrainians.today/xmlrpc.php','my-little-kitchen.com/xmlrpc.php','montages.no/xmlrpc.php','pocketofpreschool.com/xmlrpc.php','blog.lilianpraskova.cz/xmlrpc.php','sitmeanssit.com/xmlrpc.php','artmodel.com.ua/xmlrpc.php')
foreach($endpoint in $endpoints){Invoke-GootSagaLoopback 80 $endpoint 'Gootloader rotating endpoint'}
$registry=[ordered]@{reportedHive='HKCU\Software\Microsoft\Personalization';values=@(@{name='geRBAdXTDCkN';role='stage1 DLL';written=$false},@{name='cbkSBtbjQBNFy';role='stage2/Cobalt Strike';written=$false});actualRepresentation='JSON file only';reflectionAssemblyLoad=$false};Write-GootSagaFile(Join-Path $p.Registry 'Personalization\payload-values.json')($registry|ConvertTo-Json -Depth 5)'virtual registry evidence'
Add-GootSagaTimeline 0 initial-access 'SEO-poisoned employment-agreement lure and user execution represented' @{motw=3;techniques=@('T1189','T1204.002','T1059.007')}
Add-GootSagaTimeline 5 persistence 'Frontline Management.js and logon task represented without registration' @{taskCreated=$false;technique='T1053.005'}
Add-GootSagaTimeline 540 command-and-control 'Weaponized endpoint returned stage data after about nine hours; virtual registry values and memory-load evidence created' @{reportedEndpoint='46.28.105.94 blog.lilianpraskova.cz/xmlrpc.php';remoteContact=$false;registryWritten=$false;techniques=@('T1112','T1027','T1055')}
