#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\OilKeySim-utilities.ps1"
Assert-OilKeySafety -LabConfirmed:$LabConfirmed
$paths = Initialize-OilKeyEnvironment

Write-OilKeyFile (Join-Path $paths.Lure 'Apply Form.docm') 'INERT DOCM-NAME CANARY. No OLE container, macro, or executable content.' 'spearphishing attachment canary'
$scriptPath = Join-Path $paths.Update 'Script.ps1'
$tempPath = Join-Path $paths.Update 'temp.ps1'
$vbsPath = Join-Path $paths.Update 'Updater.vbs'
Write-OilKeyFile $scriptPath '# INERT Script.ps1 canary. Published GET/PUT logic is metadata only.' 'PowerShell implant canary'
Write-OilKeyFile $tempPath '# INERT temp.ps1 canary. Server instructions are never decoded or run.' 'PowerShell command runner canary'
Write-OilKeyFile $vbsPath "' INERT Updater.vbs canary. Does not launch PowerShell." 'VBS launcher canary'

$powershellDecoy = Join-Path $paths.Update 'powershell.exe'
New-OilKeyDecoy $powershellDecoy 'Signed cmd.exe stand-in for macro-spawned PowerShell'
Invoke-OilKeyDecoy $powershellDecoy 'WINWORD.EXE -> powershell.exe -ExecutionPolicy Bypass -File Script.ps1' 'WINWORD.EXE'
Invoke-OilKeyDecoy $powershellDecoy 'wscript.exe Updater.vbs -> powershell.exe -WindowStyle Hidden -File Script.ps1' 'wscript.exe'

$task = [ordered]@{name='WindowsUpdate';trigger='every 10 minutes plus random one-minute delay and idle trigger';principal='least privilege';hidden=$true;action='wscript.exe "PATH\Updater.vbs"';created=$false}
Write-OilKeyFile (Join-Path $paths.Evidence 'WindowsUpdate-task-negative-record.json') ($task | ConvertTo-Json -Depth 5) 'scheduled-task evidence'
Invoke-OilKeyLoopback 80 'http://45.89.125.189/get' GET
Invoke-OilKeyLoopback 80 'http://45.89.125.189/put' POST
Write-OilKeyFile (Join-Path $paths.Evidence 'c2-crypto-metadata.json') (@{algorithm='AES-CBC';keyHex='171d84e841aee4c0fffba27c86d1ec82b8807cb8c3799a11b8fa2db7781fd15a';ivHex='183ced6fb3349f9ac6f908f929de3552';samplePlaintext='0!@#EWQ654!@#EWQpowershell -command Get-Process^%$RTY:';decryptionPerformed=$false} | ConvertTo-Json) 'published C2 metadata'

$commands = @(
    'wmic logicaldisk get caption,description,filesystem,freespace,size,volumename',
    'powershell -command Get-Process',
    'sc query WinDefend',
    'time /t',
    'tzutil /g',
    'tracert 8.8.8.8',
    'net accounts',
    'whoami /all',
    'powershell -command Get-ChildItem C:\Users -Force',
    'powershell -command Get-ComputerInfo',
    'powershell -command Get-NetTCPConnection',
    'powershell -command Get-NetIPConfiguration',
    'powershell -command Get-WmiObject Win32_ComputerSystem | Select-Object UserName',
    'powershell -command Get-MpComputerStatus',
    'powershell DirectorySearcher domain computer and account enumeration',
    'Invoke-WebRequest https://ident.me'
)
foreach ($command in $commands) { Invoke-OilKeyDecoy $powershellDecoy $command 'temp.ps1'; Add-OilKeyManifest discovery-command 'generated-commandline-only' represented @{reportedCommandLine=$command;executedDiscovery=$false;outputCollected=$false} }
Write-OilKeyFile (Join-Path $paths.Evidence 'discovery-negative-record.json') (@{commandsRepresented=$commands.Count;realQueriesExecuted=0;directoryServicesQueried=$false;publicIpServiceContacted=$false;resultsExfiltrated=$false} | ConvertTo-Json) 'discovery safety record'
Add-OilKeyTimeline 0 initial-access 'Apply Form.docm opened and macro-created Update directory represented' @{macroExecuted=$false;techniques=@('T1566.001','T1204.002')}
Add-OilKeyTimeline 0.1 execution 'Script.ps1, temp.ps1, and Updater.vbs process ancestry represented' @{PowerShellImplantExecuted=$false;technique='T1059.001'}
Add-OilKeyTimeline 0.2 persistence 'WindowsUpdate ten-minute hidden scheduled task represented' @{taskCreated=$false;technique='T1053.005'}
Add-OilKeyTimeline 24 command-and-control 'Initial 502 responses followed by AES-CBC GET/PUT beacon represented on loopback' @{realIOCContacted=$false;bytesTransferred=0;technique='T1573.001'}
Add-OilKeyTimeline 48 discovery 'System, process, user, network, security software, file, time, service, and domain discovery command lines represented' @{realQueriesExecuted=0;techniques=@('T1087.002','T1082','T1057','T1033','T1049','T1518.001','T1083','T1124','T1007')}
