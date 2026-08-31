#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\OilKeySim-utilities.ps1"
Assert-OilKeySafety -LabConfirmed:$LabConfirmed
$paths = Initialize-OilKeyEnvironment

$moduleExe = Join-Path $paths.Modules 'module.exe'
New-OilKeyDecoy $moduleExe 'Signed cmd.exe stand-in for renamed AutoHotkey interpreter' 'b92be3d086372fc89b3466e8d9707de78a5b6dff3e4a2eecc92c01d55a86fd7d'
Write-OilKeyFile (Join-Path $paths.Modules 'module.ahk') '; INERT AutoHotkey-name canary. Contains no hooks, hotkeys, or capture logic.' 'keylogger-script canary'
Write-OilKeyFile (Join-Path $paths.Modules 'readkey.ps1') '# INERT reader-name canary. It never reads the registry or keyboard data.' 'keylogger-reader canary'
Write-OilKeyFile (Join-Path $paths.Modules 't.xml') '<Task><Description>INERT task XML canary; never registered.</Description></Task>' 'scheduled-task XML canary'
Invoke-OilKeyDecoy $moduleExe 'module.exe module.ahk' 'taskeng.exe'

$task = [ordered]@{name='MicrosoftEdgeUpdateTaskMachineUC';xmlUri='\masdfm';trigger='user logon';principal='least privilege';actions=@('module.exe module.ahk','powershell.exe -File readKey.ps1');created=$false}
Write-OilKeyFile (Join-Path $paths.Evidence 'MicrosoftEdgeUpdateTaskMachineUC-negative-record.json') ($task | ConvertTo-Json -Depth 5) 'scheduled-task evidence'
$generatedKeys = 'GENERATED CANARY ONLY: [2022-08-08T09:15:00Z] Lumen application training text; no keyboard input was observed.'
Write-OilKeyFile (Join-Path $paths.Collection 'KeypressValue.canary') $generatedKeys 'registry-value stand-in'
Write-OilKeyFile (Join-Path $paths.Collection 'logFileuyovaqv.bin') ('XOR-NAME CANARY`n' + $generatedKeys) 'generated keylog stand-in'
Write-OilKeyFile (Join-Path $paths.Evidence 'keylogger-negative-record.json') (@{keyboardHooksInstalled=0;keystrokesRead=0;clipboardRead=$false;registryKeysCreated=0;registryValuesRead=0;generatedCanaryOnly=$true} | ConvertTo-Json) 'collection safety record'
Add-OilKeyTimeline 72 collection 'AutoHotkey module.exe/module.ahk keylogger stack and logon task represented' @{keyboardHooksInstalled=0;taskCreated=$false;techniques=@('T1056.001','T1053.005')}
Add-OilKeyTimeline 72.1 collection 'KeypressValue registry staging and readkey.ps1 XOR output represented with generated text' @{registryChanged=$false;keystrokesRead=0;technique='T1112'}
