#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\GraceWipeSim-utilities.ps1"
Assert-GraceWipeSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-GraceWipeEnvironment

Write-GraceWipeFile (Join-Path $paths.Lure '404-TDS-redirect-chain.txt') "hrcbishtek[.]com/{id}`nimsagentes[.]pe/dgrjfj`necorfan[.]org/base/sj/Document_may_24_16654.exe`nMETADATA ONLY - no request was sent." 'TDS metadata'
$truebot = Join-Path $paths.Lure 'Document_may_24_16654.exe'
New-GraceWipeDecoy $truebot 'Truebot fake Adobe document stand-in' '717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb'
Invoke-GraceWipeDecoy $truebot 'User opened fake Adobe document; failure dialog displayed'
$runtime = Join-Path $paths.Beach 'C-Intel-Replica\RuntimeBroker.exe'
New-GraceWipeDecoy $runtime 'renamed Truebot RuntimeBroker stand-in' '717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb'
Invoke-GraceWipeDecoy $runtime 'Document_may_24_16654.exe -> C:\Intel\RuntimeBroker.exe'
Invoke-GraceWipeLoopback 443 'essadonio.com / 45.182.189.71 Truebot C2' 'TLS marker'

foreach ($name in @('spoolsv.exe','msiexec.exe','svchost.exe','cmd.exe')) {
    $decoy = Join-Path $paths.Beach "process-ancestry\$name"
    New-GraceWipeDecoy $decoy "FlawedGrace $name process stand-in"
    Invoke-GraceWipeDecoy $decoy "RuntimeBroker.exe -> $name; injection was reported but not performed"
}
Write-GraceWipeFile (Join-Path $paths.Payloads 'c.dll') 'INERT FLAWEDGRACE ICUI N DLL-NAME CANARY. Not a PE file.' 'FlawedGrace payload canary'
$persistence = [ordered]@{
    initialTask='\2';persistentTasks=@('\Microsoft\Windows\System diagnostics service','\Microsoft\Windows\System diagnostics monitor','\Microsoft\Windows\System monitor','\Microsoft\Windows\System service');bootTrigger=$true
    stagedRegistry='HKLM\SOFTWARE\2\CLSID\{8D81676C-7F63-8F81-676E-666B6C67818D}';finalRegistry='HKLM\Classes\CLSID\{8D81676C-7F63-8F81-676E-666B6C67818D}\TypeLib'
    rc4HostnameKey=$true;tasksCreated=0;registryKeysWritten=0;processesInjected=0;spoolerStopped=$false;requiredPrivilegesDeleted=$false
}
Write-GraceWipeFile (Join-Path $paths.Evidence 'flawedgrace-persistence-negative-record.json') ($persistence | ConvertTo-Json -Depth 6) 'persistence negative record'
$controls = [ordered]@{defenderRealtimeDisabled=$false;defenderExclusionsAdded=0;account='adminr';accountCreated=$false;administratorsGroupChanged=$false;remoteDesktopUsersGroupChanged=$false;rdpTunnelAttemptsRepresented=2;rdpConnections=0}
Write-GraceWipeFile (Join-Path $paths.Evidence 'defense-account-rdp-negative-record.json') ($controls | ConvertTo-Json -Depth 5) 'control and account negative record'
foreach ($target in @('92.118.36.199:443 initial FlawedGrace C2 and failed RDP tunnel','81.19.135.30:443 FlawedGrace C2','5.188.86.18:443 FlawedGrace C2')) { Invoke-GraceWipeLoopback 443 $target 'custom protocol marker' }
Add-GraceWipeTimeline 0 initial-access '404 TDS link and Truebot fake document represented' @{downloads=0;techniques=@('T1566.002','T1204.002')}
Add-GraceWipeTimeline .1 execution 'Truebot RuntimeBroker copy, FlawedGrace ancestry, and Cobalt injection represented' @{malwareExecuted=$false;injection=$false;techniques=@('T1036.005','T1055')}
Add-GraceWipeTimeline .3 persistence 'Registry-staged RC4 payload, temporary task, boot tasks, Spooler privilege abuse, and adminr RDP attempts represented' @{tasksCreated=0;registryWrites=0;servicesChanged=0;accountsCreated=0;techniques=@('T1053.005','T1027.011','T1140','T1543.003')}
