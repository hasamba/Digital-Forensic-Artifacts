#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ToolkitSim-utilities.ps1";Assert-ToolkitSafety -LabConfirmed:$LabConfirmed;$p=Initialize-ToolkitEnvironment
$inventory=[ordered]@{firstSeen='2023-12-10';infrastructure=@(@{address='94.198.53.143';reportedPorts=@(80,123,443,1337,8000,8443);history='PoshC2, Sliver, one Empire observation; intermittent Sep 2023-Aug 2024'},@{address='185.234.216.64';reportedPorts=@(123,443,8000);history='PoshC2; intermittent Oct 2023-Aug 2024'});httpHtmlHash=-1700067737;victimDataFound=$false;actualDestination='127.0.0.1';downloadedFiles=0}
Write-ToolkitFile(Join-Path $p.Evidence 'infrastructure.json')($inventory|ConvertTo-Json -Depth 8)'open-directory metadata';foreach($port in @(80,443,8000,8443)){Invoke-ToolkitLoopback $port "94.198.53.143:$port" 'open-directory/PoshC2/Sliver'};foreach($port in @(443,8000)){Invoke-ToolkitLoopback $port "185.234.216.64:$port" 'open-directory/PoshC2'}
$names=@('atera_del.bat','atera_del2.bat','backup.bat','clearlog.bat','cmd.cmd','def1.bat','defendermalwar.bat','delbackup.bat','disable.bat','hyp.bat','LOGOFALL.bat','LOGOFALL1.bat','NG1.bat','NG2.bat','ON.bat','shadow.bat','shadowGuru.bat','z.bat','z1.bat','poshc2+user.txt','py_dropper.sh','native_dropper','Setup_uncnow.msi','Posh_v2_dropper_x64.exe','VmManagedSetup.exe','WILD_PRIDE.exe','ngrok.exe')
foreach($n in $names){Write-ToolkitFile(Join-Path $p.Directory1 $n)"INERT OPEN-DIRECTORY INVENTORY MARKER: $n`nNo original content or executable code." 'directory listing canary'}
foreach($n in @('poshc2+user.txt','Setup_uncnow.msi','Posh_v2_dropper_x64.exe','VmManagedSetup.exe','WILD_PRIDE.exe')){Write-ToolkitFile(Join-Path $p.Directory2 $n)"INERT SECOND-DIRECTORY INVENTORY MARKER: $n" 'second directory canary'}
Add-ToolkitTimeline infrastructure 'Two open directories and long-lived C2 associations reconstructed' @{publicSystemsContacted=0;filesDownloaded=0;victims='none reported'}
