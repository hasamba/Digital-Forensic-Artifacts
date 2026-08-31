#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SnatchFiveSim-utilities.ps1";Assert-S5Safety -LabConfirmed:$LabConfirmed;$p=Initialize-S5Environment
$cpl=Join-Path $p.Payloads 'cplXen.exe';$x3=Join-Path $p.Payloads 'x3.exe';New-S5Decoy -Path $cpl -Role 'Meterpreter/Cobalt-like reverse-shell stand-in' -PublishedSha256 'c305b75a4333c7fca9d1d71b660530cc98197b171856bf433e4e8f3af0424b11';New-S5Decoy -Path $x3 -Role 'cplXen persistence loader stand-in' -PublishedSha256 'b9e4299239880961a88875e1265db0ec62a8c4ad6baf7a5de6f02ff4c31fcdb1'
Invoke-S5Decoy -FilePath $cpl -Reported 'cplXen.exe reverse shell over HTTPS/443 to 91.229.77.161' -Parent 'DC RDP session' -Label 'NO-REVERSE-SHELL';Invoke-S5Loopback -Port 443 -Target '91.229.77.161' -Role 'cplXen C2 marker'
Write-S5Json -Path(Join-Path $p.Evidence 'c2-and-pipe-marker.json')-Object([ordered]@{reportedTool='Meterpreter or possibly Cobalt Strike';reportedC2='91.229.77.161:443';reportedNamedPipeServiceLogs=$true;reverseShells=0;namedPipesCreated=0;servicesCreated=0;externalConnections=0;bytesTransferred=0})-Purpose command-and-control
$config=[ordered]@{'jd4ob7162ns.dll'='C:\windows\system32\cplXen.exe /F';'fw0a53482aa.dll'='443';'kb05987631s.dll'='91.229.77.161'}
foreach($entry in $config.GetEnumerator()){Write-S5File -Path(Join-Path $p.Payloads $entry.Key)-Content "INERT CONFIG-NAME CANARY. Reported value: $($entry.Value). No DLL or executable content." -Purpose payload-canary}
Invoke-S5Decoy -FilePath $x3 -Reported 'x3.exe reads three DLL-named configuration files and launches cplXen.exe' -Parent 'scheduled task' -Label 'NO-LOADER'
Write-S5Json -Path(Join-Path $p.Evidence 'persistence-markers.json')-Object([ordered]@{reportedConfig=$config;reportedTasks=@([ordered]@{name='Regular Idle Maintenance';schedule='DAILY 00:00'},[ordered]@{name='Regular Idle Maintenances';schedule='ONSTART'});tasksCreated=0;dllsLoaded=0;loadersPersisted=0})-Purpose persistence
Write-S5Json -Path(Join-Path $p.Evidence 'ditsnap-ntds-marker.json')-Object([ordered]@{reportedTool='ditsnap';reportedTarget='NTDS.DIT copy via snapshot on domain controller';reportConfidence='most likely';snapshotsCreated=0;ntdsPathsOpened=0;directoryDatabaseBytesRead=0;credentialMaterial=0})-Purpose credential-access
Add-S5Timeline 185 command-and-control 'cplXen HTTPS reverse shell and named-pipe-service evidence represented' @{reverseShells=0;namedPipesCreated=0}
Add-S5Timeline 195 persistence 'x3 loader, three config files, and two scheduled tasks represented' @{tasksCreated=0;dllsLoaded=0}
Add-S5Timeline 220 credential-access 'About 30 minutes after C2, Ditsnap/NTDS snapshot behavior represented' @{snapshotsCreated=0;ntdsPathsOpened=0;credentialMaterial=0}
Write-S5Json -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{reverseShells=0;namedPipesCreated=0;servicesCreated=0;tasksCreated=0;dllsLoaded=0;snapshotsCreated=0;ntdsPathsOpened=0;directoryDatabaseBytesRead=0;credentialMaterial=0;externalConnections=0;bytesTransferred=0})-Purpose safety
