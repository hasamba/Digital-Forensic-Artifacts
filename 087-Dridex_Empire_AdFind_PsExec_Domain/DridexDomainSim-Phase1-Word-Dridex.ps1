#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DridexDomainSim-utilities.ps1";Assert-DDSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DDEnvironment
Write-DDFile -Path(Join-Path $p.Payloads 'July2020_2485413825.doc')-Content 'INERT WORD-DOCUMENT NAME CANARY. No OLE, VBA, macro, link, or executable content.' -Purpose initial-access-canary
Write-DDJson -Path(Join-Path $p.Evidence 'word-delivery.json')-Object([ordered]@{reportedFile='July2020_2485413825.doc';publishedSha256='e3589aa5d687e58ee97bda2c501bcba9d5e942fe929644602dd1645b3c7f0e94';reportedAnalysis='olevba indicated OLE, macros, auto-execution, suspicious keywords, IOCs, and Dridex strings';documentOpened=$false;macrosExecuted=0;downloads=0})-Purpose initial-access
$dridex=Join-Path $p.Payloads 'rvhz1.dll';$runner=Join-Path $p.Payloads 'rundll32.exe';$bde=Join-Path $p.Payloads 'bdechangepin.exe'
New-DDDecoy -Path $dridex -Role 'Dridex rvhz1 DLL stand-in' -PublishedSha256 '076547c290c80627993690a9e6c15eeb2ac9b86a9a33af2d3dbaab135f1f43ab'
New-DDDecoy -Path $runner -Role 'rundll32 telemetry stand-in'
New-DDDecoy -Path $bde -Role 'Run-key payload stand-in'
Invoke-DDDecoy -FilePath $runner -Reported 'C:\Windows\System32\rundll32.exe C:/Windows/Temp//rvhz1.dll DllRegisterServer' -Parent 'scheduled task Zvhlxdonjwfvei' -Label 'NO-DLL-LOAD'
Write-DDJson -Path(Join-Path $p.Evidence 'persistence-markers.json')-Object([ordered]@{reportedTask=[ordered]@{name='Zvhlxdonjwfvei';runCommand='schtasks.exe /run /tn "Zvhlxdonjwfvei"';action='rundll32.exe C:/Windows/Temp//rvhz1.dll DllRegisterServer'};reportedRunKey=[ordered]@{path='HKEY_USERS\SID\Software\Microsoft\Windows\CurrentVersion\Run\Zvhlxdonjwfvei';command='%APPDATA%\Microsoft\SystemCertificates\My\CRLs\swET\bdechangepin.exe'};tasksCreated=0;registryValuesWritten=0;dllsLoaded=0})-Purpose persistence
foreach($target in @('192.99.103.228:443','64.118.8.15:443')){Invoke-DDLoopback -Port 443 -Target $target -Role 'initial Dridex C2 marker'}
Write-DDJson -Path(Join-Path $p.Evidence 'j10b9-stage.json')-Object([ordered]@{reportedCommand='cmd.exe /c %TEMP%\J10B9.cmd > %TEMP%\yp710BA.tmp 2> %TEMP%\1N10CB.tmp';reportedPurpose='transition to Empire stage hours later';batchExecuted=$false;stdoutRedirected=$false;stderrRedirected=$false})-Purpose execution
Add-DDTimeline 0 initial-access 'Malicious Word document and Dridex macro lineage represented' @{documentOpened=$false;macrosExecuted=0}
Add-DDTimeline 8 persistence 'Zvhlxdonjwfvei task and Run-key persistence represented' @{tasksCreated=0;registryValuesWritten=0;dllsLoaded=0}
Add-DDTimeline 15 command-and-control 'Initial Dridex TLS endpoints represented' @{externalConnections=0;bytesTransferred=0}
Add-DDTimeline 120 execution 'J10B9.cmd transition to Empire represented hours later' @{batchExecuted=$false}
Write-DDJson -Path(Join-Path $p.Evidence 'phase1-negative.json')-Object([ordered]@{documentOpened=$false;macrosExecuted=0;liveMalware=0;downloads=0;tasksCreated=0;registryValuesWritten=0;dllsLoaded=0;externalConnections=0;bytesTransferred=0})-Purpose safety
