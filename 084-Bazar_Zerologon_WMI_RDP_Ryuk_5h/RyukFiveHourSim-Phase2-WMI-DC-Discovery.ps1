#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukFiveHourSim-utilities.ps1"
Assert-R5Safety -LabConfirmed:$LabConfirmed
$p = Initialize-R5Environment

$secondary = New-R5HostTree -Name 'DC02-CANARY' -Role 'generated secondary domain controller representation'
$primary = New-R5HostTree -Name 'DC01-CANARY' -Role 'generated primary domain controller representation'
$servisses = Join-Path $p.Payloads 'servisses.exe'
$sql = Join-Path $p.Payloads 'SQL.dll'
$arti = Join-Path $p.Payloads 'arti64.dll'
$socks = Join-Path $p.Payloads 'socks64.dll'
$adfind = Join-Path $p.Payloads 'AdFind.exe'
$runner = Join-Path $p.Payloads 'rundll32.exe'
$registrar = Join-Path $p.Payloads 'regsvr32.exe'
$wmic = Join-Path $p.Payloads 'wmic.exe'
$mmc = Join-Path $p.Payloads 'mmc.exe'
New-R5Decoy -Path $servisses -Role 'Cobalt Strike executable stand-in' -PublishedSha256 '1d8b7faf5f290465cc742e07abca78fac419135b191071cc77912263cd1dde1d'
New-R5Decoy -Path $sql -Role 'Cobalt Strike SQL DLL stand-in' -PublishedSha256 'd67461ba45a4edf3b2a69b3e64303fda8130bd1fc7a1173f35c1fe67b40c9639'
New-R5Decoy -Path $arti -Role 'Cobalt Strike arti64 DLL stand-in' -PublishedSha256 'd67461ba45a4edf3b2a69b3e64303fda8130bd1fc7a1173f35c1fe67b40c9639'
New-R5Decoy -Path $socks -Role 'Cobalt Strike SOCKS DLL stand-in' -PublishedSha256 'feb8c2bcb71da02dbbeecb999869e053cf96af8cce6f9705cadca4338133d3b5'
New-R5Decoy -Path $adfind -Role 'AdFind stand-in'
New-R5Decoy -Path $runner -Role 'rundll32 telemetry stand-in'
New-R5Decoy -Path $registrar -Role 'regsvr32 telemetry stand-in'
New-R5Decoy -Path $wmic -Role 'WMI telemetry stand-in'
New-R5Decoy -Path $mmc -Role 'GPO console telemetry stand-in'

Invoke-R5Decoy -FilePath $wmic -Reported 'C:\Windows\system32\cmd.exe /C WMIC /node:"DC.DOMAIN.local" process call create "cmd /c C:\PerfLogs\servisess.exe"' -Parent 'Bazar beachhead shell' -Label 'NO-WMI'
Write-R5Json -Path (Join-Path $p.Evidence 'smb-wmi-movement.json') -Object ([ordered]@{reportedSource='beachhead';reportedTarget='DC not affected by Zerologon';reportedTransfer='servisess.exe over SMB using a domain administrator account';reportedExecution='remote WMI process creation';generatedTargets=@($secondary,$primary);validAccountsUsed=0;smbSessions=0;remoteFilesWritten=0;WmiCalls=0;processesCreated=0}) -Purpose lateral-movement
Write-R5Json -Path (Join-Path $p.Evidence 'trial-cobalt-marker.json') -Object ([ordered]@{reportedEdition='Cobalt Strike trial';reportedEvidence='EICAR string in beacon network configuration';EicarFileCreated=$false;antivirusTestTriggered=$false}) -Purpose command-and-control
Write-R5Json -Path (Join-Path $p.Evidence 'named-pipe-escalation.json') -Object ([ordered]@{reportedCommand='C:\Windows\system32\cmd.exe /c echo 92d8cc45954 > \\.\pipe\446b3c';reportedModule='default Cobalt Strike named-pipe privilege escalation';namedPipesCreated=0;pipeBytesWritten=0;privilegeChanges=0}) -Purpose privilege-escalation

$dllCommands = @('C:\Windows\system32\cmd.exe /C rundll32 C:\Windows\system32\SQL.dll, StartW','rundll32 C:\PerfLogs\arti64.dll, rundll','regsvr32 C:\PerfLogs\arti64.dll','rundll32 C:\PerfLogs\socks64.dll, rundll')
foreach ($command in $dllCommands) {
    $tool = if ($command -like 'regsvr32*') { $registrar } else { $runner }
    Invoke-R5Decoy -FilePath $tool -Reported $command -Parent 'Cobalt Strike beacon on generated DC representation' -Label 'NO-DLL-LOAD'
}
Write-R5Json -Path (Join-Path $p.Evidence 'dll-proxy-execution.json') -Object ([ordered]@{reportedCommands=$dllCommands;dllsLoaded=0;dllsRegistered=0;exportsCalled=0;codeExecution=$false}) -Purpose defense-evasion

$dcCommands = @('net group "enterprise admins" /domain','nltest /domain_trusts /all_trusts','nltest /dclist:"DOMAIN"','ping DOMAINCONTROLLER','cmd.exe /C time','net user administrator /domain')
foreach ($command in $dcCommands) { Invoke-R5Decoy -FilePath $servisses -Reported $command -Parent 'Cobalt Strike beacon on DC02' -Label 'SYNTHETIC-DC-DISCOVERY' }
$adComputer = 'Get-ADComputer -Filter {enabled -eq $true} -properties * | select Name,DNSHostName,OperatingSystem,LastLogonDate | Export-CSV C:\Users\AllWindows.csv -NoTypeInformation -Encoding UTF8'
Invoke-R5Decoy -FilePath $servisses -Reported $adComputer -Parent 'PowerShell Active Directory module on DC02' -Label 'NO-POWERSHELL-AD'
Write-R5File -Path (Join-Path $p.Staging 'AllWindows.csv') -Content "Name,DNSHostName,OperatingSystem,LastLogonDate`nDC01-CANARY,dc01-canary.lab-canary.local,Windows Server CANARY,2020-10-13T04:00:00Z`nDC02-CANARY,dc02-canary.lab-canary.local,Windows Server CANARY,2020-10-13T04:00:00Z`nBAK01-CANARY,bak01-canary.lab-canary.local,Windows Server CANARY,2020-10-13T04:00:00Z" -Purpose synthetic-discovery-output
$adfindCommands = @('adfind.exe -f "(objectcategory=person)"','adfind.exe -f "objectcategory=computer"','adfind.exe -f "(objectcategory=organizationalUnit)"','adfind.exe -sc trustdmp','adfind.exe -subnets -f (objectCategory=subnet)','adfind.exe -f "(objectcategory=group)"','adfind.exe -gcb -sc trustdmp')
foreach ($command in $adfindCommands) { Invoke-R5Decoy -FilePath $adfind -Reported $command -Parent 'C:\Windows\Temp\adf\adf.bat' -Label 'SYNTHETIC-ADFIND' }
Write-R5Json -Path (Join-Path $p.Evidence 'dc-discovery.json') -Object ([ordered]@{reportedCommands=$dcCommands;reportedAdModuleCommand=$adComputer;reportedAdFindPath='C:\Windows\Temp\adf\AdFind.exe';reportedBatchPath='C:\Windows\Temp\adf\adf.bat';reportedAdFindCommands=$adfindCommands;actualDirectoryQueries=0;actualPowerShellExecution=$false;syntheticCsv=(Join-Path $p.Staging 'AllWindows.csv')}) -Purpose discovery

Invoke-R5Decoy -FilePath $mmc -Reported 'mmc.exe C:\Windows\System32\gpedit.msc' -Parent 'RDP session on domain controller' -Label 'NO-GPO-ACCESS'
Write-R5Json -Path (Join-Path $p.Evidence 'gpo-access-marker.json') -Object ([ordered]@{reportedAccess='domain GPO console opened';reportStatesModifiedOrAdded=$false;GposRead=0;GposModified=0;GposCreated=0;SysvolAccess=0}) -Purpose collection
Invoke-R5Loopback -Port 445 -Target 'DC.DOMAIN.local' -Role 'SMB transfer marker'
Invoke-R5Loopback -Port 135 -Target 'DC.DOMAIN.local' -Role 'WMI RPC marker'
Invoke-R5Loopback -Port 3389 -Target 'primary and secondary domain controllers' -Role 'RDP pivot marker'
Invoke-R5Loopback -Port 443 -Target 'havemosts.com (88.119.171.94)' -Role 'servisses Cobalt C2 marker'
Invoke-R5Loopback -Port 443 -Target 'quwasd.com (5.2.64.174)' -Role 'SQL.dll Cobalt C2 marker'
Add-R5Timeline -Minutes 120 -Phase lateral-movement -Event 'SMB transfer and WMI execution to the DC not affected by Zerologon represented' -Details @{smbSessions=0;WmiCalls=0;remoteFilesWritten=0}
Add-R5Timeline -Minutes 155 -Phase discovery -Event 'Net, Nltest, time, user, and synthetic AD-computer inventory represented on DC02' -Details @{directoryQueries=0;PowerShellExecuted=$false}
Add-R5Timeline -Minutes 175 -Phase privilege-escalation -Event 'Default named-pipe escalation represented' -Details @{namedPipesCreated=0;privilegeChanges=0}
Add-R5Timeline -Minutes 190 -Phase lateral-movement -Event 'RDP from secondary to primary DC with built-in Administrator represented' -Details @{rdpSessions=0;validAccountsUsed=0}
Add-R5Timeline -Minutes 210 -Phase defense-evasion -Event 'SQL, arti64, and socks64 DLL execution via rundll32/regsvr32 represented' -Details @{dllsLoaded=0;dllsRegistered=0}
Add-R5Timeline -Minutes 225 -Phase discovery -Event 'AdFind batch and repeated trust discovery represented on primary DC' -Details @{actualDirectoryQueries=0}
Add-R5Timeline -Minutes 240 -Phase staging -Event 'Actors reported ready for final objective at hour four' -Details @{remoteTargetsChanged=0}
Write-R5Json -Path (Join-Path $p.Evidence 'phase2-negative.json') -Object ([ordered]@{validAccountsUsed=0;smbSessions=0;remoteFilesWritten=0;WmiCalls=0;remoteProcesses=0;namedPipesCreated=0;privilegeChanges=0;rdpSessions=0;dllsLoaded=0;dllsRegistered=0;PowerShellExecuted=$false;directoryQueries=0;GposRead=0;GposModified=0;SysvolAccess=0;externalConnections=0;bytesTransferred=0}) -Purpose safety
