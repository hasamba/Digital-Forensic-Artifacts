#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\MsiPlinkSim-utilities.ps1"
Assert-MsiPlinkSafety -LabConfirmed:$LabConfirmed
$p = Initialize-MsiPlinkEnvironment

$shell = Join-Path $p.Payloads 'powershell.exe'
New-MsiPlinkDecoy $shell 'fm2.jsp PowerShell child stand-in'
$commands = @('reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential','Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Value 1','query session','systeminfo','quser','arp -a','wmic computersystem get domain','netstat -an','ipconfig /all','tasklist')
foreach ($command in $commands) { Invoke-MsiPlinkDecoy $shell $command 'fm2.jsp/java.exe'; Add-MsiPlinkManifest reported-webshell-command generated-commandline-only represented @{reportedCommandLine=$command;actualQueryOrChange=$false} }
foreach ($offset in @(24,72,120,144)) { Add-MsiPlinkTimeline $offset discovery 'Periodic web-shell query session/quser check represented' @{sessionsQueried=0;usersObserved=0} }
Write-MsiPlinkFile (Join-Path $p.Evidence 'directory-browsing.json') (@{reportedPaths=@('C:\Windows\Temp','C:\Windows','C:\','C:\ALLibraries','C:\Users');synthetic=$true;realDirectoriesRead=0} | ConvertTo-Json) 'web-shell browsing evidence'
$dump = Join-Path $p.Payloads 'rundll32.exe'
New-MsiPlinkDecoy $dump 'comsvcs MiniDump stand-in'
Invoke-MsiPlinkDecoy $dump 'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump [LSASS-PID] C:\Windows\Temp\logctl.zip full' 'fm2.jsp/java.exe'
Write-MsiPlinkFile (Join-Path $p.Temp 'logctl.zip') 'GENERATED LSASS-DUMP/ZIP-NAME CANARY. Contains no memory, archive, credentials, or secrets.' 'credential canary'
Write-MsiPlinkFile (Join-Path $p.Evidence 'wdigest-lsass-discovery-negative-record.json') (@{registryQueries=0;registryWrites=0;WDigestEnabled=$false;sessionQueries=0;privilegedUsersObserved=0;LSASSAccessed=$false;memoryDumpsCreated=0;credentialsCollected=0;plaintextPasswordsCollected=0;archivesCreated=0;webShellDownloads=0;filesDeleted=0;realDirectoriesRead=0} | ConvertTo-Json) 'phase safety record'
Add-MsiPlinkTimeline .1 defense-evasion 'WDigest query followed 22 seconds later by UseLogonCredential=1 represented' @{registryWrites=0;WDigestEnabled=$false;techniques=@('T1012','T1112')}
Add-MsiPlinkTimeline 168 credential-access 'Day-seven privileged maintenance login, tasklist PID lookup, comsvcs LSASS dump, web-shell exfiltration, and deletion represented' @{LSASSAccessed=$false;credentialsCollected=0;bytesTransferred=0;filesDeleted=0;techniques=@('T1003','T1070.004')}
