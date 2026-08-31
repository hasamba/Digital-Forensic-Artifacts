#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Year2021Sim-utilities.ps1"
Assert-Year2021SimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-Year2021SimEnvironment

for ($case = 1; $case -le 14; $case++) {
    $lane = Join-Path $paths.Cases ('case-{0:d2}' -f $case)
    $method = @('scheduled task', 'BITS job', 'registry Run key', 'new user', 'remote-access software')[($case - 1) % 5]
    Write-Year2021SimFile (Join-Path $lane 'persistence-observation.json') (@{ syntheticLane = $case; aggregateMethod = $method; persistenceCreated = $false; mappingIsObservedCaseCorrelation = $false } | ConvertTo-Json) 'aggregate persistence marker'
}
foreach ($name in @('AnyDesk.exe', 'TeamViewer.exe', 'Splashtop.exe', 'AteraAgent.msi')) {
    Write-Year2021SimFile (Join-Path $paths.Tooling $name) "INERT REMOTE-ACCESS TOOL-NAME CANARY: $name. Not an installer or executable." 'RMM canary'
}

$procdump = Join-Path $paths.Tooling 'procdump.exe'
$adfind = Join-Path $paths.Tooling 'AdFind.exe'
New-Year2021SimDecoy $procdump 'credential-access telemetry stand-in'
New-Year2021SimDecoy $adfind 'discovery telemetry stand-in'
foreach ($command in @(
    'Task Manager or ProcDump dump of LSASS; Cobalt Strike Mimikatz/security-hive access',
    'ntdsutil create NTDS.dit copy; save SAM SECURITY SYSTEM hives',
    'process injection and security-tool disablement observed in five cases'
)) { Invoke-Year2021SimDecoy $procdump $command 'Cobalt Strike beacon' }
foreach ($command in @(
    'net time',
    'ping [Domain Controller]',
    'nltest /dclist:[Domain Name]',
    'net group "Domain Admins" /domain',
    'nslookup',
    'ping 190.114.254.116',
    'net group /domain',
    'AdFind domain enumeration',
    'Advanced IP Scanner and KPortScan 3.0 remote port/service enumeration'
)) { Invoke-Year2021SimDecoy $adfind $command 'Cobalt Strike beacon' }

foreach ($name in @('lsass.dmp', 'ntds.dit', 'SAM.hive', 'SECURITY.hive', 'SYSTEM.hive', 'adfind-results.txt', 'bloodhound-files.zip')) {
    Write-Year2021SimFile (Join-Path $paths.Evidence $name) "GENERATED NAME CANARY: $name. Contains no process memory, directory data, credentials, secrets, or collected host data." 'credential/discovery canary'
}
Write-Year2021SimFile (Join-Path $paths.Evidence 'persistence-credential-discovery-negative-record.json') (@{
    aggregatePersistenceCases = 14
    aggregateSecurityImpairmentCases = 5
    tasksBitsJobsRunKeysCreated = 0
    accountsCreatedOrChanged = 0
    remoteAccessToolsInstalled = 0
    processesInjected = 0
    securityControlsChanged = 0
    LSASSAccessed = $false
    NTDSOrHivesAccessed = $false
    credentialsCollected = 0
    directoryQueries = 0
    portScans = 0
    remoteHostsTouched = 0
} | ConvertTo-Json) 'phase safety record'
Add-Year2021SimTimeline 6 'persistence' 'Persistence represented in 14 synthetic lanes: tasks, BITS, Run keys, users, RMM, and redundant beacons' @{ aggregateCases = 14; persistenceChanges = 0 }
Add-Year2021SimTimeline 10 'credential-access' 'LSASS, ProcDump/Task Manager, Mimikatz, NTDS, and registry-hive access represented' @{ credentialsCollected = 0; protectedProcessesAccessed = 0 }
Add-Year2021SimTimeline 12 'defense-evasion' 'Process injection and five security-tool impairment cases represented' @{ aggregateCases = 5; processesInjected = 0; securityControlsChanged = 0 }
Add-Year2021SimTimeline 14 'discovery' 'One-to-five-second native-tool bursts, AdFind, Advanced IP Scanner, and KPortScan represented' @{ commandsReportedOnly = $true; directoryQueries = 0; portScans = 0 }
