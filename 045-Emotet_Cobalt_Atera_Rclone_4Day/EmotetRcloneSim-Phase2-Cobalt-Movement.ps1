#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetRcloneSim-utilities.ps1"
Assert-EmotetRcloneSafety -LabConfirmed:$LabConfirmed
$p = Initialize-EmotetRcloneEnvironment

$cobalt = Join-Path $p.Payloads 'UOmCgbXygCe.exe'
$dllhost = Join-Path $p.Payloads 'dllhost.exe'
$indexer = Join-Path $p.Payloads 'SearchIndexer.exe'
New-EmotetRcloneDecoy $cobalt 'Cobalt executable stand-in' 'f4c085ef1ba7e78a17a9185e4d5e06163fe0e39b6b0dc3088b4c1ed11c0d726b'
New-EmotetRcloneDecoy $dllhost 'Cobalt dllhost injection stand-in'
New-EmotetRcloneDecoy $indexer 'SearchIndexer LSASS-access stand-in'
Invoke-EmotetRcloneDecoy $cobalt 'llJyMIOvft.dll -> UOmCgbXygCe.exe; inject svchost.exe, dllhost.exe, explorer.exe' 'regsvr32.exe'
Invoke-EmotetRcloneLoopback 8080 '59.95.98.204:8080 GET /jquery-3.3.1.min.js POST /jquery-3.3.2.min.js' 'Cobalt Strike HTTP marker'

$discovery = @(
    'net group "Domain Computers" /domain',
    'net group /domain "Domain Admins"',
    'net group /domain "Enterprise Admins"',
    'systeminfo',
    'net users',
    'nltest /DOMAIN_TRUSTS',
    'Invoke-ShareFinder -CheckShareAccess'
)
foreach ($command in $discovery) { Invoke-EmotetRcloneDecoy $cobalt $command 'Cobalt beacon'; Add-EmotetRcloneManifest discovery-command generated-commandline-only represented @{reportedCommandLine=$command;directoryOrShareQueries=0} }
Invoke-EmotetRcloneDecoy $cobalt 'Invoke-Kerberoast' 'Cobalt beacon'
Write-EmotetRcloneFile (Join-Path $p.Evidence 'kerberoast-negative-record.json') (@{SPNsQueried=0;ticketRequests=0;accountsEnumerated=0;credentialsCollected=0} | ConvertTo-Json) 'Kerberoast safety record'

Write-EmotetRcloneFile (Join-Path $p.Payloads '1.dll') 'INERT COBALT DLL-NAME CANARY. Not a PE file.' 'lateral payload canary'
Write-EmotetRcloneFile (Join-Path $p.Payloads 'find.bat') '@REM INERT renamed-AdFind wrapper canary. No command is run.' 'AdFind wrapper canary'
Write-EmotetRcloneFile (Join-Path $p.Payloads 'p.bat') '@REM REPORTED ONLY: for /f %%i in (SERVERS.txt) do ping %%i -n 1 >> res.txt' 'ping wrapper canary'
Write-EmotetRcloneFile (Join-Path $p.Staging 'SERVERS.txt') "LAB-WS02.invalid`nLAB-SRV01.invalid`nLAB-DC01.invalid" 'generated host list'
$find = Join-Path $p.Payloads 'find.exe'
$dir = Join-Path $p.Payloads 'dir.exe'
New-EmotetRcloneDecoy $find 'renamed AdFind stand-in' '5a5c601ede80d53e87e9ccb16b3b46f704e63ec7807e51f37929f65266158f4c'
New-EmotetRcloneDecoy $dir 'share-listing stand-in'
foreach ($query in @('find.exe -f objectcategory=person','find.exe -f objectcategory=computer','find.exe -f objectcategory=organizationalUnit','find.exe -sc trustdmp','find.exe -subnets -f objectCategory=subnet','find.exe -f objectcategory=group','dir.exe \\LAB-SRV01.invalid\Shares')) { Invoke-EmotetRcloneDecoy $find $query 'Cobalt beacon' }
foreach ($name in @('ad_users.txt','ad_computers.txt','ad_ous.txt','trustdmp.txt','subnets.txt','ad_groups.txt','res.txt')) { Write-EmotetRcloneFile (Join-Path $p.Staging $name) "GENERATED OUTPUT $name. No directory, share, or network query occurred." 'generated discovery output' }

$sysmon10 = @{eventId=10;sourceImage='SearchIndexer.exe';targetImage='lsass.exe';grantedAccess=136208;synthetic=$true;actualProcessAccess=$false}
$sysmon17 = @{eventId=17;image='SearchIndexer.exe';pipeName='\SearchTextHarvester';synthetic=$true;actualPipeCreated=$false}
Write-EmotetRcloneFile (Join-Path $p.Evidence 'synthetic-sysmon-event-10.json') ($sysmon10 | ConvertTo-Json) 'synthetic process-access telemetry'
Write-EmotetRcloneFile (Join-Path $p.Evidence 'synthetic-sysmon-event-17.json') ($sysmon17 | ConvertTo-Json) 'synthetic named-pipe telemetry'

foreach ($port in @(445,135)) { Invoke-EmotetRcloneLoopback $port "SMB/PsExec movement of 1.dll to generated workstation and DC; port $port" 'lateral marker' }
Write-EmotetRcloneFile (Join-Path $p.Evidence 'synthetic-auth-events.json') (@{events=@(@{eventId=4624;logonType=9;authenticationPackage='Negotiate';logonProcess='seclogo'},@{eventId=4672;note='special privileges represented'},@{eventId=4776;note='DC credential validation represented'});synthetic=$true;actualLogons=0} | ConvertTo-Json -Depth 6) 'synthetic pass-the-hash telemetry'
Write-EmotetRcloneFile (Join-Path $p.Evidence 'movement-credential-negative-record.json') (@{reportedTechniques=@('Pass-the-Hash','PsExec/service','Get-System','LSASS dump','SMB transfer');remoteHostsTouched=0;remoteServicesCreated=0;SMBCopies=0;accountsAuthenticated=0;privilegeEscalations=0;LSASSAccessed=$false;credentialsCollected=0;namedPipesCreated=0;processesInjected=0} | ConvertTo-Json -Depth 5) 'movement safety record'
Add-EmotetRcloneTimeline 26 execution 'Emotet retrieves UOmCgbXygCe.exe; Cobalt injects into svchost, dllhost, and explorer' @{payloadsDownloaded=0;processesInjected=0;techniques=@('T1055','T1055.001','T1055.003','T1559.001')}
Add-EmotetRcloneTimeline 26.5 credential-access 'SearchIndexer LSASS access, SearchTextHarvester pipe, and Cobalt pipes represented' @{LSASSAccessed=$false;pipesCreated=0;technique='T1003.001'}
Add-EmotetRcloneTimeline 26.83 credential-access 'Invoke-Kerberoast represented' @{ticketsRequested=0;technique='T1558.003'}
Add-EmotetRcloneTimeline 29 lateral-movement '1.dll SMB transfer, PsExec service, pass-the-hash, Get-System, and workstation pivot represented' @{remoteHostsTouched=0;techniques=@('T1550.002','T1021.002','T1570')}
Add-EmotetRcloneTimeline 31 lateral-movement 'Domain-controller pivot, Get-System pipe, and LSASS dump represented' @{domainControllersTouched=0;credentialsCollected=0}
