#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\IcedRevilSim-utilities.ps1"
Assert-IRSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-IREnvironment

$wuauclt = Join-Path $paths.Payloads 'wuauclt.exe'
$mstsc = Join-Path $paths.Payloads 'mstsc.exe'
$calc = Join-Path $paths.Payloads 'calc.exe'
New-IRDecoy $wuauclt 'cloudmetric Cobalt Beacon stand-in' '8d44894c09a2e30b40927f8951e01708d0a600813387c3c0872bcd6cb10a3e8c'
New-IRDecoy $mstsc 'smalleststores x86 Cobalt spawn-to stand-in' '4b25f708c506e0cc747344ee79ecda48d51f6c25c9cb45ceb420575458f56720'
New-IRDecoy $calc 'smalleststores x64 Cobalt spawn-to stand-in' 'e35c31ba3e10f59ae7ea9154e2c0f6f832fcff22b959f65b607d6ba0879ab641'
Invoke-IRDecoy $wuauclt 'Cobalt Beacon HTTP GET /jquery-3.2.2.min.js; POST /jquery-3.2.2.full.js; polling 48963ms; jitter 24' 'IcedID/rundll32.exe'
Invoke-IRDecoy $mstsc 'Cobalt Beacon HTTPS GET /owa/ and /OWA/; polling 59713ms; jitter 41' 'IcedID/rundll32.exe'
Invoke-IRDecoy $calc 'Cobalt Beacon x64 spawn-to calc.exe; process injection reported' 'Cobalt Beacon'
foreach ($target in @('45.86.163.78:80','45.86.163.78:443','195.189.99.74:443','cloudmetric.online:80','smalleststores.com:443')) {
    $port = if ($target -match ':80$') { 80 } else { 443 }
    Invoke-IRLoopback $port $target 'Cobalt Strike C2 marker'
}

foreach ($hostName in @('BEACHHEAD-01','EXCHANGE-CANARY-01','DC-CANARY-01','DC-CANARY-02','FILE-CANARY-01','APP-CANARY-01')) {
    $hostRoot = Join-Path $paths.Hosts $hostName
    New-Item -Path $hostRoot -ItemType Directory -Force | Out-Null
    Write-IRFile (Join-Path $hostRoot 'host-role.txt') "GENERATED HOST CANARY: $hostName. This directory is local and is not a remote system." generated-host
}

$ldapGroups = @('Terminal Server License Servers','RAS and IAS Servers','Account Operators','Server Operators','Hyper-V Administrators','Remote Management Users','Event Log Readers','Remote Desktop Users','Backup Operators','Print Operators','ExchangeLegacyInterop','Organization Management','DnsUpdateProxy','Protected Users','Domain Controllers','Domain Computers','Domain Users')
Write-IRFile (Join-Path $paths.Evidence 'bloodhound-ldap.json') (@{reportedSource='wuauclt.exe';scope='generated DomainName.local';groups=$ldapGroups;ldapQueriesSent=0;directoryRead=$false} | ConvertTo-Json -Depth 6) discovery
Write-IRFile (Join-Path $paths.Evidence 'bloodhound-results.deleted.json') (@{reportedBehavior='BloodHound results written and deleted seconds after LDAP query burst';syntheticResultName='20210321_BloodHound.zip';resultWasEverCreated=$false;deletionPerformed=$false;recordRetainedForInvestigation=$true} | ConvertTo-Json) discovery
Write-IRFile (Join-Path $paths.Hosts 'DC-CANARY-01\some.csv') "name,cn,OperatingSystem,dNSHostName`nFILE-CANARY-01,FILE-CANARY-01,Windows Server (generated),file-canary-01.DomainName.local`nAPP-CANARY-01,APP-CANARY-01,Windows Server (generated),app-canary-01.DomainName.local" discovery
Invoke-IRDecoy $wuauclt 'cmd.exe /C adfind.exe -f objectcategory=computer -csv name cn OperatingSystem dNSHostName > some.csv' 'Cobalt Beacon on DC-CANARY-01'

Write-IRFile (Join-Path $paths.Evidence 'exchange-pivot.json') (@{reportedRoute=@('BEACHHEAD-01','EXCHANGE-CANARY-01','DC-CANARY-01','other servers');exchangeApplicationAccessed=$false;dnsRequestsSent=0;pingsSent=0;remoteHostsTouched=0} | ConvertTo-Json -Depth 5) movement
Write-IRFile (Join-Path $paths.Evidence 'lateral-movement.json') (@{reportedMethods=@('SMB transfer of Beacon executable','remote service execution','PowerShell Beacon via remote service','RDP from domain controller','RDP from secondary server');smbTransfers=0;servicesCreated=0;PowerShellExecuted=$false;rdpSessions=0;remoteHostsTouched=0} | ConvertTo-Json -Depth 5) movement
foreach ($port in @(445,3389)) { Invoke-IRLoopback $port "generated host movement port $port" 'movement telemetry marker' }
Write-IRFile (Join-Path $paths.Evidence 'uac-injection-credentials-gpo.json') (@{
    reportedUacFunctions=@('UAC-TokenMagic','Invoke-SluiBypass')
    reportedInjection='Cobalt process injection across environment'
    reportedCredentialAccess='credential dump on server and domain controller'
    reportedGpo='GPO named new disables Defender across all systems/OUs'
    privilegeChanges=0
    processesInjected=0
    LSASSAccessed=$false
    credentialsAccessed=0
    gpoOrSysvolTouched=$false
    servicesOrSecurityControlsChanged=0
} | ConvertTo-Json -Depth 6) safety
Write-IRFile (Join-Path $paths.Evidence 'phase2-negative.json') (@{externalConnections=0;ldapQueries=0;directoryReads=0;realDomainControllersTouched=0;smbTransfers=0;servicesCreated=0;PowerShellExecutions=0;rdpSessions=0;privilegeChanges=0;processesInjected=0;LSASSAccessed=$false;credentialsAccessed=0;gpoChanges=0;securityControlsImpaired=$false} | ConvertTo-Json) safety
Add-IRTimeline 90 command-and-control 'IcedID retrieves two Cobalt Beacon profiles' @{reportRelativeTiming=$true;externalConnections=0}
Add-IRTimeline 95 privilege-escalation 'UAC bypass functions and process injection represented' @{privilegeChanges=0;processesInjected=0}
Add-IRTimeline 105 discovery 'wuauclt LDAP/BloodHound activity and result deletion represented' @{ldapQueries=0;filesDeleted=0}
Add-IRTimeline 120 lateral-movement 'Exchange pivot, SMB/remote-service Beacons, and alternate PowerShell movement represented' @{remoteHostsTouched=0}
Add-IRTimeline 165 discovery 'Domain-controller AdFind, DNS, and ping discovery represented using generated hosts' @{realDomainControllersTouched=0}
Add-IRTimeline 180 lateral-movement 'RDP from DC and secondary server represented for final deployment' @{rdpSessions=0}
