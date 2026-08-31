#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ZeroQbotSim-utilities.ps1"
Assert-ZeroQbotSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-ZeroQbotSimEnvironment

$cool = Join-Path $paths.Payloads 'cool.exe'
$find = Join-Path $paths.Payloads 'find.exe'
New-ZeroQbotSimDecoy $cool 'Zerologon PoC stand-in' 'f63e17ff2d3cfe75cf3bb9cf644a2a00e50aaffe45c1adf2de02d5bd0ae35b0'
New-ZeroQbotSimDecoy $find 'renamed AdFind stand-in'
Invoke-ZeroQbotSimDecoy $cool 'cool.exe [DC IP ADDRESS] [DOMAIN NAME] Administrator -c "taskkill /f /im explorer.exe"' 'cmd.exe'
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'zerologon-negative-record.json') (@{
    cve = 'CVE-2020-1472'
    reportedEvent = 4742
    timingAfterInitialAccessMinutes = 30
    exploitPacketsSent = 0
    domainControllersContacted = 0
    computerAccountPasswordsChanged = 0
    domainAdminHashesRetrieved = 0
    repairServicesInstalled = 0
    overPassTheHashPerformed = $false
    kerberosTicketsRequested = 0
} | ConvertTo-Json) 'Zerologon safety record'
foreach ($command in @(
    'find.exe -f objectcategory=computer -csv name cn OperatingSystem dNSHostName',
    'wmic /namespace:\\root\SecurityCenter2 PATH AntiSpywareProduct GET /value',
    'wmic /namespace:\\root\SecurityCenter2 PATH AntiVirusProduct GET /value',
    'wmic /namespace:\\root\SecurityCenter2 PATH FirewallProduct GET /value',
    'ping -n 1 [REDACTED]',
    'nltest, net, local groups, shares, privileges, and Active Directory mapping'
)) { Invoke-ZeroQbotSimDecoy $find $command 'Cobalt Strike beacon' }
Write-ZeroQbotSimFile (Join-Path $paths.Evidence 'discovery-negative-record.json') (@{ directoryQueries = 0; WmiQueries = 0; pingsSent = 0; networkSharesAccessed = 0; remoteHostsTouched = 0 } | ConvertTo-Json) 'discovery safety record'
Add-ZeroQbotSimTimeline 0.5 'privilege-escalation' 'cool.exe Zerologon sequence, DC password reset/repair, DA hash retrieval, and Event 4742 represented at minute 30' @{ exploitAttempts = 0; accountChanges = 0; hashesRetrieved = 0 }
Add-ZeroQbotSimTimeline 0.55 'defense-evasion' 'Administrator over-pass-the-hash and TGT request represented' @{ credentialUse = $false; ticketsRequested = 0 }
Add-ZeroQbotSimTimeline 1 'discovery' 'Qbot plus Cobalt discovery, renamed AdFind, WMI security-product queries, and ping represented' @{ realQueries = 0; remoteHostsTouched = 0 }
