#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Year2021Sim-utilities.ps1"
Assert-Year2021SimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-Year2021SimEnvironment

$caseMatrix = for ($case = 1; $case -le 20; $case++) {
    $lane = Join-Path $paths.Cases ('case-{0:d2}' -f $case)
    New-Item -Path $lane -ItemType Directory -Force | Out-Null
    if ($case -le 16) {
        $family = @('TrickBot', 'Bazar', 'IcedID', 'Hancitor')[($case - 1) % 4]
        Write-Year2021SimFile (Join-Path $lane 'phishing-attachment.docm') "INERT MASS-PHISHING ATTACHMENT CANARY. Aggregate family: $family. No macro or payload." 'phishing canary'
        [ordered]@{ syntheticLane = $case; initialAccess = 'phishing'; initialMalwareFamily = $family; mappingIsObservedCaseCorrelation = $false }
    } elseif ($case -eq 17) {
        Write-Year2021SimFile (Join-Path $lane 'exchange-webshell.aspx') '<%-- INERT VULNERABLE-APPLICATION/RANSOMWARE CASE CANARY. --%>' 'web exploit canary'
        [ordered]@{ syntheticLane = $case; initialAccess = 'vulnerable Exchange application'; outcomeClass = 'domain-wide ransomware'; mappingIsObservedCaseCorrelation = $false }
    } elseif ($case -eq 18) {
        Write-Year2021SimFile (Join-Path $lane 'web-exploit-miner.request') 'INERT WEB-EXPLOIT/COINMINER CASE CANARY.' 'web exploit canary'
        [ordered]@{ syntheticLane = $case; initialAccess = 'vulnerable web application'; outcomeClass = 'cryptominer'; mappingIsObservedCaseCorrelation = $false }
    } elseif ($case -eq 19) {
        Write-Year2021SimFile (Join-Path $lane 'weblogic-rce-xmrig.request') 'INERT WEBLOGIC-RCE/XMRIG CASE CANARY.' 'web exploit canary'
        [ordered]@{ syntheticLane = $case; initialAccess = 'WebLogic RCE'; outcomeClass = 'XMRig cryptominer'; mappingIsObservedCaseCorrelation = $false }
    } else {
        Write-Year2021SimFile (Join-Path $lane 'other-nonphishing-vector.marker') 'The article states 16 of 20 phishing cases but does not identify the fourth non-phishing vector in text.' 'unspecified access marker'
        [ordered]@{ syntheticLane = $case; initialAccess = 'other non-phishing vector not identified in article text'; mappingIsObservedCaseCorrelation = $false }
    }
}
Write-Year2021SimFile (Join-Path $paths.Evidence 'synthetic-case-matrix.json') ($caseMatrix | ConvertTo-Json -Depth 6) '20-lane aggregate matrix'

$rundll32 = Join-Path $paths.Tooling 'rundll32.exe'
New-Year2021SimDecoy $rundll32 'Cobalt Strike spawn-as stand-in'
foreach ($command in @('rundll32.exe beacon.dll,Start', 'jquery-3.3.1.min.js malleable C2 profile', 'multiple Cobalt Strike beacon sessions across workstations and servers')) {
    Invoke-Year2021SimDecoy $rundll32 $command 'initial-access malware'
}
Invoke-Year2021SimLoopback 443 'aggregate Cobalt Strike endpoint' 'post-exploitation C2'
Write-Year2021SimFile (Join-Path $paths.Evidence 'access-c2-negative-record.json') (@{
    phishingMessagesSent = 0
    macrosExecuted = 0
    exploitsAttempted = 0
    malwareExecuted = $false
    beaconsDeployed = 0
    remoteConnections = 0
    bytesTransferred = 0
} | ConvertTo-Json) 'phase safety record'
Add-Year2021SimTimeline 0 'initial-access' 'Sixteen phishing lanes and four non-phishing lanes represented from the 20-case aggregate' @{ publicCases = 20; phishingCases = 16; exploitsAttempted = 0 }
Add-Year2021SimTimeline 2 'command-and-control' 'Initial-access brokers and multi-host Cobalt Strike beacon trend represented' @{ beaconsDeployed = 0; remoteConnections = 0 }
