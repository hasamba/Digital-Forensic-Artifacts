#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SettraSim-utilities.ps1";Assert-SxSafety -LabConfirmed:$LabConfirmed;$p=Initialize-SxEnvironment
# Initial access: Huntress could not confirm the vector; public reporting (MoxFive) cites VPN compromise / stolen credentials. Represented as a marker only.
Invoke-SxLoopback 443 'VPN / valid-account initial access (reported by public sources; unconfirmed by Huntress)' 'initial access marker'
Write-SxJson (Join-Path $p.Evidence 'initial-access.json') ([ordered]@{huntressConfirmedVector=$false;publicReportedVectors=@('compromised VPN','previously-obtained valid credentials');reportedSource='MoxFive / SOCRadar public reporting';authenticationAttempts=0;credentialsUsed=0;externalConnections=0}) initial-access
# July incident: MeshAgent RMM renamed to mvtcs.exe, C2 45.13.122[.]7
$july=Join-Path $p.Hosts 'JULY-RETAIL-CONSUMER'
$julyMesh=Join-Path $july 'C$\ProgramData\mvtcs\mvtcs.exe'
New-SxDecoy $julyMesh 'MeshAgent RMM renamed to mvtcs.exe (July incident, first EDR detection)'
Invoke-SxDecoy $julyMesh 'mvtcs.exe (MeshAgent RMM) --installandrun ; C2 45.13.122[.]7' 'services.exe (RMM persistence)'
Invoke-SxLoopback 443 '45.13.122[.]7 MeshAgent C2 (July)' 'RMM C2 beacon marker'
Write-SxJson (Join-Path $july 'C$\ProgramData\mvtcs\meshagent.msh') ([ordered]@{reportedProduct='MeshAgent';reportedBinary='mvtcs.exe (renamed)';reportedC2='45.13.122[.]7';reportedRole='persistent remote access';agentInstalled=$false;c2Contacted=$false}) rmm-config
# September incident: MeshAgent NOT renamed, C2 193.5.65[.]114 (also in certificate info and active connections), workstation WIN-LIVFRVQFMKO
$sept=Join-Path $p.Hosts 'SEPT-MANUFACTURING'
$septMesh=Join-Path $sept 'C$\Program Files\Mesh Agent\MeshAgent.exe'
New-SxDecoy $septMesh 'MeshAgent RMM (September incident, not renamed)'
Invoke-SxDecoy $septMesh 'MeshAgent.exe (MeshAgent RMM) ; C2 193.5.65[.]114 present in certificate info and active network connections' 'services.exe (RMM persistence)'
Invoke-SxLoopback 443 '193.5.65[.]114 MeshAgent C2 (September)' 'RMM C2 beacon marker'
Write-SxJson (Join-Path $sept 'C$\Program Files\Mesh Agent\meshagent.msh') ([ordered]@{reportedProduct='MeshAgent';reportedBinary='MeshAgent.exe (not renamed)';reportedC2='193.5.65[.]114';reportedC2InCertificate=$true;reportedC2InActiveConnections=$true;reportedWorkstationName='WIN-LIVFRVQFMKO';agentInstalled=$false;c2Contacted=$false}) rmm-config
# Attribution artifact: workstation WIN-LIVFRVQFMKO tied to 193.5.65[.]114 across incidents since Dec 24 2024
Write-SxJson (Join-Path $p.Evidence 'attribution-workstation.json') ([ordered]@{reportedWorkstationName='WIN-LIVFRVQFMKO';reportedAssociatedIp='193.5.65[.]114';reportedFirstSeen='2024-12-24';reportedAlsoSeen=@('2025-11','2026-02');reportedContext='workstation name observed across multiple Huntress incidents';actualHostnameChanged=$false}) attribution
Add-SxTimeline 0 initial-access 'Reported (unconfirmed) VPN / valid-account access represented' @{authenticationAttempts=0}
Add-SxTimeline 5 persistence 'July: MeshAgent RMM (mvtcs.exe) installed, C2 45.13.122[.]7 represented' @{agentInstalled=0;c2Contacted=0}
Add-SxTimeline 10 persistence 'September: MeshAgent RMM installed, C2 193.5.65[.]114 represented' @{agentInstalled=0;c2Contacted=0}
