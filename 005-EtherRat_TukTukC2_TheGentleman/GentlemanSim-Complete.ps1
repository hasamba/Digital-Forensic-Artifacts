# ============================================================================
# ETHERRAT / TUKTUK / THE GENTLEMEN FULL INTRUSION SIMULATION
# ============================================================================
# Source report: "Flash Alert: EtherRat and TukTuk C2 End in The Gentleman
# Ransomware" - https://thedfirreport.com/2026/05/11/
#   flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
#
# Runs the full attack chain end-to-end on a single host:
#   1. Initial Access        - trojanized RAMMap.msi -> msiexec -> cmd child
#   2. Execution              - Node.js runtime + EtherRAT / EtherHiding C2
#   3. Persistence            - HKCU Run key + GoTo Resolve RMM service
#   4. Discovery               - system/domain profiling, AV enum, netscan
#   5. Defense Evasion         - TukTuk DLL sideloading (Greenshot/SyncTrayzor/
#                                docfx/Cake + log4net.dll), Arweave dead-drop
#   6. Command and Control     - TukTuk SaaS channels (ClickHouse/Supabase/
#                                Ably/Dropbox/GitHub) + GoTo Resolve
#   7. Credential Access       - Kerberoasting, comsvcs.dll LSASS dump, NTDS
#   8. Lateral Movement        - GoTo Resolve, RDP/SMB/WinRM, NetExec, resets
#   9. Collection/Exfiltration - Rclone to Wasabi cloud storage
#  10. Impact                  - The Gentlemen ransomware, VSS deletion, GPO
#
# REQUIREMENTS: Run as Administrator, on an isolated/disposable lab VM only.
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$DumpRealLsass  # See GentlemanSim-Phase7-CredentialAccess.ps1 - leave OFF unless fully disposable lab
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptDir\GentlemanSim-utilities.ps1"
. "$scriptDir\GentlemanSim-Phase1-InitialAccess.ps1"
. "$scriptDir\GentlemanSim-Phase2-Execution.ps1"
. "$scriptDir\GentlemanSim-Phase3-Persistence.ps1"
. "$scriptDir\GentlemanSim-Phase4-Discovery.ps1"
. "$scriptDir\GentlemanSim-Phase5-DefenseEvasion.ps1"
. "$scriptDir\GentlemanSim-Phase6-CommandAndControl.ps1"
. "$scriptDir\GentlemanSim-Phase7-CredentialAccess.ps1"
. "$scriptDir\GentlemanSim-Phase8-LateralMovement.ps1"
. "$scriptDir\GentlemanSim-Phase9-Exfiltration.ps1"
. "$scriptDir\GentlemanSim-Phase10-Impact.ps1"

Confirm-Execution
$logPath = Start-SimulationLogging
$simPaths = Initialize-SimulationEnvironment

Write-Host "`n=== ETHERRAT / TUKTUK / THE GENTLEMEN INTRUSION SIMULATION ===" -ForegroundColor Cyan
Write-Host "Simulation root: $($simPaths.Root)`n" -ForegroundColor Cyan

$initialAccess = Simulate-InitialAccess -SimPaths $simPaths
Start-Sleep -Seconds 2

$execution = Simulate-Execution -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-Persistence -SimPaths $simPaths -NodeExe $execution.NodeExe -ConfigFile $execution.ConfigFile
Start-Sleep -Seconds 2

Simulate-Discovery -SimPaths $simPaths
Start-Sleep -Seconds 2

$defenseEvasion = Simulate-DefenseEvasion -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-CommandAndControl -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-CredentialAccess -SimPaths $simPaths -DumpRealLsass:$DumpRealLsass
Start-Sleep -Seconds 2

Simulate-LateralMovement -SimPaths $simPaths
Start-Sleep -Seconds 2

$exfil = Simulate-Exfiltration -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-Impact -SimPaths $simPaths

Write-Host "`n=== SIMULATION COMPLETE ===" -ForegroundColor Cyan
Write-Host "Artifacts root: $($simPaths.Root)" -ForegroundColor Cyan
Write-Host "Execution log: $logPath" -ForegroundColor Cyan
Write-Host "Ransom note / encrypted files: $($simPaths.VictimFiles)" -ForegroundColor Cyan
Write-Host "`nSuggested next steps for the analyst:" -ForegroundColor Green
Write-Host " - Collect with KAPE (see 'kape command.bat' in the repo root)"
Write-Host " - Review Sysmon/Security event logs, Prefetch, Amcache, MFT"
Write-Host " - Pull PCAP/Zeek if network capture was running during execution"
Write-Host " - Cross-reference IOCs against the source DFIR report's Indicators section"

Stop-Transcript | Out-Null
