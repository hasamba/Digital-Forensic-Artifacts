# ============================================================================
# AKIRA / BUMBLEBEE / ADAPTIXC2 FULL INTRUSION SIMULATION
# ============================================================================
# Source report: "From Bing Search to Ransomware: Bumblebee and AdaptixC2
# Deliver Akira" - https://thedfirreport.com/2026/06/29/
#   from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
#
# Runs the full attack chain end-to-end on a single host:
#   1. Initial Access      - Bing SEO poisoning -> trojanized MSI -> BumbleBee
#   2. Execution/Injection - AdgNsy.exe (WAB.exe) via WMI + AdaptixC2 beacon
#   3. Persistence         - rogue accounts, RustDesk service, cloudflared
#   4. Defense Evasion     - mixed-case exec, file deletion, BYOVD services
#   5. Credential Access   - NTDS.dit, Veeam DPAPI dump, LSASS MiniDump
#   6. Discovery           - net/nltest/quser, SPN enum, ShareFinder, AD export
#   7. Lateral Movement    - reverse SSH tunnel, RDP pivot artifacts
#   8. Collection          - credential/config/dev directory sweep
#   9. Exfiltration        - FileZilla + SFTP to reported exfil server
#  10. Impact              - Akira ransomware, VSS deletion, ransom note
#
# REQUIREMENTS: Run as Administrator, on an isolated/disposable lab VM only.
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$DumpRealLsass  # See AkiraSim-Phase5-CredentialAccess.ps1 - leave OFF unless fully disposable lab
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptDir\AkiraSim-utilities.ps1"
. "$scriptDir\AkiraSim-Phase1-InitialAccess.ps1"
. "$scriptDir\AkiraSim-Phase2-ExecutionInjection.ps1"
. "$scriptDir\AkiraSim-Phase3-Persistence.ps1"
. "$scriptDir\AkiraSim-Phase4-DefenseEvasion.ps1"
. "$scriptDir\AkiraSim-Phase5-CredentialAccess.ps1"
. "$scriptDir\AkiraSim-Phase6-Discovery.ps1"
. "$scriptDir\AkiraSim-Phase7-LateralMovement.ps1"
. "$scriptDir\AkiraSim-Phase8-Collection.ps1"
. "$scriptDir\AkiraSim-Phase9-Exfiltration.ps1"
. "$scriptDir\AkiraSim-Phase10-Impact.ps1"

Confirm-Execution
$logPath = Start-SimulationLogging
$simPaths = Initialize-SimulationEnvironment

Write-Host "`n=== AKIRA / BUMBLEBEE / ADAPTIXC2 INTRUSION SIMULATION ===" -ForegroundColor Cyan
Write-Host "Simulation root: $($simPaths.Root)`n" -ForegroundColor Cyan

$installFolder = Simulate-InitialAccess -SimPaths $simPaths
Start-Sleep -Seconds 2

$adgNsyPid = Simulate-ExecutionAndInjection -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-Persistence -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-DefenseEvasion -SimPaths $simPaths -InstallFolder $installFolder
Start-Sleep -Seconds 2

Simulate-CredentialAccess -SimPaths $simPaths -DumpRealLsass:$DumpRealLsass
Start-Sleep -Seconds 2

Simulate-Discovery -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-LateralMovement -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-Collection -SimPaths $simPaths
Start-Sleep -Seconds 2

Simulate-Exfiltration -SimPaths $simPaths
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
