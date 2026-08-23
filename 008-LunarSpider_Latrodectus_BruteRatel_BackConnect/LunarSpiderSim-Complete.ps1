# ============================================================================
# LUNAR SPIDER / LATRODECTUS / BRUTE RATEL / BACKCONNECT FULL INTRUSION SIM
# ============================================================================
# Source report: "From a Single Click: How Lunar Spider Enabled a Near-Two-Month
# Intrusion" - https://thedfirreport.com/2025/09/29/
#   from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/
#
# Runs the full attack chain end-to-end on a single host:
#   1.  Initial Access       - malvertising -> obfuscated W-9 JS -> MSI.msi
#   2.  Execution/Injection  - Brute Ratel C4 -> Latrodectus (explorer) -> stealer
#   3.  Persistence          - HKCU Run 'Update', SchedulerLsass task (lsassa.exe)
#   4.  Privilege Escalation - runas (seclogon), UAC bypass (ms-settings)
#   5.  Defense Evasion      - injection into sacrificial procs, tool deletion
#   6.  Credential Access    - unattend.xml, LSASS dump, stealer, Veeam creds
#   7.  Discovery            - net/nltest/WMIC, AdFind, rustscan/nmap
#   8.  Lateral Movement     - WMIC, PsExec, Zerologon (zero.exe), RDP
#   9.  Command and Control  - Latrodectus/BRC4/BackConnect/CobaltStrike/.NET beacons
#   10. Collection/Exfil     - Rclone (sihosts.exe) -> FTP 45.135.232.3
#   11. Impact               - NO ransomware; dwell + exfiltration marker
#
# REQUIREMENTS: Run as Administrator, on an isolated/disposable lab VM only.
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$DumpRealLsass,        # See Phase 6 - leave OFF unless the VM is fully disposable
    [switch]$SkipDefenderDisable   # Leave Microsoft Defender enabled (default: disable it at start)
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptDir\LunarSpiderSim-utilities.ps1"
. "$scriptDir\LunarSpiderSim-Phase1-InitialAccess.ps1"
. "$scriptDir\LunarSpiderSim-Phase2-ExecutionInjection.ps1"
. "$scriptDir\LunarSpiderSim-Phase3-Persistence.ps1"
. "$scriptDir\LunarSpiderSim-Phase4-PrivilegeEscalation.ps1"
. "$scriptDir\LunarSpiderSim-Phase5-DefenseEvasion.ps1"
. "$scriptDir\LunarSpiderSim-Phase6-CredentialAccess.ps1"
. "$scriptDir\LunarSpiderSim-Phase7-Discovery.ps1"
. "$scriptDir\LunarSpiderSim-Phase8-LateralMovement.ps1"
. "$scriptDir\LunarSpiderSim-Phase9-CommandAndControl.ps1"
. "$scriptDir\LunarSpiderSim-Phase10-Exfiltration.ps1"
. "$scriptDir\LunarSpiderSim-Phase11-Impact.ps1"

Confirm-Execution
$logPath = Start-SimulationLogging
$simPaths = Initialize-SimulationEnvironment

# Disable Microsoft Defender up front so the chain detonates deterministically
# (lab-only; T1562.001). Use -SkipDefenderDisable to leave Defender on.
if (-not $SkipDefenderDisable) {
    Disable-DefenderForSimulation -AddExclusions
}

Write-Host "`n=== LUNAR SPIDER INTRUSION SIMULATION ===" -ForegroundColor Cyan
Write-Host "Simulation root: $($simPaths.Root)`n" -ForegroundColor Cyan

# Run each phase in isolation: a phase that throws (e.g. blocked by an EDR on a
# monitored host) is logged and the simulation continues with the next phase,
# instead of one failure aborting the whole chain / closing the console.
function Invoke-Phase {
    param([Parameter(Mandatory)][scriptblock]$Body, [string]$Name)
    try {
        & $Body
    } catch {
        Write-Host "  [!] Phase '$Name' error (continuing): $($_.Exception.Message)" -ForegroundColor Red
        try { Write-SimEvent -EventId 9999 -Message "SIMULATION: phase '$Name' failed: $($_.Exception.Message)" } catch {}
    }
    Start-Sleep -Seconds 2
}

Invoke-Phase -Name "InitialAccess"       { Simulate-InitialAccess         -SimPaths $simPaths }
Invoke-Phase -Name "ExecutionInjection"  { Simulate-ExecutionAndInjection -SimPaths $simPaths }
Invoke-Phase -Name "Persistence"         { Simulate-Persistence           -SimPaths $simPaths }
Invoke-Phase -Name "PrivilegeEscalation" { Simulate-PrivilegeEscalation   -SimPaths $simPaths }
Invoke-Phase -Name "DefenseEvasion"      { Simulate-DefenseEvasion        -SimPaths $simPaths }
Invoke-Phase -Name "CredentialAccess"    { Simulate-CredentialAccess      -SimPaths $simPaths -DumpRealLsass:$DumpRealLsass }
Invoke-Phase -Name "Discovery"           { Simulate-Discovery             -SimPaths $simPaths }
Invoke-Phase -Name "LateralMovement"     { Simulate-LateralMovement       -SimPaths $simPaths }
Invoke-Phase -Name "CommandAndControl"   { Simulate-CommandAndControl     -SimPaths $simPaths }
Invoke-Phase -Name "Exfiltration"        { Simulate-Exfiltration          -SimPaths $simPaths }
Invoke-Phase -Name "Impact"              { Simulate-Impact                -SimPaths $simPaths }

Write-Host "`n=== SIMULATION COMPLETE ===" -ForegroundColor Cyan
Write-Host "Artifacts root: $($simPaths.Root)" -ForegroundColor Cyan
Write-Host "Execution log:  $logPath" -ForegroundColor Cyan
Write-Host "Impact summary: $($simPaths.VictimFiles)\_INTRUSION_IMPACT_SUMMARY.txt" -ForegroundColor Cyan
Write-Host "`nSuggested next steps for the analyst:" -ForegroundColor Green
Write-Host " - Collect with KAPE (see 'kape command.bat' in the repo root)"
Write-Host " - Review Sysmon/Security event logs, Prefetch, Amcache, MFT, USN journal"
Write-Host " - Pull PCAP/Zeek if network capture was running during execution"
Write-Host " - Cross-reference IOCs against the source DFIR report's Indicators section"

Stop-Transcript | Out-Null
