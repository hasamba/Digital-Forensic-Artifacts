# ============================================================================
# BLURRING THE LINES - PLAY / RANSOMHUB / DRAGONFORCE FULL INTRUSION SIM
# ============================================================================
# Source report: "Blurring the Lines: Intrusion Shows Connection with Three
# Major Ransomware Gangs" - The DFIR Report, 2025-09-08
#   https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-
#   connection-with-three-major-ransomware-gangs/
#
# Runs the full attack chain end-to-end on a single host:
#   1.  Initial Access       - trojanized EarthTime.exe -> cmd -> MSBuild ->
#                              Pastebin config -> WakeWordEngine.dll (SectopRAT)
#   2.  Execution/Injection  - SectopRAT into MSBuild, SystemBC (conhost.dll),
#                              stealer (Steam/Discord/Telegram/wallets)
#   3.  Persistence          - BITS -> QuickAgent2\ChromeAlt_dbg.exe, Startup
#                              .lnk, local admin 'Admon'
#   4.  Privilege Escalation - PsExec -s (PSEXESVC) -> SYSTEM SystemBC
#   5.  Defense Evasion      - Defender policy off, GT_NET/ccs masquerade,
#                              ExportData.db timestomp to 2037
#   6.  Credential Access    - Veeam DB creds, DCSync (4662), LSASS (0x1410)
#   7.  Discovery            - net/nltest, Grixba, NetScan, SharpHound, AdFind
#   8.  Lateral Movement     - RDP over SystemBC proxy, Impacket wmiexec
#   9.  Command and Control  - Betruger (Day 6) + SectopRAT/SystemBC/Betruger C2
#   10. Collection/Exfil     - WinRAR, FS64.exe, WinSCP clear-text FTP
#   11. Impact               - 3-gang attribution; NO ransomware by default
#                              (prevented in the real case). -DeployRansomware
#                              adds REAL sandbox-scoped encryption + note + VSS.
#
# REQUIREMENTS: Run as Administrator, on an isolated/disposable lab VM only.
# ============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$DumpRealLsass,        # See Phase 6 - leave OFF unless the VM is fully disposable
    [switch]$SkipDefenderDisable,  # Leave Microsoft Defender enabled (default: disable it at start)
    [switch]$DeployRansomware,     # Phase 11: also detonate REAL, sandbox-scoped encryption (real case: PREVENTED)
    [ValidateSet('RansomHub','Play','DragonForce')]
    [string]$RansomFamily = 'RansomHub'   # Which gang's extension + ransom note to emulate under -DeployRansomware
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$scriptDir\BlurringLinesSim-utilities.ps1"
. "$scriptDir\BlurringLinesSim-Phase1-InitialAccess.ps1"
. "$scriptDir\BlurringLinesSim-Phase2-Execution.ps1"
. "$scriptDir\BlurringLinesSim-Phase3-Persistence.ps1"
. "$scriptDir\BlurringLinesSim-Phase4-PrivilegeEscalation.ps1"
. "$scriptDir\BlurringLinesSim-Phase5-DefenseEvasion.ps1"
. "$scriptDir\BlurringLinesSim-Phase6-CredentialAccess.ps1"
. "$scriptDir\BlurringLinesSim-Phase7-Discovery.ps1"
. "$scriptDir\BlurringLinesSim-Phase8-LateralMovement.ps1"
. "$scriptDir\BlurringLinesSim-Phase9-CommandAndControl.ps1"
. "$scriptDir\BlurringLinesSim-Phase10-CollectionExfiltration.ps1"
. "$scriptDir\BlurringLinesSim-Phase11-Impact.ps1"

Confirm-Execution
$logPath = Start-SimulationLogging
$simPaths = Initialize-SimulationEnvironment

# Disable Microsoft Defender up front so the chain detonates deterministically
# (lab-only; T1562.001). Use -SkipDefenderDisable to leave Defender on.
if (-not $SkipDefenderDisable) {
    Disable-DefenderForSimulation -AddExclusions
}

Write-Host "`n=== BLURRING THE LINES INTRUSION SIMULATION ===" -ForegroundColor Cyan
Write-Host "Simulation root: $($simPaths.Root)" -ForegroundColor Cyan
Write-Host "Staging path:    $($simPaths.PublicMusic)`n" -ForegroundColor Cyan

if ($DeployRansomware) {
    Write-Host "[!!!] -DeployRansomware SET: Phase 11 will run REAL $RansomFamily AES-256 encryption," -ForegroundColor Red
    Write-Host "      delete Volume Shadow Copies and change the wallpaper. Encryption is hard-scoped" -ForegroundColor Red
    Write-Host "      to $($simPaths.VictimFiles) and $($simPaths.Staging) only. Snapshot the VM first.`n" -ForegroundColor Red
}

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

Invoke-Phase -Name "InitialAccess"          { Simulate-InitialAccess          -SimPaths $simPaths }
Invoke-Phase -Name "Execution"              { Simulate-Execution              -SimPaths $simPaths }
Invoke-Phase -Name "Persistence"            { Simulate-Persistence            -SimPaths $simPaths }
Invoke-Phase -Name "PrivilegeEscalation"    { Simulate-PrivilegeEscalation    -SimPaths $simPaths }
Invoke-Phase -Name "DefenseEvasion"         { Simulate-DefenseEvasion         -SimPaths $simPaths }
Invoke-Phase -Name "CredentialAccess"       { Simulate-CredentialAccess       -SimPaths $simPaths -DumpRealLsass:$DumpRealLsass }
Invoke-Phase -Name "Discovery"              { Simulate-Discovery              -SimPaths $simPaths }
Invoke-Phase -Name "LateralMovement"        { Simulate-LateralMovement        -SimPaths $simPaths }
Invoke-Phase -Name "CommandAndControl"      { Simulate-CommandAndControl      -SimPaths $simPaths }
Invoke-Phase -Name "CollectionExfiltration" { Simulate-CollectionExfiltration -SimPaths $simPaths }
Invoke-Phase -Name "Impact"                 { Simulate-Impact                 -SimPaths $simPaths -DeployRansomware:$DeployRansomware -RansomFamily $RansomFamily }

Write-Host "`n=== SIMULATION COMPLETE ===" -ForegroundColor Cyan
Write-Host "Artifacts root: $($simPaths.Root)" -ForegroundColor Cyan
Write-Host "Staging path:   $($simPaths.PublicMusic)" -ForegroundColor Cyan
Write-Host "Execution log:  $logPath" -ForegroundColor Cyan
Write-Host "Impact summary: $($simPaths.VictimFiles)\_INTRUSION_IMPACT_SUMMARY.txt" -ForegroundColor Cyan
Write-Host "Attribution:    $($simPaths.VictimFiles)\_THREE_GANG_ATTRIBUTION.txt" -ForegroundColor Cyan
Write-Host "`nSuggested next steps for the analyst:" -ForegroundColor Green
Write-Host " - Collect with KAPE (see 'kape command.bat' in the repo root)"
Write-Host " - Review Sysmon/Security event logs, Prefetch, Amcache, MFT, USN journal"
Write-Host " - Pull PCAP/Zeek if network capture was running during execution"
Write-Host " - Cross-reference IOCs against the source DFIR report's Indicators section"

Stop-Transcript | Out-Null
