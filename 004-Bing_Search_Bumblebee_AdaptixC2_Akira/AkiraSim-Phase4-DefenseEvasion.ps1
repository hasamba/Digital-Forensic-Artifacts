# ============================================================================
# AKIRA SIMULATION - PHASE 4: DEFENSE EVASION
# ============================================================================
# Simulates: mixed-case command obfuscation, secure deletion of staged
# loaders (Sysmon EID 23), and a BYOVD ("AV-killer") driver service
# registration (Swisscom variant - decoy vulnerable drivers, non-functional).
# MITRE: T1027.010 Command Obfuscation, T1070.004 File Deletion,
#        T1068 Exploitation for Privilege Escalation (BYOVD context)
# ============================================================================

function Simulate-DefenseEvasion {
    param($SimPaths, $InstallFolder)

    Write-Host "[+] Phase 4: Defense Evasion ..." -ForegroundColor Green

    # --- Mixed-case command execution to evade case-sensitive detections ---
    # e.g. CmD.eXe / pOWerShELl.exE as observed in the report
    try {
        Start-Process -FilePath "CmD.eXe" -ArgumentList "/c echo AkiraSim mixed-case exec test" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Start-Process -FilePath "pOWerShELl.exE" -ArgumentList "-NoProfile -Command `"Write-Host 'AkiraSim mixed-case exec test'`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 4001 -Message "SIMULATION: Mixed-case command execution used to evade case-sensitive detection rules (CmD.eXe / pOWerShELl.exE)"
    } catch {}

    # --- Secure deletion of staged loaders/recon logs (Sysmon Event ID 23: FileDelete) ---
    if ($InstallFolder -and (Test-Path $InstallFolder)) {
        Get-ChildItem -Path $InstallFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
        }
        Write-SimEvent -EventId 4002 -Message "SIMULATION: Threat actor deleted staged loader artifacts from $InstallFolder to minimize local footprint (Sysmon EID 23)"
    }

    # --- BYOVD: decoy vulnerable-driver services (Swisscom variant) ---
    # NOTE: these are inert placeholder .sys files, NOT the real signed
    # vulnerable drivers (rwdrv.sys/hlpdrv.sys) - registering the genuine
    # drivers would actually grant kernel access and is intentionally NOT
    # reproduced here. This still generates the same service-creation/
    # DriverPath forensic artifacts (registry ImagePath, RecentApps GUI
    # execution history) that analysts would hunt for.
    $tempDriverDir = "$env:TEMP"
    $rwdrv = "$tempDriverDir\rwdrv.sys"
    $hlpdrv = "$tempDriverDir\hlpdrv.sys"
    New-DecoyBinary -Path $rwdrv -SizeBytes 65536 | Out-Null
    New-DecoyBinary -Path $hlpdrv -SizeBytes 65536 | Out-Null

    try {
        New-Service -Name "mgdsrv" -BinaryPathName $rwdrv -DisplayName "mgdsrv" -StartupType Manual -ErrorAction Stop | Out-Null
    } catch { Write-Warning "mgdsrv service registration failed (expected if driver is invalid/unsigned): $_" }
    try {
        New-Service -Name "KMHLPSVC" -BinaryPathName $hlpdrv -DisplayName "KMHLPSVC" -StartupType Manual -ErrorAction Stop | Out-Null
    } catch { Write-Warning "KMHLPSVC service registration failed (expected if driver is invalid/unsigned): $_" }

    # RecentApps-style "AV-killer" GUI execution history artifact
    $avKillDir1 = "C:\ProgramData\av_kill_new\icardagt"
    $avKillDir2 = "C:\ProgramData\av_kill_old\mfpmp"
    New-Item -Path $avKillDir1 -ItemType Directory -Force | Out-Null
    New-Item -Path $avKillDir2 -ItemType Directory -Force | Out-Null
    $avKill1 = New-DecoyBinary -Path "$avKillDir1\icardagt.exe" -SizeBytes 131072
    $avKill2 = New-DecoyBinary -Path "$avKillDir2\mfpmp.exe" -SizeBytes 131072
    try {
        Start-Process -FilePath $avKill1 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
    Start-Sleep -Milliseconds 500
    Remove-Item -Path $avKill1, $avKill2 -Force -ErrorAction SilentlyContinue

    Write-SimEvent -EventId 4003 -Message "SIMULATION: BYOVD driver services (mgdsrv/KMHLPSVC) registered and AV-killer utilities executed then deleted"

    Write-Host "  [OK] Defense Evasion artifacts created" -ForegroundColor Yellow
}
