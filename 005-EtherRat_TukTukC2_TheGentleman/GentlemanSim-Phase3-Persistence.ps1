# ============================================================================
# GENTLEMAN SIMULATION - PHASE 3: PERSISTENCE
# ============================================================================
# Simulates: EtherRAT establishing persistence via an HKCU Run key that
# re-launches node.exe against its config on logon, plus (later in the
# intrusion) the GoTo Resolve RMM service installation used for lateral
# access.
# MITRE: T1547.001 Registry Run Keys / Startup Folder, T1219 Remote Access
#        Software (service persistence)
#
# Report artifact reproduced exactly:
#   reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver
#     /d "conhost --headless \"...\node.exe\" \"...\A7Pnj975bl.cfg\"" /f
# ============================================================================

function Simulate-Persistence {
    param($SimPaths, $NodeExe, $ConfigFile)

    Write-Host "[+] Phase 3: Persistence - Registry Run Key + RMM Service ..." -ForegroundColor Green

    if (-not $NodeExe)   { $NodeExe = "$($SimPaths.Payloads)\P2RsupmqXnmx\gksVMg\node.exe" }
    if (-not $ConfigFile) { $ConfigFile = "$($SimPaths.Payloads)\P2RsupmqXnmx\gksVMg\A7Pnj975bl.cfg" }

    # --- Real registry Run key, exact reported command line ---
    $runValue = "conhost --headless `"$NodeExe`" `"$ConfigFile`""
    $realRegCmd = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver /d `"$runValue`" /f"
    Set-Content -Path "$($SimPaths.Logs)\phase3_persistence_commands.log" -Value $realRegCmd -Force
    Write-Host "    Executing: $realRegCmd" -ForegroundColor DarkGray

    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver /d `"$runValue`" /f" -WindowStyle Hidden -Wait -ErrorAction Stop
        Write-SimEvent -EventId 3001 -Message "SIMULATION: HKCU Run key 'AppResolver' created for EtherRAT persistence (T1547.001): $runValue"
    } catch { Write-Warning "Registry Run key simulation failed: $_" }

    # --- Later-stage RMM service install: GoTo Resolve Unattended access ---
    # Reproduces the reported service name/path pattern using a decoy binary
    # standing in for the real GoTo Resolve process checker.
    $serviceName = "GoToResolve_SIM"
    $serviceDir = "$($SimPaths.Tools)\GoTo Resolve Unattended\SIM"
    New-Item -Path $serviceDir -ItemType Directory -Force | Out-Null
    $serviceExe = New-DecoyBinary -Path "$serviceDir\GoToResolveProcessChecker.exe" -SizeBytes 1048576

    $serviceBinPath = "`"$serviceExe`" -Service -WorkFolder `"$serviceDir`" -ApplicationType `"4`""
    try {
        sc.exe create $serviceName binPath= "$serviceBinPath" start= demand DisplayName= "GoTo Resolve Unattended Access" | Out-Null
        Write-SimEvent -EventId 3002 -Message "SIMULATION: RMM service '$serviceName' installed for GoTo Resolve unattended access (T1219). Service File Name: $serviceBinPath"
        Set-Content -Path "$($SimPaths.Logs)\phase3_gotoresolve_service.log" -Value "Service Name: $serviceName`r`nService File Name: $serviceBinPath`r`nService Type: user mode service" -Force
    } catch { Write-Warning "GoTo Resolve service simulation failed: $_" }

    # Also stage the reported MSI install artifact for GoTo Resolve deployment
    $gotoMsi = New-DecoyBinary -Path "$($SimPaths.Payloads)\smokymo.msi" -SizeBytes 15728640
    Write-SimEvent -EventId 3003 -Message "SIMULATION: GoTo Resolve installer 'smokymo.msi' staged at $gotoMsi for RMM-based lateral deployment"

    Write-Host "  [OK] Persistence artifacts created (Run key + service $serviceName)" -ForegroundColor Yellow

    return @{
        ServiceName    = $serviceName
        ServiceExePath = $serviceExe
        GotoMsiPath    = $gotoMsi
    }
}
