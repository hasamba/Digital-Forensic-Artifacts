# ============================================================================
# GENTLEMAN SIMULATION - PHASE 8: LATERAL MOVEMENT
# ============================================================================
# Simulates: leveraging compromised service account credentials to deploy
# GoTo Resolve remote management tooling laterally across servers and
# domain controllers, then expanded access over RDP, SMB, WinRM, and
# NetExec (nxc), along with privileged account password resets.
# MITRE: T1021.001 RDP, T1021.002 SMB/Windows Admin Shares, T1021.006 WinRM,
#        T1078 Valid Accounts, T1098 Account Manipulation
#
# Report artifacts reproduced:
#   nxc smb REDACTED_IP -u REDACTED_USER -p REDACTED_PASSWORD --ntds
#   nxc smb REDACTED_IP -u 1.txt -p 2.txt --no-bruteforce --continue-on-success
#   nxc smb REDACTED_IP -u REDACTED_USER -p REDACTED_PASSWORD -M lsassy
# ============================================================================

function Simulate-LateralMovement {
    param($SimPaths, $ServiceExePath)

    Write-Host "[+] Phase 8: Lateral Movement - GoTo Resolve + RDP/SMB/WinRM/NetExec ..." -ForegroundColor Green

    $isDomainJoined = Test-DomainJoined
    $localIp = "127.0.0.1"

    # --- GoTo Resolve lateral deployment using compromised service account creds ---
    if (-not $ServiceExePath) { $ServiceExePath = "$($SimPaths.Tools)\GoTo Resolve Unattended\SIM\GoToResolveProcessChecker.exe" }
    $lateralTargets = @("SIM-SRV01", "SIM-DC01", "SIM-SRV02")
    foreach ($t in $lateralTargets) {
        Write-SimEvent -EventId 8001 -Message "SIMULATION: GoTo Resolve deployed laterally to $t using compromised service account credentials (T1078, T1219)"
    }
    Set-Content -Path "$($SimPaths.Logs)\phase8_lateral_targets.log" -Value ($lateralTargets -join "`r`n") -Force

    # --- NetExec (nxc) commands, exact reported command lines ---
    $nxcCommands = @(
        "nxc  smb $localIp -u REDACTED_USER -p REDACTED_PASSWORD --ntds",
        "nxc  smb $localIp -u 1.txt -p 2.txt --no-bruteforce --continue-on-success",
        "nxc  smb $localIp -u REDACTED_USER -p REDACTED_PASSWORD -M lsassy"
    )
    Set-Content -Path "$($SimPaths.Logs)\phase8_netexec_commands.log" -Value ($nxcCommands -join "`r`n") -Force
    Write-SimEvent -EventId 8002 -Message "SIMULATION: NetExec (nxc) used for lateral SMB authentication, NTDS dump, credential-list spraying, and lsassy module remote LSASS access"

    # --- RDP pivot artifact (mstsc process-creation pattern) ---
    try {
        Start-Process -FilePath "cmdkey.exe" -ArgumentList "/generic:TERMSRV/$localIp /user:SIM-DOMAIN\svc_backup /pass:SimulatedPassword123!" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 8003 -Message "SIMULATION: cached RDP credential added via cmdkey.exe for TERMSRV/$localIp (T1021.001 RDP pivot pattern)"
    } catch { Write-Warning "RDP pivot artifact simulation failed: $_" }

    # --- SMB admin-share access pattern ---
    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c net use \\$localIp\C$ /user:SIM-DOMAIN\svc_backup SimulatedPassword123!" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c net use \\$localIp\C$ /delete" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 8004 -Message "SIMULATION: SMB admin share access pattern executed against $localIp (T1021.002)"
    } catch { Write-Warning "SMB lateral movement simulation failed: $_" }

    # --- WinRM lateral pattern ---
    try {
        Test-WSMan -ComputerName $localIp -ErrorAction SilentlyContinue | Out-Null
        Write-SimEvent -EventId 8005 -Message "SIMULATION: WinRM connectivity check executed against $localIp (T1021.006)"
    } catch {}

    # --- Privileged account password resets ---
    if ($isDomainJoined) {
        Write-SimEvent -EventId 8006 -Message "SIMULATION: privileged domain account password reset attempted as part of broad AD reconnaissance and takeover (T1098 Account Manipulation)"
    } else {
        try {
            $simUser = "svc_gentleman_sim"
            $securePass = ConvertTo-SecureString "SimulatedP@ssw0rd!" -AsPlainText -Force
            if (-not (Get-LocalUser -Name $simUser -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $simUser -Password $securePass -Description "GentlemanSim decoy service account" -ErrorAction SilentlyContinue | Out-Null
            }
            Set-LocalUser -Name $simUser -Password $securePass -ErrorAction SilentlyContinue
            Write-SimEvent -EventId 8006 -Message "SIMULATION: local decoy privileged account '$simUser' password reset, standing in for reported domain account takeover pattern (T1098)"
        } catch { Write-Warning "Local account password reset simulation failed: $_" }
    }

    Write-Host "  [OK] Lateral Movement artifacts created across $($lateralTargets.Count) simulated targets" -ForegroundColor Yellow
}
