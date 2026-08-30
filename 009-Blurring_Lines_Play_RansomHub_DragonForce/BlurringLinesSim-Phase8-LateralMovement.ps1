# ============================================================================
# BLURRING THE LINES SIM - PHASE 8: LATERAL MOVEMENT
# ============================================================================
# Simulates: (1) RDP enabled and tunneled through the SystemBC proxy
# (149.28.101.219:443) - logon sequence Type 3 (network) then Type 10 (remote
# interactive), with the operator's client hostnames (DESCTOP-QPITRY,
# DESKTOP-A1HRTMJ, DESKTOP-PGD76HT, WIN-FLGU1CC210K); (2) Impacket wmiexec on
# Day 6 from the domain controller - WmiPrvSE.exe -> cmd.exe with output
# redirected to an admin share.
# MITRE: T1021.001 RDP, T1047 WMI, T1090 Proxy, T1572 Protocol Tunneling,
#        T1570 Lateral Tool Transfer, T1078 Valid Accounts
# ============================================================================

function Simulate-LateralMovement {
    param($SimPaths)

    Write-Host "[+] Phase 8: Lateral Movement - RDP over SystemBC proxy + Impacket wmiexec ..." -ForegroundColor Green

    # --- Enable RDP (real registry + firewall change) -------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Write-Host "    RDP enabled (fDenyTSConnections=0, firewall group 'Remote Desktop')" -ForegroundColor DarkGray
    } catch { Write-Warning "RDP enable failed: $($_.Exception.Message)" }
    Write-SimEvent -EventId 8001 -Message "SIMULATION: RDP enabled and tunneled via SystemBC proxy $($Global:BlurIOCs.SystemBcC2):$($Global:BlurIOCs.SystemBcPort) (T1021.001/T1572)"

    # --- Record the operator RDP client hostnames + logon-type sequence -------
    $rdpLog = "$($SimPaths.Logs)\rdp_lateral.log"
    Set-Content -Path $rdpLog -Value @"
[RDP-over-SystemBC lateral movement - BlurringLinesSim]
Proxy tunnel   : $($Global:BlurIOCs.SystemBcC2):$($Global:BlurIOCs.SystemBcPort)  (SystemBC)
Logon sequence : Type 3 (network) -> Type 10 (RemoteInteractive)
Accounts used  : CORP\Administrator (via DCSync), local '$($Global:BlurIOCs.LocalAccountUser)', Veeam svc
Operator client hostnames observed (Security 4624/4778, RDP ClientName):
"@ -Force
    foreach ($h in $Global:BlurIOCs.ActorHostnames) { Add-Content -Path $rdpLog -Value "  - $h" }
    # Seed the Terminal Services client-hostname registry hint the analyst pulls
    try {
        $tsHint = "HKCU:\Software\Microsoft\Terminal Server Client\Servers\10.10.10.20"
        New-Item -Path $tsHint -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $tsHint -Name "UsernameHint" -Value "CORP\Administrator" -Force -ErrorAction SilentlyContinue
    } catch {}
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.SystemBcC2 -Port $Global:BlurIOCs.SystemBcPort
    Write-SimEvent -EventId 8002 -Message "SIMULATION: operator RDP client hostnames $($Global:BlurIOCs.ActorHostnames -join ', ') recorded (T1078)"

    # --- Impacket wmiexec: WmiPrvSE.exe -> cmd.exe (real WMI process spawn) ----
    # 'wmic process call create' spawns the target under WmiPrvSE.exe, producing the
    # exact parent->child artifact the report calls out, with output to an admin path.
    $wmiOut = "$($SimPaths.Logs)\wmiexec_output.txt"
    Write-Host "    Impacket wmiexec pattern: WmiPrvSE.exe -> cmd.exe -> whoami ..." -ForegroundColor DarkGray
    try {
        & cmd.exe /c "wmic /node:localhost process call create `"cmd.exe /c whoami > $wmiOut`"" 2>$null | Out-Null
    } catch {}
    # Impacket wmiexec's signature: redirect to \\<host>\ADMIN$\__<epoch> then read back
    $adminShareStyle = "\\127.0.0.1\ADMIN$\__$(Get-Random -Minimum 1000000000 -Maximum 1999999999)"
    Add-Content -Path $wmiOut -Value "`n[Impacket wmiexec] output staged to $adminShareStyle then retrieved (SMB)"
    Write-SimEvent -EventId 8003 -Message "SIMULATION: Impacket wmiexec (WmiPrvSE.exe -> cmd.exe) run from DC on Day 6 (T1047)"

    Write-Host "  [OK] Lateral Movement artifacts created (RDP-over-proxy, wmiexec)" -ForegroundColor Yellow
}
