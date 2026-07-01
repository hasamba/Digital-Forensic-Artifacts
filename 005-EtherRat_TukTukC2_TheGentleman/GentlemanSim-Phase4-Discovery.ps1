# ============================================================================
# GENTLEMAN SIMULATION - PHASE 4: DISCOVERY
# ============================================================================
# Simulates: extensive host and domain reconnaissance triggered shortly after
# the EtherRAT C2 config update - system profiling, antivirus enumeration,
# domain checks, LDAP-based user activity discovery, plus manual
# whoami/net/nltest commands and SoftPerfect Network Scanner usage observed
# later in the intrusion.
# MITRE: T1082 System Information Discovery, T1518.001 Security Software
#        Discovery, T1069/T1087 Group/Account Discovery, T1018 Remote System
#        Discovery, T1046 Network Service Discovery
#
# Report artifacts reproduced verbatim as automated discovery one-liners and
# manual operator commands.
# ============================================================================

function Simulate-Discovery {
    param($SimPaths)

    Write-Host "[+] Phase 4: Discovery - Host and Domain Reconnaissance ..." -ForegroundColor Green

    $discoveryLog = "$($SimPaths.Logs)\phase4_discovery_commands.log"

    # --- Automated discovery pipeline, exact reported PowerShell one-liners
    #     spawned via cmd.exe /d /s /c ---
    $automatedCommands = @(
        '[System.Globalization.CultureInfo]::InstalledUICulture.Name',
        "(Get-WmiObject Win32_VideoController).Name -join ', '",
        "try { (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -EA Stop).displayName -join ', ' } catch { 'none' }",
        '(Get-WmiObject Win32_ComputerSystem).Domain',
        '(Get-WmiObject Win32_ComputerSystem).PartOfDomain'
    )

    foreach ($psCmd in $automatedCommands) {
        $fullCmd = "cmd.exe /d /s /c `"powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command `"$psCmd`"`""
        Add-Content -Path $discoveryLog -Value $fullCmd
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/d /s /c `"powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command `"$psCmd`"`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } catch {}
    }

    # Two reg query discovery commands from the automated pipeline
    $regQueries = @(
        'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName',
        'reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid'
    )
    foreach ($rq in $regQueries) {
        $fullCmd = "cmd.exe /d /s /c `"$rq`""
        Add-Content -Path $discoveryLog -Value $fullCmd
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/d /s /c `"$rq`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } catch {}
    }
    Write-SimEvent -EventId 4001 -Message "SIMULATION: automated discovery pipeline executed (locale, GPU, AV product, domain membership, ProductName, MachineGuid) via cmd.exe /d /s /c powershell one-liners"

    # --- Manual operator discovery commands, exact reported command lines ---
    Add-Content -Path $discoveryLog -Value '"cmd.exe" /c whoami /all'
    try { Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami /all" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue } catch {}

    $isDomainJoined = Test-DomainJoined
    if ($isDomainJoined) {
        Add-Content -Path $discoveryLog -Value '"cmd.exe" /c net group "Domain Admins" /domain'
        try { Start-Process -FilePath "cmd.exe" -ArgumentList '/c net group "Domain Admins" /domain' -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue } catch {}

        Add-Content -Path $discoveryLog -Value '"cmd.exe" /c nltest /domain_trusts /all_trusts'
        try { Start-Process -FilePath "cmd.exe" -ArgumentList "/c nltest /domain_trusts /all_trusts" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue } catch {}

        Add-Content -Path $discoveryLog -Value '"cmd.exe" /c nltest /dclist:REDACTED'
        try {
            $domainName = (Get-CimInstance Win32_ComputerSystem).Domain
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c nltest /dclist:$domainName" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } catch {}

        Add-Content -Path $discoveryLog -Value '"cmd.exe" /c net group "Enterprise Admins" /domain'
        try { Start-Process -FilePath "cmd.exe" -ArgumentList '/c net group "Enterprise Admins" /domain' -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue } catch {}
    } else {
        Write-Host "    [i] Host not domain-joined - falling back to local-only group discovery" -ForegroundColor DarkGray
        Add-Content -Path $discoveryLog -Value '"cmd.exe" /c net localgroup Administrators (local fallback - not domain joined)'
        try { Start-Process -FilePath "cmd.exe" -ArgumentList "/c net localgroup Administrators" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue } catch {}
    }
    Write-SimEvent -EventId 4002 -Message "SIMULATION: manual discovery commands executed (whoami /all, net group Domain/Enterprise Admins, nltest /domain_trusts, nltest /dclist) - domain-joined=$isDomainJoined"

    # --- SoftPerfect Network Scanner (netscan.exe) - real reported tool use ---
    $netscanPath = "$($SimPaths.Tools)\netscan.exe"
    New-DecoyBinary -Path $netscanPath -SizeBytes 4200000 | Out-Null
    try {
        Start-Process -FilePath $netscanPath -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Milliseconds 500
        Get-Process | Where-Object { $_.Path -eq $netscanPath } | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
    Write-SimEvent -EventId 4003 -Message "SIMULATION: SoftPerfect Network Scanner (netscan.exe) executed from $netscanPath for internal network discovery (T1046)"

    Write-Host "  [OK] Discovery artifacts created - see $discoveryLog" -ForegroundColor Yellow
}
