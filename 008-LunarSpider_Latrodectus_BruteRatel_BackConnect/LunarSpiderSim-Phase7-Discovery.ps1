# ============================================================================
# LUNAR SPIDER SIMULATION - PHASE 7: DISCOVERY
# ============================================================================
# Simulates: Day 1 host/domain recon (ipconfig, systeminfo, nltest, net view,
# whoami /groups, AV enumeration via WMIC), AdFind AD reconnaissance to
# ad_*.txt/.csv, DNS zone enumeration, and Day 28 rustscan/nmap SMB sweeps.
# MITRE: T1016, T1082, T1482, T1087, T1018, T1069, T1046, T1518.001
# ============================================================================

function Simulate-Discovery {
    param($SimPaths)

    Write-Host "[+] Phase 7: Discovery - host/domain recon, AdFind, rustscan ..." -ForegroundColor Green

    # --- Day 1 discovery commands (run for real; harmless, authentic artifacts) ---
    $discoveryLog = "$($SimPaths.Logs)\discovery_day1.log"
    "=== LunarSpiderSim Day-1 discovery ===" | Out-File $discoveryLog -Encoding utf8

    $cmds = @(
        'ipconfig /all',
        'systeminfo',
        'nltest /domain_trusts',
        'nltest /domain_trusts /all_trusts',
        'net view /all /domain',
        'net view /all',
        'net group "Domain Admins" /domain',
        'net config workstation',
        'whoami /groups'
    )
    foreach ($c in $cmds) {
        "`r`n>>> $c" | Out-File $discoveryLog -Append -Encoding utf8
        try { cmd.exe /c $c 2>&1 | Out-File $discoveryLog -Append -Encoding utf8 } catch {}
    }
    # AV enumeration one-liner from the report
    $avCmd = 'wmic.exe /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed'
    "`r`n>>> $avCmd" | Out-File $discoveryLog -Append -Encoding utf8
    try { cmd.exe /c $avCmd 2>&1 | Out-File $discoveryLog -Append -Encoding utf8 } catch {}
    Write-SimEvent -EventId 7001 -Message "SIMULATION: Day-1 host/domain discovery commands executed (ipconfig/systeminfo/nltest/net/whoami/WMIC AV)"

    # --- AdFind reconnaissance (stand-in binary + exact command lines) --------
    $adfind = "$($SimPaths.Tools)\adfind.exe"
    New-DecoyBinary -Path $adfind -SizeBytes 512000 | Out-Null
    $adfindCmds = @(
        'adfind.exe -f "(objectcategory=person)" >> ad_users.txt',
        'adfind.exe -f "objectcategory=computer" >> ad_computers.txt',
        'adfind.exe -f "(objectcategory=organizationalUnit)" > ad_ous.txt',
        'adfind.exe -subnets -f (objectCategory=subnet) > ad_subnets.txt',
        'adfind.exe -gcb -sc trustdmp > ad_trustdmp.txt',
        'adfind.exe -f "&(objectCategory=computer)(operatingSystem=*server*)" -csv > ad_servers.csv'
    )
    Set-Content -Path "$($SimPaths.Logs)\adfind_commands.log" -Value ($adfindCmds -join "`r`n") -Force
    # Produce the output files the actor's commands would create (lab-populated)
    Set-Content -Path "$($SimPaths.Loot)\ad_users.txt"    -Value "CN=Administrator`r`nCN=jsmith`r`nCN=svc_backup" -Force
    Set-Content -Path "$($SimPaths.Loot)\ad_computers.txt" -Value "CN=DC01`r`nCN=FS01`r`nCN=BACKUP01" -Force
    Set-Content -Path "$($SimPaths.Loot)\ad_servers.csv"  -Value "name,os`r`nDC01,Windows Server 2019`r`nFS01,Windows Server 2019" -Force
    Set-Content -Path "$($SimPaths.Loot)\ad_trustdmp.txt" -Value "CORP.LOCAL trust dump (lab)" -Force
    Write-SimEvent -EventId 7002 -Message "SIMULATION: AdFind AD reconnaissance executed (ad_users/computers/ous/subnets/trustdmp/servers)"

    # --- DNS zone / domain enumeration ----------------------------------------
    $dnsCmds = @(
        'dnscmd /zoneprint corp.local',
        'netdom query DC01 >> serv.log',
        'dsquery subnet'
    )
    Set-Content -Path "$($SimPaths.Logs)\dns_enum.log" -Value ($dnsCmds -join "`r`n") -Force

    # --- Day 28: rustscan + nmap SMB sweeps -----------------------------------
    $rustscan = "$($SimPaths.Tools)\rustscan.exe"
    New-DecoyBinary -Path $rustscan -SizeBytes 4194304 | Out-Null   # rustscan (MD5 9eaa8464... ref)
    $scanCmds = @(
        'rustscan.exe -a 10.10.0.0/16 -p 445 --no-nmap',
        'rustscan.exe -a 10.10.0.0/16 -p 445',
        'rustscan.exe -a 10.0.0.0/8 -p 445',
        'nmap -vvv -p 445 10.10.0.0/24'
    )
    Set-Content -Path "$($SimPaths.Logs)\network_scan_day28.log" -Value ($scanCmds -join "`r`n") -Force
    Write-SimEvent -EventId 7003 -Message "SIMULATION: rustscan/nmap SMB (445) network sweeps executed (Day 28)"

    Write-Host "  [OK] Discovery artifacts created" -ForegroundColor Yellow
}
