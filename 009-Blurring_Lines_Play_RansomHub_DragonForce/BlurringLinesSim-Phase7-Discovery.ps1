# ============================================================================
# BLURRING THE LINES SIM - PHASE 7: DISCOVERY
# ============================================================================
# Simulates: native recon commands (ipconfig, nslookup, whoami, net user/group,
# nltest domain-trust + dclist, net group "Domain Admins"); Grixba network
# scanning (GT_NET.exe / GRB_NET.exe with -m:scan -i:f -d:list.txt producing
# data.zip / export.zip / ExportData.db); SoftPerfect NetScan (netscan.exe under
# C:\Users\Public\Music\123\123 with netscan.xml, delete.me write-test, and
# newuser.bat/openrdp.bat/start.bat remote scripts); SharpHound (C:\PerfLogs\
# sh.exe); ADFind (adfind.exe -subnets); and a PowerShell Get-ADComputer export
# to AllWindows.csv.
# MITRE: T1016, T1018, T1046, T1069.001/.002, T1087.001/.002, T1482, T1135, T1615
# ============================================================================

function Simulate-Discovery {
    param($SimPaths)

    Write-Host "[+] Phase 7: Discovery - native recon, Grixba, NetScan, SharpHound, ADFind ..." -ForegroundColor Green

    $discOut = "$($SimPaths.Logs)\discovery_output.txt"
    "=== BlurringLinesSim discovery ($(Get-Date)) ===" | Set-Content -Path $discOut -Force

    # --- Native discovery commands (real execution -> 4688/Sysmon1 + console) --
    $commands = @(
        "ipconfig /all",
        "whoami /all",
        "net user",
        "net localgroup",
        "net localgroup Administrators",
        "nltest /domain_trusts /all_trusts",
        "nltest /dclist:",
        "net group `"Domain Admins`" /domain",
        "nslookup -type=srv _ldap._tcp.dc._msdcs"
    )
    foreach ($c in $commands) {
        Add-Content -Path $discOut -Value "`n> $c"
        try {
            $out = & cmd.exe /c $c 2>&1
            Add-Content -Path $discOut -Value ($out | Out-String)
        } catch { Add-Content -Path $discOut -Value "  [command failed / not domain-joined]" }
    }
    Write-SimEvent -EventId 7001 -Message "SIMULATION: native discovery commands executed (net/nltest/whoami/ipconfig) (T1016/T1069/T1482)"

    # --- Grixba GT_NET.exe / GRB_NET.exe (Play recon) -------------------------
    foreach ($g in @("GT_NET.exe", "GRB_NET.exe")) {
        $gp = "$($SimPaths.PublicMusic)\$g"
        if (-not (Test-Path $gp)) {
            New-RunnablePayload -Path $gp -OverlayStrings @("Grixba scanner", "Play ransomware recon") | Out-Null
        }
        Set-ArtifactTimestamp -Path $gp -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 30
        Invoke-RunPayload -Path $gp -Arguments "-m:scan -i:f -d:list.txt"
    }
    # Grixba list + outputs
    Set-Content -Path "$($SimPaths.PublicMusic)\list.txt" -Value "DC01`nFILE01`nBACKUP01`nWEB01" -Force
    New-DecoyBinary -Path "$($SimPaths.PublicMusic)\data.zip" -SizeBytes 65536 | Out-Null
    New-DecoyBinary -Path "$($SimPaths.PublicMusic)\export.zip" -SizeBytes 73728 | Out-Null
    Write-SimEvent -EventId 7002 -Message "SIMULATION: Grixba GT_NET.exe/GRB_NET.exe executed (-m:scan -i:f -d:list.txt); data.zip/export.zip/ExportData.db written (T1046/T1018)"

    # --- SoftPerfect NetScan under C:\Users\Public\Music\123\123 --------------
    $nsDir = "$($SimPaths.PublicMusic)\123\123"
    New-Item -Path $nsDir -ItemType Directory -Force | Out-Null
    $netscan = "$nsDir\netscan.exe"
    New-RunnablePayload -Path $netscan -OverlayStrings @("SoftPerfect Network Scanner", "netscan") | Out-Null
    Set-ArtifactTimestamp -Path $netscan -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 30
    Invoke-RunPayload -Path $netscan -Arguments "/hide /auto:results.xml"
    # netscan.xml config with checkwrite + remote scripts
    Set-Content -Path "$nsDir\netscan.xml" -Value @"
<?xml version="1.0"?>
<Config><Ports>135,445,3389</Ports><CheckWrite>1</CheckWrite>
<Scripts><Script name="newuser.bat"/><Script name="openrdp.bat"/><Script name="start.bat"/></Scripts>
</Config>
"@ -Force
    Set-Content -Path "$nsDir\newuser.bat" -Value "net user $($Global:BlurIOCs.LocalAccountUser) $($Global:BlurIOCs.LocalAccountPass) /add & net localgroup Administrators $($Global:BlurIOCs.LocalAccountUser) /add" -Force
    Set-Content -Path "$nsDir\openrdp.bat" -Value "reg add `"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`" /v fDenyTSConnections /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group=`"remote desktop`" new enable=Yes" -Force
    Set-Content -Path "$nsDir\start.bat" -Value "psexec \\%1 -u CORP\Administrator -p %2 -s cmd /c rundll32 C:\Users\Public\Music\WakeWordEngine.dll,Reset" -Force
    Set-Content -Path "$nsDir\delete.me" -Value "netscan write-access test" -Force   # dropped on C$ during checkwrite
    Write-SimEvent -EventId 7003 -Message "SIMULATION: SoftPerfect NetScan run from C:\Users\Public\Music\123\123 (ports 135/445/3389, checkwrite, newuser/openrdp/start.bat) (T1046/T1135)"

    # --- SharpHound (C:\PerfLogs\sh.exe) --------------------------------------
    $perflogs = "$env:SystemDrive\PerfLogs"
    New-Item -Path $perflogs -ItemType Directory -Force | Out-Null
    $sharphound = "$perflogs\sh.exe"
    New-RunnablePayload -Path $sharphound -OverlayStrings @("SharpHound BloodHound collector") | Out-Null
    Set-ArtifactTimestamp -Path $sharphound -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 30
    Invoke-RunPayload -Path $sharphound -Arguments "-c All --outputdirectory C:\PerfLogs"
    New-DecoyBinary -Path "$perflogs\20240808_BloodHound.zip" -SizeBytes 49152 | Out-Null
    Write-SimEvent -EventId 7004 -Message "SIMULATION: SharpHound (C:\PerfLogs\sh.exe -c All) executed; BloodHound collection written (T1087.002/T1615)"

    # --- ADFind -subnets ------------------------------------------------------
    $adfind = "$($SimPaths.PublicMusic)\adfind.exe"
    New-RunnablePayload -Path $adfind -OverlayStrings @("AdFind joeware") | Out-Null
    Set-ArtifactTimestamp -Path $adfind -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 30
    Invoke-RunPayload -Path $adfind -Arguments "-subnets -f (objectCategory=subnet)"
    Write-SimEvent -EventId 7005 -Message "SIMULATION: Adfind.exe -subnets executed (CN=Subnets,CN=Sites,CN=Configuration) (T1016)"

    # --- PowerShell Get-ADComputer -> AllWindows.csv --------------------------
    $adCmd = 'Import-Module ActiveDirectory; Get-ADComputer -Filter {enabled -eq $true} -properties * | select comment, description, Name, DNSHostName, OperatingSystem, LastLogonDate, ipv4address | Export-CSV C:\Users\Public\Music\AllWindows.csv -NoTypeInformation -Encoding UTF8'
    Set-Content -Path "$($SimPaths.Logs)\get_adcomputer.log" -Value $adCmd -Force
    # Produce a representative CSV artifact (no live AD in lab)
    Set-Content -Path "$($SimPaths.PublicMusic)\AllWindows.csv" -Value @"
"comment","description","Name","DNSHostName","OperatingSystem","LastLogonDate","ipv4address"
"","Domain Controller","DC01","DC01.corp.local","Windows Server 2019","$(Get-Date)","10.10.10.10"
"","File Server","FILE01","FILE01.corp.local","Windows Server 2019","$(Get-Date)","10.10.10.20"
"","Backup (Veeam)","BACKUP01","BACKUP01.corp.local","Windows Server 2022","$(Get-Date)","10.10.10.30"
"@ -Force
    Write-SimEvent -EventId 7006 -Message "SIMULATION: Get-ADComputer exported to C:\Users\Public\Music\AllWindows.csv (T1087.002)"

    Write-Host "  [OK] Discovery artifacts created (native recon, Grixba, NetScan, SharpHound, ADFind, AllWindows.csv)" -ForegroundColor Yellow
}
