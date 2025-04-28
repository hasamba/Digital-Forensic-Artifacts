# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 4: CREDENTIAL ACCESS & DISCOVERY
# ============================================================================
# This script simulates credential theft and system discovery techniques used in
# the Trigona ransomware attack.
# ============================================================================

function Simulate-CredentialAccessAndDiscovery {
    param($SimPaths)
    
    Write-Host "[+] Simulating Credential Access & Discovery Techniques..." -ForegroundColor Green
    
    # Create a simulated SAM dump
    $samDumpContent = @"
mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

mimikatz(commandline) # lsadump::sam
Domain : DESKTOP-TRIGONA
SID    : S-1-5-21-1266370457-1204892538-707370924

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : f0d412bd764ffe81aad3b435b51404ee

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000003e8 (1000)
User : user1
LM   :
NTLM : 3ca78bd971286fa38369d8959bee4560
"@
    
    $samDumpPath = "$($SimPaths.Logs)\sam_dump.txt"
    Set-Content -Path $samDumpPath -Value $samDumpContent -Force
    
    # Create a simulated LSASS dump file (just random bytes)
    $lsassDumpBytes = New-Object byte[] 4096
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($lsassDumpBytes)
    [System.IO.File]::WriteAllBytes("$($SimPaths.Logs)\lsass.dmp", $lsassDumpBytes)
    
    # Create discovery command logs
    $discoveryCommands = @(
        "ipconfig /all",
        "netstat -ano",
        "net user",
        "net localgroup administrators",
        "net group 'Domain Admins' /domain",
        "net group 'Enterprise Admins' /domain",
        "net share",
        "systeminfo",
        "tasklist /v",
        "query user",
        "wmic qfe list",
        "wmic product get name",
        "nltest /domain_trusts",
        "nltest /dclist:",
        "net view /all /domain",
        "net view /all",
        "wmic computersystem get domain",
        "powershell -c 'Get-ADDomain'"
    )
    
    $discoveryLogPath = "$($SimPaths.Logs)\discovery_commands.log"
    Set-Content -Path $discoveryLogPath -Value $discoveryCommands -Force
    
    # Execute some discovery commands to generate real artifacts
    $ipConfigPath = "$($SimPaths.Logs)\ipconfig.txt"
    $netstatPath = "$($SimPaths.Logs)\netstat.txt"
    $systemInfoPath = "$($SimPaths.Logs)\systeminfo.txt"
    $netUserPath = "$($SimPaths.Logs)\netuser.txt"
    $netAdminsPath = "$($SimPaths.Logs)\netadmins.txt"
    
    try {
        ipconfig /all > $ipConfigPath
        netstat -ano > $netstatPath
        systeminfo > $systemInfoPath
        net user > $netUserPath
        net localgroup administrators > $netAdminsPath
    } catch {
        Write-Warning "Error running discovery commands: $_"
    }
    
    # Create registry access artifacts
    $regAccessContent = @"
Accessing: HKLM\SAM
Accessing: HKLM\SECURITY
Accessing: HKLM\SYSTEM\CurrentControlSet\Services\NTDS
Accessing: HKLM\SYSTEM\CurrentControlSet\Control\LSA
"@
    
    $regAccessPath = "$($SimPaths.Logs)\registry_access.log"
    Set-Content -Path $regAccessPath -Value $regAccessContent -Force
    
    # Log the access activities
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1343 -Message "SIMULATION: Credential dumping activity detected - possible Mimikatz usage" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1344 -Message "SIMULATION: Registry credential access detected - SAM hive access attempt" -EntryType Warning
    
    # Create a network scan simulation log
    $networkScanContent = @"
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.1.0/24
Host is up (0.0040s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
5986/tcp open  wsmans

Nmap done: 256 IP addresses (10 hosts up) scanned in 25.33 seconds
"@
    
    $networkScanPath = "$($SimPaths.Logs)\nmap_scan.txt"
    Set-Content -Path $networkScanPath -Value $networkScanContent -Force
    
    Write-Host "  [✓] Credential Access & Discovery artifacts created" -ForegroundColor Yellow
}