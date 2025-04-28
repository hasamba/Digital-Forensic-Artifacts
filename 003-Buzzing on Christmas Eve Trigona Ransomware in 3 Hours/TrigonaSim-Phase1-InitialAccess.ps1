# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 1: INITIAL ACCESS
# ============================================================================
# This script simulates the initial access phase of the Trigona ransomware attack
# using IcedID infection and VNC connections.
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
    
    Write-Host "  [✓] Initial Access artifacts created" -ForegroundColor Yellow
    return $icedidPath
}