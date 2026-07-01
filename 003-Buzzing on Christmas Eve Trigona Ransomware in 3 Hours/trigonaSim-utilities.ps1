# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - UTILITY FUNCTIONS
# ============================================================================
# This script contains utility functions for the Trigona ransomware simulation
# ============================================================================

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