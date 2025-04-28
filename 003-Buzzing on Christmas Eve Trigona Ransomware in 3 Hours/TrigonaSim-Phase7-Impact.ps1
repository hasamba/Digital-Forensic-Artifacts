# ============================================================================
# TRIGONA RANSOMWARE SIMULATION - PHASE 7: IMPACT
# ============================================================================
# This script simulates the final impact phase of the Trigona ransomware attack
# including process termination, file encryption, and ransom note creation.
# ============================================================================

function Simulate-TrigonaRansomware {
    param($SimPaths)
    
    Write-Host "[+] Simulating Trigona Ransomware Execution & Impact..." -ForegroundColor Green
    
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
    
    Write-Host "  [✓] Trigona Ransomware Impact artifacts created" -ForegroundColor Yellow
}