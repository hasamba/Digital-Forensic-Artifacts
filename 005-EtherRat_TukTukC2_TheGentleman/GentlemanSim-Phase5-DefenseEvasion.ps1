# ============================================================================
# GENTLEMAN SIMULATION - PHASE 5: DEFENSE EVASION - TUKTUK DLL SIDELOADING
# ============================================================================
# Simulates: download of additional payloads from S3 buckets, then TukTuk
# malware variants disguised as Greenshot binaries and DLL-sideloaded via
# log4net.dll, plus the same sideloading technique applied to SyncTrayzor,
# DocFX, and Cake - all legitimate signed binaries abused as loaders.
# MITRE: T1574.002 DLL Side-Loading, T1036.005 Masquerading
#
# Report note: TukTuk can also use Arweave as a dead-drop resolver for a
# credential-pool config blob covering ClickHouse/Supabase/Slack/GitHub/
# Dropbox transports. The functionality is present in the code but the
# report could not confirm it was used in this intrusion - we still
# generate the DNS telemetry against the real Arweave gateways for
# detection-engineering completeness.
# ============================================================================

function Simulate-DefenseEvasion {
    param($SimPaths)

    Write-Host "[+] Phase 5: Defense Evasion - TukTuk DLL Sideloading ..." -ForegroundColor Green

    # --- Additional payloads pulled from S3 buckets (real AWS S3 endpoint,
    #     safe to resolve/attempt - object itself won't exist) ---
    Invoke-SafeNetworkAttempt -Target "s3.amazonaws.com" -Port 443
    Write-SimEvent -EventId 5101 -Message "SIMULATION: additional payloads staged for download from S3-hosted archive (matches reported TukTuk delivery mechanism)"

    # --- Sideload targets: legitimate binary name + directory, TukTuk-as-log4net.dll ---
    $sideloadTargets = @(
        @{ Binary = "Greenshot.exe";   Dir = "$($SimPaths.Payloads)\Greenshot" },
        @{ Binary = "SyncTrayzor.exe"; Dir = "$($SimPaths.Payloads)\SyncTrayzor" },
        @{ Binary = "docfx.exe";       Dir = "$($SimPaths.Payloads)\docfx" },
        @{ Binary = "Cake.exe";        Dir = "$($SimPaths.Payloads)\Cake" }
    )

    $tukTukDllPaths = @()
    foreach ($target in $sideloadTargets) {
        New-Item -Path $target.Dir -ItemType Directory -Force | Out-Null
        $decoyExe = New-DecoyBinary -Path "$($target.Dir)\$($target.Binary)" -SizeBytes 1500000
        # log4net.dll is the real reported sideloaded DLL name for the Greenshot
        # abuse chain; we reuse the same filename convention for each abused
        # host binary since that's the sideload search-order technique.
        $tukTukDll = New-DecoyBinary -Path "$($target.Dir)\log4net.dll" -SizeBytes 245760
        $tukTukDllPaths += $tukTukDll

        try {
            Start-Process -FilePath $decoyExe -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 300
            Get-Process | Where-Object { $_.Path -eq $decoyExe } | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}

        Write-SimEvent -EventId 5102 -Message "SIMULATION: TukTuk sideloaded via log4net.dll next to trojanized $($target.Binary) at $($target.Dir) (T1574.002 DLL Side-Loading)"
    }

    Set-Content -Path "$($SimPaths.Logs)\phase5_sideload_targets.log" -Value ($sideloadTargets | ForEach-Object { "$($_.Binary) -> $($_.Dir)\log4net.dll" }) -Force

    # --- TukTuk dead-drop resolver capability check via real Arweave gateways ---
    # Present/loaded in the code per the report; use during THIS intrusion was
    # not confirmed. We still generate the DNS/network telemetry pattern.
    foreach ($gateway in $Global:GentlemanIOCs.ArweaveGateways) {
        Invoke-SafeNetworkAttempt -Target $gateway -Port 443
    }
    Write-SimEvent -EventId 5103 -Message "SIMULATION: TukTuk Arweave dead-drop resolver capability exercised - queried $($Global:GentlemanIOCs.ArweaveGateways -join ', ') for Drive-Id $($Global:GentlemanIOCs.ArweaveDriveId) (present in code, use in this intrusion unconfirmed per report)"

    Write-Host "  [OK] Defense Evasion artifacts created - $($tukTukDllPaths.Count) sideloaded DLL(s)" -ForegroundColor Yellow

    return @{
        SideloadTargets = $sideloadTargets
        TukTukDllPaths  = $tukTukDllPaths
    }
}
