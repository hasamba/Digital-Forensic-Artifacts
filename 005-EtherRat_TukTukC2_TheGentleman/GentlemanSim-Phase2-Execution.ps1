# ============================================================================
# GENTLEMAN SIMULATION - PHASE 2: EXECUTION - ETHERRAT / ETHERHIDING
# ============================================================================
# Simulates: download of a portable Node.js runtime, launch of an obfuscated
# JavaScript payload (EtherRAT) that queries the Ethereum blockchain (via
# 1rpc.io "EtherHiding") for its C2 configuration, then a config update that
# points it at a real TryCloudflare tunnel plus decoy domains.
# MITRE: T1105 Ingress Tool Transfer, T1071.001 Web Protocols,
#        T1568 Dynamic Resolution (blockchain/EtherHiding)
#
# Report artifacts reproduced:
#   curl -sLo "...\9gY0LJMyXW.zip" "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"
#   node.exe launched against A7Pnj975bl.cfg config, contacting 1rpc[.]io
# ============================================================================

function Simulate-Execution {
    param($SimPaths)

    Write-Host "[+] Phase 2: Execution - EtherRAT / EtherHiding C2 Bootstrap ..." -ForegroundColor Green

    # --- Download portable Node.js runtime via curl, exact reported command ---
    $nodeZipPath = "$($SimPaths.Payloads)\9gY0LJMyXW.zip"
    $realCurlCmd = "curl  -sLo `"$nodeZipPath`" `"$($Global:GentlemanIOCs.NodeJsDownload)`""
    Set-Content -Path "$($SimPaths.Logs)\phase2_nodejs_download.log" -Value $realCurlCmd -Force
    Write-Host "    Executing: $realCurlCmd" -ForegroundColor DarkGray

    try {
        # Real download from the legitimate official Node.js source - not attacker
        # infrastructure - so this is safe to actually fetch. Falls back to a
        # decoy zip if offline.
        Start-Process -FilePath "curl.exe" -ArgumentList "-sLo `"$nodeZipPath`" `"$($Global:GentlemanIOCs.NodeJsDownload)`"" -WindowStyle Hidden -Wait -ErrorAction Stop
        if (-not (Test-Path $nodeZipPath) -or (Get-Item $nodeZipPath).Length -lt 1000) {
            throw "curl did not produce a usable archive"
        }
        Write-SimEvent -EventId 2001 -Message "SIMULATION: real curl download of portable Node.js runtime from nodejs.org (matches reported command line)"
    } catch {
        Write-Warning "Node.js download failed/offline, falling back to decoy archive: $_"
        New-DecoyBinary -Path $nodeZipPath -SizeBytes 2097152 | Out-Null
    }

    # --- Extract to the reported install directory ---
    $installDir = "$($SimPaths.Payloads)\P2RsupmqXnmx\gksVMg"
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
    $nodeExePath = "$installDir\node.exe"
    try {
        Expand-Archive -Path $nodeZipPath -DestinationPath "$($SimPaths.Staging)\node_extract" -Force -ErrorAction Stop
        $realNode = Get-ChildItem -Path "$($SimPaths.Staging)\node_extract" -Filter "node.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($realNode) {
            Copy-Item -Path $realNode.FullName -Destination $nodeExePath -Force
        } else {
            New-DecoyBinary -Path $nodeExePath -SizeBytes 76185600 | Out-Null
        }
    } catch {
        New-DecoyBinary -Path $nodeExePath -SizeBytes 76185600 | Out-Null
    }

    # --- Drop the EtherRAT config + obfuscated JS payload (inert decoys) ---
    $cfgPath = "$installDir\A7Pnj975bl.cfg"
    $iniPath = "$installDir\v72HYLU3OpRBznc.ini"
    Set-Content -Path $cfgPath -Value "// SIMULATION: inert decoy stand-in for real EtherRAT JSON config blob" -Force
    New-DecoyBinary -Path $iniPath -SizeBytes 8192 | Out-Null

    $obfuscatedJs = @'
// SIMULATION: inert decoy stand-in for the real obfuscated EtherRAT
// JavaScript payload. No real C2/backdoor logic is implemented here.
(function(_0x1a2b){ console.log("simulated obfuscated payload placeholder"); })();
'@
    $jsPath = "$installDir\index.js"
    Set-Content -Path $jsPath -Value $obfuscatedJs -Force
    Write-SimEvent -EventId 2002 -Message "SIMULATION: obfuscated JavaScript payload (EtherRAT decoy) dropped at $jsPath alongside node.exe and A7Pnj975bl.cfg"

    # --- Launch node.exe against the config, mirroring the persistence Run-key command ---
    try {
        Start-Process -FilePath "conhost.exe" -ArgumentList "--headless `"$nodeExePath`" `"$cfgPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue | Out-Null
        Write-SimEvent -EventId 2003 -Message "SIMULATION: conhost --headless `"node.exe`" `"A7Pnj975bl.cfg`" executed (EtherRAT bootstrap)"
    } catch { Write-Warning "node.exe launch simulation failed: $_" }

    # --- EtherHiding: query 1rpc.io (real domain) to resolve C2 config from the
    #     Ethereum blockchain. No active C2 is expected to be reachable. ---
    Invoke-SafeNetworkAttempt -Target $Global:GentlemanIOCs.EtherHidingRPC -Port 443
    foreach ($contract in $Global:GentlemanIOCs.EthereumContracts) {
        Set-Content -Path "$($SimPaths.Logs)\etherhiding_contract_query.log" -Value "Queried Ethereum smart contract $contract via $($Global:GentlemanIOCs.EtherHidingRPC) for C2 URL" -Append -Force
    }
    Write-SimEvent -EventId 2004 -Message "SIMULATION: EtherRAT queried 1rpc.io to resolve C2 configuration from Ethereum smart contracts (EtherHiding, T1568)"

    # --- Simulated config update: threat actor rotates in a real TryCloudflare
    #     tunnel plus decoy domains alongside it, as described in the report ---
    $activeC2 = Get-Random -InputObject $Global:GentlemanIOCs.TryCloudflareDomains
    $decoys = $Global:GentlemanIOCs.TryCloudflareDomains | Where-Object { $_ -ne $activeC2 } | Get-Random -Count 3
    Invoke-SafeNetworkAttempt -Target $activeC2 -Port 443
    foreach ($d in $decoys) { Invoke-SafeNetworkAttempt -Target $d -Port 443 }
    Set-Content -Path "$($SimPaths.Logs)\etherhiding_c2_update.log" -Value "Active C2 (from updated Ethereum config): $activeC2`r`nDecoy domains pushed alongside: $($decoys -join ', ')" -Force
    Write-SimEvent -EventId 2005 -Message "SIMULATION: Ethereum-hosted config updated - active C2 rotated to $activeC2 (real TryCloudflare tunnel), decoy domains pushed alongside for analyst confusion"

    Write-Host "  [OK] Execution/EtherHiding artifacts created - $installDir" -ForegroundColor Yellow

    return @{
        InstallDir = $installDir
        NodeExe    = $nodeExePath
        ConfigFile = $cfgPath
        ActiveC2   = $activeC2
    }
}
