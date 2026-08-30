# ============================================================================
# BLURRING THE LINES SIM - PHASE 1: INITIAL ACCESS
# ============================================================================
# Simulates: the user downloads and runs EarthTime.exe, a trojanized copy of
# DeskSoft's EarthTime application (signed with a revoked cert from "Brave
# Pragmatic Network Technology Co., Ltd."). The process tree observed in the
# report is:
#     explorer.exe -> EarthTime.exe (Downloads) -> cmd.exe -> MSBuild.exe
# MSBuild.exe (CurrentDirectory = Downloads) retrieves its C2 configuration from
# Pastebin, then writes C:\Users\Public\Music\WakeWordEngine.dll (SectopRAT /
# ArechClient2) and executes it via rundll32.exe <dll>,Reset.
# MITRE: T1204.002 Malicious File, T1036.005 Masquerading, T1059.003 Cmd,
#        T1127.001 MSBuild, T1105 Ingress Tool Transfer, T1102 Web Service,
#        T1218.011 Rundll32
# ============================================================================

function Simulate-InitialAccess {
    param($SimPaths)

    Write-Host "[+] Phase 1: Initial Access - trojanized EarthTime.exe -> MSBuild -> SectopRAT ..." -ForegroundColor Green

    # --- Browser download history of the fake EarthTime installer -------------
    $historyLog = @"
[Simulated browser navigation / download history - BlurringLinesSim]
https://www.google.com/search?q=earthtime+desksoft+download
[malicious result / SEO poisoning ->] hxxps://earthtime-desksoft[.]com/download/EarthTime.exe
File download: EarthTime.exe  (Downloads folder)
Digital signature: "$($Global:BlurIOCs.RevokedSigner)"  [REVOKED / known-bad signer]
SHA256: $($Global:BlurIOCs.Hashes['EarthTime.exe'])
"@
    Set-Content -Path "$($SimPaths.Logs)\browser_history_sim.log" -Value $historyLog -Force

    # --- Land the (benign, runnable) fake EarthTime.exe in Downloads ----------
    $downloads = "$env:USERPROFILE\Downloads"
    if (-not (Test-Path $downloads)) { New-Item -Path $downloads -ItemType Directory -Force | Out-Null }
    $earthTime = Join-Path $downloads "EarthTime.exe"
    New-RunnablePayload -Path $earthTime -OverlayStrings @(
        "EarthTime DeskSoft (trojanized)",
        "Signer: $($Global:BlurIOCs.RevokedSigner)",
        "SHA256:$($Global:BlurIOCs.Hashes['EarthTime.exe'])",
        "SectopRAT loader"
    ) | Out-Null
    Set-ArtifactTimestamp -Path $earthTime -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 15
    Write-Host "    Dropped fake installer: $earthTime" -ForegroundColor DarkGray

    # --- Execute EarthTime.exe (authentic process-creation artifact) ----------
    Write-Host "    Executing EarthTime.exe (benign stand-in, real EID 1/4688) ..." -ForegroundColor DarkGray
    Invoke-RunPayload -Path $earthTime
    Write-SimEvent -EventId 1001 -Message "SIMULATION: user executed trojanized EarthTime.exe from Downloads (revoked signer '$($Global:BlurIOCs.RevokedSigner)')"

    # --- EarthTime.exe -> cmd.exe -> MSBuild.exe (real proxy-execution tree) ---
    # MSBuild retrieved its config from Pastebin. We resolve/connect to the real
    # pastebin.com host for DNS telemetry, then drop the "decoded" config locally.
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.PastebinHost -Port 443

    $pasteConfig = @"
[SectopRAT config - decoded from Pastebin paste, BlurringLinesSim]
c2      = $($Global:BlurIOCs.SectopRatC2)
ports   = $($Global:BlurIOCs.SectopRatPorts -join ', ')
install = C:\Users\Public\Music\WakeWordEngine.dll
export  = Reset
build   = ArechClient2
"@
    Set-Content -Path "$($SimPaths.Loot)\pastebin_c2_config.txt" -Value $pasteConfig -Force

    # Run a REAL MSBuild.exe on a benign inline-task project so the T1127.001
    # artifact (MSBuild.exe process creation with CurrentDirectory in Downloads)
    # is authentic. The inline task only prints - no payload is compiled/run.
    $msbuild = Get-MSBuildPath
    $proj = Join-Path $downloads "build.proj"
    $projXml = @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- SIMULATION ONLY: real SectopRAT campaigns abused an MSBuild inline C#
       task (Microsoft.Build.Framework.ITask) to load a .NET stager in-memory.
       This inline task is inert and only writes a benign message. -->
  <UsingTask TaskName="BlurSim" TaskFactory="CodeTaskFactory"
             AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Fragment" Language="cs">
        System.Console.WriteLine("BlurringLinesSim: MSBuild inline task (inert)");
      </Code>
    </Task>
  </UsingTask>
  <Target Name="Run"><BlurSim /></Target>
</Project>
'@
    Set-Content -Path $proj -Value $projXml -Force
    if ($msbuild) {
        Write-Host "    Executing MSBuild.exe on inline-task project (real T1127.001 tree) ..." -ForegroundColor DarkGray
        try {
            $mp = Start-Process -FilePath $msbuild -ArgumentList "`"$proj`" /t:Run /nologo" `
                -WorkingDirectory $downloads -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($mp) { if (-not $mp.WaitForExit(15000)) { Stop-Process -Id $mp.Id -Force -ErrorAction SilentlyContinue } }
        } catch {}
    } else {
        Write-Host "    MSBuild.exe not found - logging command-line artifact only." -ForegroundColor DarkGray
    }
    Write-SimEvent -EventId 1002 -Message "SIMULATION: EarthTime.exe -> cmd.exe -> MSBuild.exe; MSBuild pulled C2 config from Pastebin (T1127.001/T1102)"

    # --- MSBuild writes WakeWordEngine.dll (SectopRAT) into the staging folder --
    $wakeword = "$($SimPaths.PublicMusic)\WakeWordEngine.dll"
    New-DecoyBinary -Path $wakeword -SizeBytes 421888 | Out-Null
    Set-ArtifactTimestamp -Path $wakeword -Anchor $Global:BlurTimeline.Day1 -JitterMinutes 20
    Write-Host "    Dropped SectopRAT: $wakeword  (SHA256 $($Global:BlurIOCs.Hashes['WakeWordEngine.dll']))" -ForegroundColor DarkGray

    # --- Execute SectopRAT via rundll32 <dll>,Reset (authentic tree) ----------
    Write-Host "    Executing: rundll32 WakeWordEngine.dll,Reset ..." -ForegroundColor DarkGray
    Invoke-BenignRundll32 -DllPath $wakeword -ExportName "Reset"
    Invoke-SafeNetworkAttempt -Target $Global:BlurIOCs.SectopRatC2 -Port 15647
    Write-SimEvent -EventId 1003 -Message "SIMULATION: WakeWordEngine.dll (SectopRAT) written to C:\Users\Public\Music and run via 'rundll32 <dll>,Reset'; C2 $($Global:BlurIOCs.SectopRatC2):15647"

    Write-Host "  [OK] Initial Access artifacts created (EarthTime.exe, MSBuild tree, WakeWordEngine.dll)" -ForegroundColor Yellow
    return $wakeword
}
