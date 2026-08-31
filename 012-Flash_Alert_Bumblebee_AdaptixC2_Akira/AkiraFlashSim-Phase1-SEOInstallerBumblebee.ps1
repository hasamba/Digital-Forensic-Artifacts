function Invoke-AkiraFlashSEOInstallerBumblebee {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-AkiraFlashTimeline

    $lure = @'
<!doctype html><html><head><meta charset="utf-8"><title>ManageEngine OpManager Download</title></head>
<body><h1>ManageEngine OpManager</h1>
<p>Local SEO-poisoning forensic canary. No remote resources are loaded.</p>
<button data-download-ioc="https://opmanager.pro/ManageEngine-OpManager.msi">Download</button>
</body></html>
'@
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Evidence 'opmanager-search-lure.html') -Content $lure -Purpose 'local Bing/OpManager SEO lure with IOC as inert data attribute' -Timestamp $time.InitialAccess

    $msiMetadata = @"
AKIRA-FLASH-MSI-CANARY
ReportedName=ManageEngine-OpManager.msi
ReportedSHA256=186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da
SourceIOC=opmanager.pro
Behavior=legitimate OpManager plus consent.exe/msimg32.dll Bumblebee sideload
This file is deliberately not a valid Windows Installer package and contains no executable code.
"@
    Write-AkiraFlashEvidenceFile -Path $Paths.Installer -Content $msiMetadata -Purpose 'inert trojanized MSI-shaped artifact; hash is metadata only' -Timestamp $time.InitialAccess.AddMinutes(4)
    Set-Content -LiteralPath $Paths.InstallerOwner -Value $script:AkiraScenarioId -Encoding ASCII
    Add-AkiraFlashManifestEntry -Type 'file' -Path $Paths.InstallerOwner -Action 'created' -Details @{ purpose = 'cleanup ownership marker' }

    $msiLog = Join-Path $Paths.Evidence 'ManageEngine-OpManager-msiexec.log'
    if (Get-Command msiexec.exe -ErrorAction SilentlyContinue) {
        try {
            $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', "`"$($Paths.Installer)`"", '/qn', '/L*v', "`"$msiLog`"") -PassThru -Wait
            Add-AkiraFlashManifestEntry -Type 'process' -Path 'msiexec.exe' -Action 'attempted-invalid-canary-msi' -Details @{ installer = $Paths.Installer; exitCode = $process.ExitCode; codeExecution = $false }
        } catch {}
    }

    $consent = Join-Path $Paths.Payloads 'ManageEngine\consent.exe'
    $msimg = Join-Path $Paths.Payloads 'ManageEngine\msimg32.dll'
    New-AkiraFlashBinaryDecoy -Path $consent -Role 'consent.exe sideload process-name canary'
    Write-AkiraFlashEvidenceFile -Path $msimg -Content "MZ-AKIRA-FLASH-CANARY`nReportedSHA256=a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331`nFamily=Bumblebee" -Purpose 'inert Bumblebee DLL-shaped artifact' -Timestamp $time.InitialAccess.AddMinutes(6)
    Invoke-AkiraFlashDecoyProcess -FilePath $consent -ReportedCommandLine "consent.exe loading $msimg (Bumblebee sideload canary)"

    foreach ($endpoint in @(
        @{ Host = '109.205.195.211'; Path = '/gate' },
        @{ Host = '188.40.187.145'; Path = '/gate' },
        @{ Host = 'ev2sirbd269o5j.org'; Path = '/' },
        @{ Host = '2rxyt9urhq0bgj.org'; Path = '/' }
    )) {
        Invoke-AkiraFlashLoopbackEndpoint -HostName $endpoint.Host -Port 443 -Path $endpoint.Path
    }

    Add-AkiraFlashTimelineEvent -Timestamp $time.InitialAccess -Phase 'Initial Access' -Event 'Bing search led to opmanager.pro and ManageEngine-OpManager.msi.' -Details @{ website = 'metadata-only'; installerLive = $false; reportedSha256 = '186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da' }
    Add-AkiraFlashTimelineEvent -Timestamp $time.InitialAccess.AddMinutes(6) -Phase 'Execution' -Event 'consent.exe and msimg32.dll Bumblebee sideload represented with signed and inert decoys.' -Details @{ malwareExecuted = $false; C2ActualDestination = '127.0.0.1' }
}
