function New-AkiraFlashImpactRepresentation {
    param(
        [Parameter(Mandatory)][string]$WaveRoot,
        [Parameter(Mandatory)][datetime]$Timestamp,
        [Parameter(Mandatory)][string]$WaveName
    )
    foreach ($source in Get-ChildItem -LiteralPath $WaveRoot -File -Recurse | Where-Object { $_.Extension -ne '.akira' -and $_.Name -ne 'akira_readme.txt' }) {
        $destination = "$($source.FullName).akira"
        $hash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
        $content = @"
AKIRA-FLASH-INERT-IMPACT-REPRESENTATION
Wave=$WaveName
No encryption occurred; the original generated canary remains intact.
OriginalPath=$($source.FullName)
OriginalSHA256=$hash
"@
        Write-AkiraFlashEvidenceFile -Path $destination -Content $content -Purpose 'Akira extension artifact without encryption' -Timestamp $Timestamp
    }
    $note = @"
AKIRA RANSOMWARE FORENSIC CANARY - $WaveName
No file was encrypted. No onion address, payment instruction, victim identifier,
or attacker contact detail in this note is real.
"@
    Write-AkiraFlashEvidenceFile -Path (Join-Path $WaveRoot 'akira_readme.txt') -Content $note -Purpose 'inert Akira ransom-note artifact' -Timestamp $Timestamp.AddMinutes(1)
}

function Invoke-AkiraFlashTwoWaveImpact {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-AkiraFlashTimeline
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $locker = Join-Path $Paths.Payloads 'locker.exe'
    New-AkiraFlashBinaryDecoy -Path $locker -Role 'Akira locker.exe process-name and command-line canary' -ReportedSha256 'de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d'

    $rootWave = Join-Path $Paths.CanaryData 'ROOT-DOMAIN'
    Write-AkiraFlashEvidenceFile -Path (Join-Path $rootWave 'FILE01\Finance\RootBudget_CANARY.xlsx') -Content 'AKIRA-FLASH-CANARY root-domain finance data.' -Purpose 'generated first-wave impact canary' -Timestamp $time.FirstWave.AddMinutes(-8)
    Write-AkiraFlashEvidenceFile -Path (Join-Path $rootWave 'WS001\Users\Admin\RootNotes_CANARY.docx') -Content 'AKIRA-FLASH-CANARY root-domain workstation data.' -Purpose 'generated first-wave impact canary' -Timestamp $time.FirstWave.AddMinutes(-7)
    Invoke-AkiraFlashDecoyProcess -FilePath $locker -ReportedCommandLine "locker.exe --local --network-shares --path `"$rootWave`" (inert first-wave canary)"
    New-AkiraFlashImpactRepresentation -WaveRoot $rootWave -Timestamp $time.FirstWave -WaveName 'ROOT-DOMAIN-FIRST-WAVE'

    $shareFinder = Join-Path $Paths.Evidence 'child-domain-sharefinder.txt'
    Invoke-AkiraFlashDecoyProcess -FilePath $cmd -ReportedCommandLine 'powershell.exe -NoProfile -Command Invoke-ShareFinder -Domain child.corp'
    Write-AkiraFlashEvidenceFile -Path $shareFinder -Content "ShareFinder canary`n\\CHILD-FILE01\Projects (metadata only)`n\\CHILD-DC01\SYSVOL (metadata only; never accessed)" -Purpose 'child-domain share discovery canary' -Timestamp $time.SecondWave.AddMinutes(-16)
    Invoke-AkiraFlashDecoyProcess -FilePath $cmd -ReportedCommandLine 'dnscmd CHILD-DC01 /ZoneExport child.corp child-corp.dns'
    Invoke-AkiraFlashDecoyProcess -FilePath $cmd -ReportedCommandLine 'dnscmd CHILD-DC01 /ZoneExport _msdcs.child.corp msdcs-child.dns'
    Write-AkiraFlashEvidenceFile -Path (Join-Path $Paths.Evidence 'child-corp.dns') -Content "; AKIRA-FLASH-CANARY DNS zone export`n@ IN SOA CHILD-DC01.child.corp. hostmaster.child.corp. (1 3600 600 86400 60)" -Purpose 'synthetic DNS zone export; no DNS server contacted' -Timestamp $time.SecondWave.AddMinutes(-13)

    $rustDesk = Join-Path $Paths.Payloads 'RustDesk\rustdesk.exe'
    Invoke-AkiraFlashDecoyProcess -FilePath $rustDesk -ReportedCommandLine 'rustdesk.exe --reentry CHILD-DC01 (service is not installed; network disabled)'

    $childWave = Join-Path $Paths.CanaryData 'CHILD-DOMAIN'
    Write-AkiraFlashEvidenceFile -Path (Join-Path $childWave 'CHILD-FILE01\Projects\Roadmap_CANARY.docx') -Content 'AKIRA-FLASH-CANARY child-domain project data.' -Purpose 'generated second-wave impact canary' -Timestamp $time.SecondWave.AddMinutes(-7)
    Write-AkiraFlashEvidenceFile -Path (Join-Path $childWave 'CHILD-WS01\Users\Engineer\Design_CANARY.pdf') -Content 'AKIRA-FLASH-CANARY child-domain workstation data.' -Purpose 'generated second-wave impact canary' -Timestamp $time.SecondWave.AddMinutes(-6)
    Invoke-AkiraFlashDecoyProcess -FilePath $locker -ReportedCommandLine "locker.exe --local --network-shares --path `"$childWave`" (inert second-wave canary)"
    New-AkiraFlashImpactRepresentation -WaveRoot $childWave -Timestamp $time.SecondWave -WaveName 'CHILD-DOMAIN-SECOND-WAVE'

    Add-AkiraFlashTimelineEvent -Timestamp $time.FirstWave -Phase 'Impact' -Event 'First Akira deployment occurred just under 44 hours after initial access in the root domain.' -Details @{ reportedPayload = 'locker.exe'; reportedSha256 = 'de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d'; encryption = $false; userDataTouched = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $time.SecondWave.AddMinutes(-16) -Phase 'Discovery' -Event 'Threat actor returned via RustDesk two days later and performed ShareFinder and DNS zone export discovery in a child domain.' -Details @{ remoteAccessInstalled = $false; domainContacted = $false; SYSVOLAccessed = $false }
    Add-AkiraFlashTimelineEvent -Timestamp $time.SecondWave -Phase 'Impact' -Event 'Second Akira wave represented against generated child-domain canaries.' -Details @{ encryption = $false; userDataTouched = $false; operationalDisruption = 'metadata only' }
}
