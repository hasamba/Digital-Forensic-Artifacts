function Invoke-LynxCollectionAndExfiltration {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-LynxTimeline

    $finance = Join-Path $Paths.Shares 'FILE01\Finance'
    $legal = Join-Path $Paths.Shares 'FILE02\Legal'
    New-Item -Path $finance -ItemType Directory -Force | Out-Null
    New-Item -Path $legal -ItemType Directory -Force | Out-Null
    Write-LynxEvidenceFile -Path (Join-Path $finance 'FY2025_Budget_CANARY.xlsx') -Content "DFIR-CANARY,Department,Amount`nDFIR-CANARY,Research,25000" -Purpose 'generated collection canary; contains no user data' -Timestamp $time.Day6.AddMinutes(31)
    Write-LynxEvidenceFile -Path (Join-Path $finance 'Payroll_Summary_CANARY.csv') -Content "DFIR-CANARY,Employee,Value`nDFIR-CANARY,Sample User,0" -Purpose 'generated collection canary; contains no real personal data' -Timestamp $time.Day6.AddMinutes(32)
    Write-LynxEvidenceFile -Path (Join-Path $legal 'Merger_Draft_CANARY.docx') -Content 'DFIR CANARY ONLY - synthetic legal document content.' -Purpose 'generated collection canary; not a real Word document or user file' -Timestamp $time.Day6.AddMinutes(33)

    $sevenZip = Join-Path $Paths.Desktop000 '7zG.exe'
    New-LynxCommandDecoy -Path $sevenZip -ReportedSha256 'NOT-PUBLISHED-IN-REPORT' -Role '7-Zip GUI process-name and context-menu command-line canary'

    $archive1 = Join-Path $Paths.Archives 'FILE01_Finance.zip'
    $archive2 = Join-Path $Paths.Archives 'FILE02_Legal.zip'
    Invoke-LynxDecoyProcess -FilePath $sevenZip -ReportedCommandLine "7zG.exe a `"$archive1`" `"$finance\*`""
    Invoke-LynxDecoyProcess -FilePath $sevenZip -ReportedCommandLine "7zG.exe a `"$archive2`" `"$legal\*`""
    Compress-Archive -Path (Join-Path $finance '*') -DestinationPath $archive1 -Force
    Compress-Archive -Path (Join-Path $legal '*') -DestinationPath $archive2 -Force
    foreach ($archive in @($archive1, $archive2)) {
        Set-LynxArtifactTime -Path $archive -Timestamp $time.Day6.AddMinutes(38)
        Add-LynxManifestEntry -Type 'file' -Path $archive -Action 'created-from-generated-canaries' -Details @{ purpose = '7-Zip collection artifact'; sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash; userData = $false }
        Invoke-LynxLoopbackUpload -FilePath $archive
    }

    $browserHistory = @(
        [ordered]@{ timestamp = $time.Day6.AddMinutes(43).ToString('o'); url = 'https://temp.sh/'; transition = 'typed'; actualConnection = '127.0.0.1 via curl --resolve' },
        [ordered]@{ timestamp = $time.Day6.AddMinutes(44).ToString('o'); url = 'https://temp.sh/upload'; transition = 'form_submit'; actualConnection = '127.0.0.1 via curl --resolve' },
        [ordered]@{ timestamp = $time.Day6.AddMinutes(45).ToString('o'); url = 'https://temp.sh/upload'; transition = 'form_submit'; actualConnection = '127.0.0.1 via curl --resolve' }
    )
    Write-LynxEvidenceFile -Path (Join-Path $Paths.Evidence 'edge-history-temp-sh-canary.json') -Content ($browserHistory | ConvertTo-Json -Depth 5) -Purpose 'portable browsing-history representation of temp.sh upload activity' -Timestamp $time.Day6.AddMinutes(46)

    Add-LynxTimelineEvent -Timestamp $time.Day6.AddMinutes(30) -Phase 'Collection' -Event 'Generated Finance and Legal canaries archived individually with 7-Zip process-name telemetry.' -Details @{ archives = @('FILE01_Finance.zip', 'FILE02_Legal.zip'); realUserData = $false }
    Add-LynxTimelineEvent -Timestamp $time.Day6.AddMinutes(43) -Phase 'Exfiltration' -Event 'Two temp.sh upload attempts forced to loopback with proxy bypass.' -Details @{ destinationIoc = 'temp.sh'; actualAddress = '127.0.0.1'; realExfiltration = $false }
}
