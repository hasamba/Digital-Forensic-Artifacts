function Invoke-BengalMayaBotAndScam {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)

    $session = [ordered]@{
        family = 'MayaBot-CANARY'
        observedSince = 2022
        campaign = 'Bitdefender support lure'
        execution = 'wscript.exe BitdefenderSupportInstaller.exe.js'
        actualNetworkDestination = '127.0.0.1 only'
        reportC2Metadata = @('cus.cam', 'dll.lat', 'us99.org')
        prohibitedBehaviors = @('credential collection', 'remote access', 'real C2', 'live malware download')
    } | ConvertTo-Json -Depth 5
    Write-BengalEvidenceFile -Path (Join-Path $Paths.MayaCache 'mayabot-session.json') -Content $session -Purpose 'MayaBot investigation metadata and local execution session'

    foreach ($hostName in @('cus.cam', 'dll.lat', 'us99.org')) {
        Invoke-BengalLoopbackRequest -HostName $hostName -Path '/api/checkin?campaign=bitdefender-central'
    }

    $scamPage = @'
<!doctype html><html><head><meta charset="utf-8"><title>Support Required</title></head>
<body><h1>Activation support required</h1>
<p>Call 1-800-555-0100 (reserved fictional number; local canary only).</p>
<p>No call is placed and no real contact details are included.</p></body></html>
'@
    Write-BengalEvidenceFile -Path (Join-Path $Paths.Lure 'tech-support-scam-landing.html') -Content $scamPage -Purpose 'inert alternate phone-scam outcome using a reserved fictional number'

    Write-BengalPhaseMarker -Phase '03-MayaBotAndScam' -Description 'MayaBot-named local session, loopback-only IOC command lines, and inert alternate tech-support scam landing page.'
}
