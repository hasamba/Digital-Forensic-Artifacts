function Invoke-BengalLureAndTDS {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths, [switch]$LaunchVisibleBrowser)

    $referrer = 'https://www.bing.com/search?q=bitdefender+central+download'
    $lureUrl = 'https://oculus-app.com/'
    $trackingToken = ConvertTo-BengalTrackingToken -Value $lureUrl
    $redirectIoc = "https://link72.com/r/$trackingToken"
    $lurePath = Join-Path $Paths.Lure 'bitdefender-central-help.html'

    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Bitdefender Central Help - Local DFIR Canary</title>
<meta name="keywords" content="bitdefender central download activate support setup">
<meta name="google-site-verification" content="BENGALSEO-CANARY-VERIFY">
</head><body>
<h1>Bitdefender Central Help</h1>
<p>This is a local forensic canary. It never loads remote content.</p>
<button id="continue" data-tds-ioc="$redirectIoc">Get Started</button>
<div id="status"></div>
<script>
const campaign = {
  referrer: '$referrer',
  trackingDomainIOC: 'stats.us3.org',
  trackingEndpointIOC: 'https://stats.us3.org/matomo.php',
  siteId: 35,
  redirectIOC: '$redirectIoc'
};
document.getElementById('continue').onclick = () => {
  document.getElementById('status').textContent = 'Local CAPTCHA passed; payload delivery recorded.';
  localStorage.setItem('bengalseo_canary', JSON.stringify(campaign));
};
</script></body></html>
"@
    Write-BengalEvidenceFile -Path $lurePath -Content $html -Purpose 'local SEO lure page with inert Matomo and redirector IOC strings'

    $fingerprint = [ordered]@{
        url = $lureUrl
        urlref = $referrer
        idsite = 35
        visitorId = '82fc7378bc9ef9d9'
        pageviewId = 'FAsJXL'
        os = 'Windows 10.0.0'
        browser = 'Microsoft Edge 133.0.3065.92 / Chromium 133.0.6943.142'
        resolution = '1360x768'
        captchaVerdict = 'allow-canary'
        redirectTrackingToken = $trackingToken
    } | ConvertTo-Json -Depth 4
    Write-BengalEvidenceFile -Path (Join-Path $Paths.Tds 'matomo-browser-fingerprint.json') -Content $fingerprint -Purpose 'reported Matomo/browser fingerprint telemetry canary'

    Invoke-BengalLoopbackRequest -HostName 'stats.us3.org' -Path '/matomo.php?idsite=35&rec=1'
    Invoke-BengalLoopbackRequest -HostName 'link72.com' -Path "/r/$trackingToken"

    if ($LaunchVisibleBrowser) {
        $edge = Get-Command msedge.exe -ErrorAction SilentlyContinue
        if ($edge) {
            $localUri = ([Uri]$lurePath).AbsoluteUri
            Start-Process -FilePath $edge.Source -ArgumentList @('--inprivate', '--no-first-run', '--disable-background-networking', $localUri) | Out-Null
            Add-BengalManifestEntry -Type 'process' -Path 'msedge.exe' -Action 'launched-local-file' -Details @{ localUri = $localUri; remoteNavigation = $false }
        }
    }

    Write-BengalPhaseMarker -Phase '01-LureAndTDS' -Description 'Local lure, browser fingerprint, Base64 tracking token, CAPTCHA verdict, and loopback-only redirector/Matomo requests.'
}
