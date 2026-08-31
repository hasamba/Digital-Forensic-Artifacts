function Invoke-FogSliverTunneling {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    foreach ($name in @('sliver-client_linux', 'sliver-server', 'slv.bin')) {
        $path = Join-Path $Paths.OpenDirectory $name
        New-FogBinaryDecoy -Path $path -Role 'Sliver component filename canary'
        Invoke-FogDecoyProcess -FilePath $path -ReportedCommandLine "$name --reported-server 194.48.154.79:31337 --actual-loopback 127.0.0.1:31337"
    }
    Invoke-FogLoopbackPort -Port 31337 -ReportedTarget '194.48.154.79:31337 Sliver team server'
    Invoke-FogLoopbackPort -Port 80 -ReportedTarget '194.48.154.79:80 open directory'
    Write-FogEvidenceFile -Path (Join-Path $Paths.OpenDirectory '.sliver\configs\fog-affiliate.cfg') -Content @'
{
  "reported_server": "194.48.154.79:31337",
  "actual_connection": "127.0.0.1:31337",
  "implant_generated": false,
  "encrypted_slv_bin_analyzed": false
}
'@ -Purpose 'Sliver configuration canary'

    Write-FogEvidenceFile -Path (Join-Path $Paths.OpenDirectory '.config\proxychains.conf') -Content @'
strict_chain
proxy_dns_old
[ProxyList]
socks5 127.0.0.1 1080
# Reported victim routes intentionally omitted; loopback only.
'@ -Purpose 'loopback-only Proxychains configuration canary'
    Invoke-FogLoopbackPort -Port 1080 -ReportedTarget 'Proxychains SOCKS pivot'
    Write-FogEvidenceFile -Path (Join-Path $Paths.OpenDirectory 'powercat.ps1') -Content @'
# FOG CANARY: filename and analyst-search terms only.
# Reported capabilities: TCP, UDP, bind shell, reverse shell, transfer, DNS/dnscat2, tunneling.
# No socket, listener, payload, encoded command, or invocation is implemented.
Write-Output 'FOG CANARY: Powercat networking disabled'
'@ -Purpose 'inert Powercat artifact'
    Write-FogEvidenceFile -Path (Join-Path $Paths.Evidence 'c2-and-tunneling.json') -Content (@{
        reportedOpenDirectory = '194.48.154.79:80'; reportedSliverPort = 31337; actualTargets = @('127.0.0.1:80', '127.0.0.1:31337', '127.0.0.1:1080'); proxyTrafficRouted = $false; reverseShellOpened = $false; dataTransferred = $false; ransomwareExecuted = $false
    } | ConvertTo-Json -Depth 5) -Purpose 'C2/tunneling evidence and negative assertions'
    Add-FogTimelineEvent -Phase 'Command and Control' -Event 'Sliver, Proxychains, and Powercat artifacts were staged with loopback-only connection telemetry.' -Details @{ reportedInfrastructure = '194.48.154.79'; actualScope = '127.0.0.1'; implantGenerated = $false; tunnelOpened = $false }
    Add-FogTimelineEvent -Phase 'Impact' -Event 'No ransomware deployment was observed in the report and none is simulated.' -Details @{ ransomwareExecuted = $false; encryption = $false; leakSiteVictims = 'metadata only' }
}
