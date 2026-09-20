function Invoke-FogOpenDirectoryInitialAccess {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $observed = $script:FogAnchor.AddDays(-263)
    $names = @('.bash_history', '.bashrc', '.cache', '.config', '.gnupg', '.local', '.nxc', '.profile', '.sliver', '.sliver-client', '.ssh', '.wget-hsts', '.Xauthority', '.xorgxrdp.10.log', '.xsession-errors', '20241121150831_Certipy.zip', 'any.ps1', 'AnyDesk.exe', 'Certipy', 'Desktop', 'Documents', 'DonPAPI-1.0.0', 'Downloads', 'Music', 'noPac', 'orpheus', 'ouroverde.net.br', 'Pachine', 'Pictures', 'powercat.ps1', 'Public', 'sliver-client_linux', 'sliver-client_linux.sig', 'sliver-server', 'sliver-server_linux.sig', 'slv.bin', 'snap', 'sonic_scan', 'sonic_scan.zip', 'Templates', 'thinclient_drives', 'v1.0.0.zip', 'Videos', 'zer0dump')
    foreach ($name in $names) {
        if ($name -in @('.nxc', 'DonPAPI-1.0.0', '.sliver', '.config', 'sliver-client_linux', 'sliver-server')) { continue }
        $path = Join-Path $Paths.OpenDirectory $name
        if ([IO.Path]::GetExtension($name) -or $name.StartsWith('.')) {
            Write-FogEvidenceFile -Path $path -Content "FOG OPEN-DIRECTORY CANARY: $name" -Purpose 'reported open-directory listing artifact' -Timestamp $observed
        } else { New-Item -Path $path -ItemType Directory -Force | Out-Null }
    }
    Write-FogEvidenceFile -Path (Join-Path $Paths.Evidence 'open-directory-listing.txt') -Content ($names -join "`n") -Purpose 'captured directory-index listing' -Timestamp $observed

    $sonic = Join-Path $Paths.OpenDirectory 'sonic_scan'
    New-Item -Path $sonic -ItemType Directory -Force | Out-Null
    Write-FogEvidenceFile -Path (Join-Path $sonic 'data.txt') -Content @'
127.0.0.1,CANARY-VPN-USER,Generated-Not-A-Real-Password,LAB.INVALID,NetExtender
127.0.0.1,CANARY-VPN-USER2,Generated-Not-A-Real-Password2,LAB.INVALID,NetExtender
'@ -Purpose 'generated SonicWall scanner input; no reported victim credentials' -Timestamp $observed
    Write-FogEvidenceFile -Path (Join-Path $sonic 'main.py') -Content @'
# FOG CANARY: non-executable documentation of reported logic.
# netextender <target> --username <user> --password <password> --domain <domain> --always-trust
# This file does not import subprocess, sockets, nmap, or a VPN library.
print("FOG CANARY - VPN login and scanning disabled")
'@ -Purpose 'inert SonicWall scanner source canary' -Timestamp $observed
    $netextender = Join-Path $sonic 'netextender.exe'
    New-FogBinaryDecoy -Path $netextender -Role 'SonicWall NetExtender process-name canary'
    Invoke-FogDecoyProcess -FilePath $netextender -ReportedCommandLine 'netextender 127.0.0.1 --username CANARY-VPN-USER --password Generated-Not-A-Real-Password --domain LAB.INVALID --always-trust'
    foreach ($port in @(443, 500, 4500)) { Invoke-FogLoopbackPort -Port $port -ReportedTarget 'generated SonicWall VPN target' }
    Write-FogEvidenceFile -Path (Join-Path $Paths.Evidence 'vpn-and-nmap-results.json') -Content (@{ vpnConnected = $false; targets = @('127.0.0.1'); scannedPorts = @(53, 80, 88, 135, 139, 389, 443, 445, 3389); remoteScan = $false } | ConvertTo-Json -Depth 5) -Purpose 'VPN and follow-on scan evidence canary' -Timestamp $observed.AddMinutes(5)
    Add-FogTimelineEvent -Phase 'Initial Access' -Event 'Generated SonicWall credential records drove an echo-only NetExtender process and loopback scan evidence.' -Details @{ validAccountsUsed = $false; vpnConnected = $false; actualTarget = '127.0.0.1' } -Timestamp $observed
}
