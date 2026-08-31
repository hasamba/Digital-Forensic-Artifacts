function Invoke-InterlockPHPExecutionDiscovery {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)
    $time = Get-InterlockTimeline

    New-InterlockBinaryDecoy -Path $Paths.PhpExe -Role 'PHP Interlock RAT process-name canary'
    New-InterlockSizedConfigCanary -Path $Paths.Config -Size 27392 -ReportedSha256 '28a9982cf2b4fc53a1545b6ed0d0c1788ca9369a847750f5652ffa0ca7f7b7d3' -Timestamp $time.PhpRat
    New-InterlockSizedConfigCanary -Path $Paths.AltConfig -Size 28268 -ReportedSha256 '8afd6c0636c5d70ac0622396268786190a428635e9cf28ab23add939377727b0' -Timestamp $time.PhpRat.AddSeconds(5)
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.PhpRoot 'ext\php_zip.dll') -Content 'MZ-INTERLOCK-CANARY - inert ZIP extension filename only.' -Purpose 'PHP ZIP extension-shaped canary' -Timestamp $time.PhpRat

    $phpCommand = "`"$($Paths.PhpExe)`" -d extension=zip -d extension_dir=ext `"$($Paths.Config)`" 1"
    Invoke-InterlockDecoyProcess -FilePath $Paths.PhpExe -ReportedCommandLine $phpCommand

    $automatedCommands = @'
powershell -c Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Permanent' } | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress | ConvertTo-Json
powershell -c "systeminfo /FO CSV | ConvertFrom-Csv | ConvertTo-Json"
powershell -c "if current identity is SYSTEM then SYSTEM elseif Administrator then ADMIN else USER"
powershell -c "tasklist /svc /FO CSV | ConvertFrom-Csv | ConvertTo-Json"
powershell -c "Get-Service | Select-Object Name,DisplayName | ConvertTo-Json"
powershell -c "Get-PSDrive -PSProvider FileSystem | ConvertTo-Json"
'@
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Discovery 'automated-command-lines.txt') -Content $automatedCommands -Purpose 'reported automated discovery command lines' -Timestamp $time.Discovery

    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    foreach ($command in ($automatedCommands -split "`n" | Where-Object { $_.Trim() })) {
        Invoke-InterlockDecoyProcess -FilePath $cmd -ReportedCommandLine $command.Trim()
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $privilege = if ($identity.Name -match '(?i)SYSTEM') { 'SYSTEM' } elseif ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'ADMIN' } else { 'USER' }
    $neighborData = if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Permanent' } | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State)
    } else { @() }
    $localProfile = [ordered]@{
        disclaimer = 'Read-only profile of this lab host; no data is transmitted.'
        computer = Get-CimInstance Win32_ComputerSystem | Select-Object Name, Manufacturer, Model, TotalPhysicalMemory
        operatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
        processes = @(Get-Process | Select-Object -First 75 Name, Id)
        services = @(Get-Service | Select-Object Name, DisplayName, Status)
        drives = @(Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, Used, Free)
        neighbors = $neighborData
        privilege = $privilege
    }
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Discovery 'automated-system-profile.json') -Content ($localProfile | ConvertTo-Json -Depth 7) -Purpose 'local automated discovery JSON matching RAT collection categories' -Timestamp $time.Discovery.AddMinutes(2)

    $handsOnCommands = @'
powershell -WindowStyle Hidden -Command "echo AD_Computers: ([adsiSearcher]'(ObjectClass=computer)').FindAll().count"
powershell -Command "search AD users with non-empty description attributes"
net user %USERNAME% /domain
powershell -Command "search computer names matching VB|VBR|VEEA|VEEAM|BCK|BACK"
tasklist
nltest /dclist:
whoami
dir %appdata%
'@
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Discovery 'hands-on-command-lines.txt') -Content $handsOnCommands -Purpose 'reported interactive discovery command lines' -Timestamp $time.HandsOn
    foreach ($command in ($handsOnCommands -split "`n" | Where-Object { $_.Trim() })) {
        Invoke-InterlockDecoyProcess -FilePath $cmd -ReportedCommandLine $command.Trim()
    }

    $directoryResults = [ordered]@{
        disclaimer = 'Synthetic directory search results; no LDAP or domain query was performed.'
        AD_Computers = 7
        describedUsers = @('svc_backup - LAB CANARY backup operator', 'svc_veeam - LAB CANARY Veeam service')
        backupTargets = @('VEEAM01 - LAB CANARY backup server', 'VBR02 - LAB CANARY repository')
        domainControllers = @('DC01.lab.invalid', 'DC02.lab.invalid')
    }
    Write-InterlockEvidenceFile -Path (Join-Path $Paths.Discovery 'directory-search-results.json') -Content ($directoryResults | ConvertTo-Json -Depth 6) -Purpose 'AD/Veeam targeting canaries without directory access' -Timestamp $time.HandsOn.AddMinutes(3)

    Add-InterlockTimelineEvent -Timestamp $time.PhpRat -Phase 'Execution' -Event 'AppData Roaming php.exe launched with ZIP extension directives and wefs.cfg argument.' -Details @{ phpRuntime = 'signed cmd decoy'; configExecutable = $false; configSizes = @(27392, 28268) }
    Add-InterlockTimelineEvent -Timestamp $time.Discovery -Phase 'Automated Discovery' -Event 'RAT produced a local JSON system profile covering system, processes, services, drives, neighbors, and privilege context.' -Details @{ transmitted = $false; domainQueried = $false }
    Add-InterlockTimelineEvent -Timestamp $time.HandsOn -Phase 'Hands-on Discovery' -Event 'Interactive AD, user-description, backup-server, task, DC, identity, and AppData discovery represented with escaped command lines and synthetic results.' -Details @{ LDAPQueried = $false; remoteSystemsContacted = $false }
}
