#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\RyukSpeedSim-utilities.ps1"
Assert-RSSafety -LabConfirmed:$LabConfirmed
$p = Initialize-RSEnvironment

$roles = [ordered]@{'BAK01-CANARY'='backup server';'FS01-CANARY'='file server';'DEPLOY01-CANARY'='software deployment server';'WS01-CANARY'='workstation';'WS02-CANARY'='workstation';'WS03-CANARY'='workstation'}
foreach ($entry in $roles.GetEnumerator()) { $null = New-RSHostTree -Name $entry.Key -Role $entry.Value }
$ryuk = Join-Path $p.Payloads 'fx2-12_multi_for_crypt_x86.exe'
New-RSDecoy -Path $ryuk -Role 'Ryuk ransomware stand-in' -PublishedSha256 '34007d53a8e64bf1dbbeace9e4878fb209878e6a6843251895d4dc9c2699056e'
Invoke-RSDecoy -FilePath $ryuk -Reported 'fx2-12_multi_for_crypt_x86.exe deployed through RDP from domain controllers to servers and workstations' -Parent 'RDP session from compromised domain controller' -Label 'SYNTHETIC-RYUK'

$reportedCommands = @(
    'C:\Windows\system32\net1 stop "samss" /y',
    'C:\Windows\system32\net1 stop "veeamcatalogsvc" /y',
    'C:\Windows\system32\net1 stop "veeamcloudsvc" /y',
    'C:\Windows\system32\net1 stop "veeamdeploysvc" /y',
    'C:\Windows\System32\net.exe stop "samss" /y',
    'C:\Windows\System32\net.exe stop "veeamcatalogsvc" /y',
    'C:\Windows\System32\net.exe stop "veeamcloudsvc" /y',
    'C:\Windows\System32\net.exe stop "veeamdeploysvc" /y',
    'C:\Windows\System32\taskkill.exe /IM sqlbrowser.exe /F',
    'C:\Windows\System32\taskkill.exe /IM sqlceip.exe /F',
    'C:\Windows\System32\taskkill.exe /IM sqlservr.exe /F',
    'C:\Windows\System32\taskkill.exe /IM sqlwriter.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.agent.configurationservice.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.brokerservice.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.catalogdataservice.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.cloudservice.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.externalinfrastructure.dbprovider.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.manager.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.mountservice.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.service.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.uiserver.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.backup.wmiserver.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeamdeploymentsvc.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeamfilesysvsssvc.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeam.guest.interaction.proxy.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeamnfssvc.exe /F',
    'C:\Windows\System32\taskkill.exe /IM veeamtransportsvc.exe /F',
    'C:\Windows\system32\taskmgr.exe /4',
    'C:\Windows\system32\wbem\wmiprvse.exe -Embedding',
    'C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding',
    'icacls "C:\*" /grant Everyone:F /T /C /Q',
    'icacls "D:\*" /grant Everyone:F /T /C /Q'
)
foreach ($command in $reportedCommands) { Invoke-RSDecoy -FilePath $ryuk -Reported $command -Parent 'fx2-12_multi_for_crypt_x86.exe' -Label 'NO-IMPACT-COMMAND' }
Write-RSJson -Path (Join-Path $p.Evidence 'pre-impact-commands.json') -Object ([ordered]@{reportedCommands=$reportedCommands;servicesStopped=0;processesTerminated=0;aclChanges=0;drivesTraversed=0;reportedOnly=$true}) -Purpose impact

$impactRecords = New-Object System.Collections.Generic.List[object]
foreach ($entry in $roles.GetEnumerator()) {
    $hostRoot = Join-Path $p.Hosts $entry.Key
    foreach ($department in @('Finance','Operations')) {
        $marker = Join-Path $hostRoot "C$\$department\README_FOR_FORENSICS.txt"
        Write-RSFile -Path $marker -Content "RYUK-SPEED INERT RANSOM-NOTE CANARY for $($entry.Key). No original file was changed." -Purpose ransom-note-canary
        $extension = Join-Path $hostRoot "C$\$department\generated-evidence.RYUK-CANARY"
        Write-RSFile -Path $extension -Content "INERT ENCRYPTION MARKER for generated host $($entry.Key). This is newly generated canary data, not encrypted data." -Purpose encryption-canary
    }
    $impactRecords.Add([ordered]@{hostname=$entry.Key;role=$entry.Value;generatedTree=$hostRoot;generatedMarkers=4;userFilesRead=0;userFilesChanged=0;filesEncrypted=0})
}
Write-RSJson -Path (Join-Path $p.Evidence 'impact-summary.json') -Object ([ordered]@{reportedStartMinutes=120;reportedCompletionMinutes=180;reportedOrder=@('backup, file, and software deployment servers','workstations');generatedHosts=$impactRecords;reportedExtension='Ryuk ransomware impact';actualExtension='.RYUK-CANARY';servicesStopped=0;processesTerminated=0;aclChanges=0;userFilesRead=0;userFilesChanged=0;filesEncrypted=0;generatedCanaryMarkers=24}) -Purpose impact
Invoke-RSLoopback -Port 3389 -Target 'server and workstation targets from compromised domain controllers' -Role 'Ryuk RDP deployment marker'
Add-RSTimeline -Minutes 120 -Phase impact -Event 'Ryuk deployment begins around two hours; generated backup, file, and deployment servers marked first' -Details @{rdpSessions=0;filesEncrypted=0;generatedTargets=3}
Add-RSTimeline -Minutes 145 -Phase impact -Event 'Generated workstation impact markers created after server wave' -Details @{filesEncrypted=0;generatedTargets=3}
Add-RSTimeline -Minutes 180 -Phase impact -Event 'Report states entire domain encrypted three hours after initial access' -Details @{realDomainTargets=0;userFilesChanged=0;generatedCanaryMarkers=24}
Write-RSJson -Path (Join-Path $p.Evidence 'phase3-negative.json') -Object ([ordered]@{rdpSessions=0;remoteDeployments=0;servicesStopped=0;processesTerminated=0;aclChanges=0;drivesTraversed=0;userFilesRead=0;userFilesChanged=0;filesEncrypted=0;securityControlsChanged=0;logsCleared=0;shadowCopiesDeleted=0;externalConnections=0;bytesTransferred=0}) -Purpose safety
