#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()] param([switch]$LabConfirmed)
. "$PSScriptRoot\WordPressGodzillaSim-utilities.ps1"
Assert-WordPressGodzillaSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-WordPressGodzillaEnvironment
$dashDecoy = Join-Path $paths.Process 'usr\bin\dash.exe'
New-WordPressGodzillaDecoy $dashDecoy 'signed Windows stand-in for Apache child /usr/bin/dash'

$commands = @(
    'whoami', 'id', 'ls', 'uname -a', 'ufw', 'ufw status', 'env', 'sudo -l', 'sudo -S',
    'ls -la', 'history', 'ip route', 'lsb_release -a', 'sudo -V', 'netstat -a',
    'cat /etc/services', 'cat /proc/1/cgroup', 'ifconfig', 'ip addr', 'cat /etc/shadow',
    'ps aux ps -ef top cat /etc/services', 'find / -type f -perm 0777'
)
foreach ($command in $commands) { Invoke-WordPressGodzillaDecoy $dashDecoy $command }

$tree = [ordered]@{
    reportedParent = @{ image = '/usr/sbin/apache2'; account = 'www-data'; uid = 33 }
    reportedChild = @{ image = '/usr/bin/dash'; reason = '/usr/bin/sh symlink target' }
    actualProcess = @{ image = $dashDecoy; signedCmdCopy = $true; behavior = 'echo only' }
    reportedCommands = $commands
    realLinuxCommandsExecuted = $false
    realCredentialFilesRead = $false
}
Write-WordPressGodzillaFile (Join-Path $paths.Evidence 'apache-dash-process-tree.json') ($tree | ConvertTo-Json -Depth 8) 'process ancestry evidence'

$linEnumPath = Join-Path $paths.Upload '1.sh'
Write-WordPressGodzillaFile $linEnumPath "INERT LINENUM CANARY`nReported command sequence: touch 1.sh; chmod +x 1.sh; bash ./1.sh; rm -rf 1.sh`nNo shell statements or executable content are present. The canary intentionally remains for investigation." 'inert LinEnum filename canary'
foreach ($command in @('touch 1.sh', 'chmod +x 1.sh', 'bash ./1.sh', 'rm -rf 1.sh', 'mysql -u admin -p')) {
    Invoke-WordPressGodzillaDecoy $dashDecoy $command
}

$negativeActions = [ordered]@{
    etcShadow = @{ reportedCommand = 'cat /etc/shadow'; actualAccess = $false; credentialsCollected = $false }
    mysql = @{ reportedCommand = 'mysql -u admin -p'; authenticated = $false; actualClientRun = $false }
    linEnum = @{ reportedPath = '/var/www/html/wp-content/uploads/p3d/1.sh'; executed = $false; removed = $false; canaryRemains = $true }
}
Write-WordPressGodzillaFile (Join-Path $paths.Evidence 'discovery-negative-actions.json') ($negativeActions | ConvertTo-Json -Depth 6) 'unsafe-action refusal evidence'
Add-WordPressGodzillaTimeline 18 discovery 'Apache-to-dash discovery burst represented with a signed echo-only decoy' @{ commandCount = $commands.Count; techniques = @('T1059.004', 'T1087', 'T1082', 'T1016', 'T1046', 'T1083', 'T1518.001', 'T1003.008') }
Add-WordPressGodzillaTimeline 86 collection 'LinEnum upload and invocation strings represented by inert evidence' @{ scriptExecuted = $false; artifactDeleted = $false; technique = 'T1105' }
Add-WordPressGodzillaTimeline 112 discovery 'MySQL login attempt represented as a negative record' @{ credentialsUsed = $false; databaseContacted = $false }
