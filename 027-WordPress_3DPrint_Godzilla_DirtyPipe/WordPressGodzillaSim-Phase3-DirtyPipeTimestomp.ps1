#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()] param([switch]$LabConfirmed)
. "$PSScriptRoot\WordPressGodzillaSim-utilities.ps1"
Assert-WordPressGodzillaSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-WordPressGodzillaEnvironment
$dashDecoy = Join-Path $paths.Process 'usr\bin\dash.exe'
if (-not (Test-Path $dashDecoy)) { New-WordPressGodzillaDecoy $dashDecoy 'signed Windows stand-in for Apache child /usr/bin/dash' }

$dirtyPipe = Join-Path $paths.Upload 'Dirty-Pipe.sh'
Write-WordPressGodzillaFile $dirtyPipe "INERT CVE-2022-0847 CANARY`nThe report associated this filename with r1is/CVE-2022-0847.`nNo exploit, compiler input, passwd manipulation, shell, or executable content is present." 'inert Dirty Pipe filename canary'
foreach ($command in @('bash ./Dirty-Pipe.sh', 'bash ./Dirty-Pipe.sh', 'find / -type f -perm 0777')) {
    Invoke-WordPressGodzillaDecoy $dashDecoy $command
}

$dirtyPipeEvidence = [ordered]@{
    cve = 'CVE-2022-0847'
    reportedPath = '/var/www/html/wp-content/uploads/p3d/Dirty-Pipe.sh'
    referenceRepository = 'r1is/CVE-2022-0847'
    attemptsRepresented = 2
    gccObservedByReport = $false
    compiledExpObservedByReport = $false
    actualCompilerRun = $false
    actualExploitRun = $false
    passwdReadOrCopied = $false
    privilegeEscalated = $false
    result = 'unsuccessful in report; simulation records only negative evidence'
}
Write-WordPressGodzillaFile (Join-Path $paths.Evidence 'dirty-pipe-negative-record.json') ($dirtyPipeEvidence | ConvertTo-Json -Depth 6) 'failed privilege-escalation evidence'
Add-WordPressGodzillaTimeline 211 privilege-escalation 'Repeated Dirty Pipe attempts represented as failed, inert evidence' @{ exploitExecuted = $false; privilegeChanged = $false; technique = 'T1068' }

$webShell = Join-Path $paths.Upload '123.php'
$index = Join-Path $paths.WebRoot 'index.html'
if (-not (Test-Path $webShell)) { Write-WordPressGodzillaFile $webShell 'INERT GODZILLA WEB-SHELL CANARY.' 'inert web-shell filename canary' }
if (-not (Test-Path $index)) { Write-WordPressGodzillaFile $index '<html><body>INERT WORDPRESS HOME CANARY</body></html>' 'timestamp reference canary' }
$before = (Get-Item -LiteralPath $webShell).LastWriteTimeUtc
$reference = (Get-Item -LiteralPath $index).LastWriteTimeUtc
[IO.File]::SetLastWriteTimeUtc($webShell, $reference)
$after = (Get-Item -LiteralPath $webShell).LastWriteTimeUtc
Add-WordPressGodzillaManifest file $webShell timestomp-local-canary @{ originalUtc = $before.ToString('o'); referencePath = $index; referenceUtc = $reference.ToString('o'); newUtc = $after.ToString('o'); generatedArtifactOnly = $true }

$timestomp = [ordered]@{
    failedReportedCommand = 'sh -c ''sh -c "cd "/var/www/html/wp-content/uploads/p3d/";touch -d "2022-12-28 12:26:21" 123.php" 2>&1'''
    failedEffect = 'quoting reduced operation to touch -d 2022-12-28 and produced a missing-operand error'
    successfulReportedCommand = 'touch -r index.html 123.php'
    simulationMethod = 'SetLastWriteTimeUtc on generated canary only'
    originalUtc = $before.ToString('o')
    referenceUtc = $reference.ToString('o')
    resultingUtc = $after.ToString('o')
}
Write-WordPressGodzillaFile (Join-Path $paths.Evidence 'timestomp-evidence.json') ($timestomp | ConvertTo-Json -Depth 6) 'timestomp evidence'
Invoke-WordPressGodzillaDecoy $dashDecoy $timestomp.failedReportedCommand
Invoke-WordPressGodzillaDecoy $dashDecoy $timestomp.successfulReportedCommand
Add-WordPressGodzillaTimeline 278 defense-evasion 'Failed quoted touch command followed by reference-file timestomp represented on the generated canary' @{ realSystemFilesChanged = $false; technique = 'T1070.006' }

foreach ($command in @('whereis openvpn', 'where openvpn', 'id', 'whoami', 'cat /proc/1/cgroup', 'ifconfig', 'ip addr', 'curl 167.179.108.182')) {
    Invoke-WordPressGodzillaDecoy $dashDecoy $command
}
Invoke-WordPressGodzillaLoopback 80 '167.179.108.182 curl target' 'reported HTTP troubleshooting attempt'
Add-WordPressGodzillaTimeline 321 discovery 'Final troubleshooting commands and operator-IP shift represented' @{ reportedOperatorIp = '167.179.108.182'; remoteContact = $false }
Add-WordPressGodzillaTimeline 360 completion 'Activity ceased after approximately six hours; generated artifacts intentionally remain' @{ remediatedInReport = $true; cleanupRun = $false }
