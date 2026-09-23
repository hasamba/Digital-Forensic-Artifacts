#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\SettraSim-utilities.ps1";Assert-SxSafety -LabConfirmed:$LabConfirmed;$p=Initialize-SxEnvironment
# BYOVD observed in the September incident only (gdrv.sys - Gigabyte driver), typically dropped to impair onboard security tooling. July incident showed no BYOVD.
$sept=Join-Path $p.Hosts 'SEPT-MANUFACTURING'
$drv=Join-Path $sept 'C$\Windows\Temp\gdrv.sys'
New-SxDecoy $drv 'BYOVD vulnerable driver gdrv.sys (September incident) - stand-in, not a real driver and never loaded'
$sc=Join-Path $p.Payloads 'sc.exe';New-SxDecoy $sc 'service-control command stand-in'
Invoke-SxDecoy $sc 'sc.exe create gdrv type= kernel binPath= C:\Windows\Temp\gdrv.sys ; sc.exe start gdrv (BYOVD load to impair security tooling)' 'ransomware / manual RMM session'
Write-SxJson (Join-Path $p.Registry 'gdrv-BYOVD-service.json') ([ordered]@{reportedDriver='gdrv.sys';reportedTechnique='Bring Your Own Vulnerable Driver (BYOVD)';reportedIntent='impair onboard security tooling / crash AV-related services';observedIncident='September';notObservedIncident='July';serviceCreated=$false;driverLoaded=$false;securityToolsImpaired=0}) byovd
Write-SxJson (Join-Path $p.Evidence 'defense-evasion.json') ([ordered]@{reportedByovdFile='gdrv.sys';reportedByovdPath='observed in September incident';securityControlsChanged=0;driversLoaded=0;servicesCrashed=0;antivirusDisabled=$false}) defense-evasion
Add-SxTimeline 15 defense-evasion 'September: BYOVD (gdrv.sys) staged to impair security tooling - represented' @{driverLoaded=0;securityToolsImpaired=0}
