#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ProxyEncryptSim-utilities.ps1";Assert-ProxyEncryptSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ProxyEncryptSim-Phase1-ProxyShell-WebShell.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ProxyEncryptSim-Phase2-Accounts-Tunnels-Credentials.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\ProxyEncryptSim-Phase3-BitLocker-DiskCryptor.ps1" -LabConfirmed:$LabConfirmed;$p=Get-ProxyEncryptPaths;Write-ProxyEncryptSummary $p;Write-Host "Scenario complete. Evidence remains at $($p.Root). Cleanup is separate."
