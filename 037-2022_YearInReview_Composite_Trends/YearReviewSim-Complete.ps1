#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\YearReviewSim-utilities.ps1";Assert-YearReviewSafety -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\YearReviewSim-Phase1-Access-Execution.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\YearReviewSim-Phase2-Persistence-Credential-Discovery.ps1" -LabConfirmed:$LabConfirmed;& "$PSScriptRoot\YearReviewSim-Phase3-Movement-Outcome.ps1" -LabConfirmed:$LabConfirmed;$p=Get-YearReviewPaths;Write-YearReviewSummary $p;Write-Host "Composite complete. Evidence remains at $($p.Root). Cleanup is separate."
