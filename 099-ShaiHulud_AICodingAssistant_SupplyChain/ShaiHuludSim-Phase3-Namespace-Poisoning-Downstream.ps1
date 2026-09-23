#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShaiHuludSim-utilities.ps1";Assert-ShSafety -LabConfirmed:$LabConfirmed;$p=Initialize-ShEnvironment
# The actor poisons a package inside the organization's OFFICIAL namespace, leading to a downstream secondary infection.
$nsRepo=Join-Path $p.Repos 'internal-namespace-acme-utils'
Write-ShFile (Join-Path $nsRepo 'package.json') @"
{
  "name": "@acme-internal/utils",
  "version": "4.2.1",
  "description": "GENERATED CANARY - represents a package poisoned inside the org's official namespace.",
  "scripts": {
    "postinstall": "echo SHAIHULUD-LAB-CANARY (poisoned postinstall; no action taken)"
  }
}
"@ 'poisoned internal-namespace package manifest canary'
Write-ShFile (Join-Path $nsRepo 'index.js') "// GENERATED CANARY - poisoned trusted-namespace package. Inert; runs nothing.`nmodule.exports = { note: 'lab canary' };`n" 'poisoned namespace package canary'
# Secondary victim: another employee pulls the compromised version, re-triggering the infection chain.
$victim2=Join-Path $p.Repos 'DEV-WORKSTATION-2'
$npm=Join-Path $p.Payloads 'npm.exe';New-ShDecoy $npm 'node package manager command stand-in'
Invoke-ShDecoy $npm 'npm install @acme-internal/utils@4.2.1 (pulls the poisoned trusted-namespace package)' 'second developer workstation'
Write-ShFile (Join-Path $victim2 'C$\Users\devuser2\project\node_modules\@acme-internal\utils\INFECTION.canary') "GENERATED CANARY - downstream secondary infection from the poisoned official-namespace package. No code executed.`n" 'downstream secondary infection canary'
Write-ShJson (Join-Path $p.Evidence 'namespace-poisoning.json') ([ordered]@{reportedPoisonedPackage='@acme-internal/utils (official namespace)';reportedMechanism='package poisoned inside org namespace; pulled by another employee';reportedResult='downstream secondary infection';repositoryMonitoringPresent=$false;multiPartyApprovalPresent=$false;packagesPoisoned=0;secondaryInfections=0;codeExecuted=$false}) supply-chain
Write-ShJson (Join-Path $p.Evidence 'scenario-negative.json') ([ordered]@{sessionsHijacked=0;packagesInstalled=0;infostealerExecuted=$false;tokensCollected=0;tokenValuesRead=$false;repositoriesInfected=0;repositoriesContacted=0;secretsCollected=0;sourceExfiltrated=0;packagesPoisoned=0;secondaryInfections=0;codeExecuted=$false;externalConnections=0;bytesTransferred=0}) safety
Add-ShTimeline 45 impact 'Package poisoned inside the org official namespace (@acme-internal/utils) - represented' @{packagesPoisoned=0}
Add-ShTimeline 52 impact 'Second employee pulls compromised version -> downstream secondary infection - represented' @{secondaryInfections=0}
