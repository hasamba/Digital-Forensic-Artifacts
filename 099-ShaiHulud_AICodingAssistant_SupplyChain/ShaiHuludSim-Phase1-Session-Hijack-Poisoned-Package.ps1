#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShaiHuludSim-utilities.ps1";Assert-ShSafety -LabConfirmed:$LabConfirmed;$p=Initialize-ShEnvironment
# A compromised SaaS provider is used to hijack an ACTIVE AI coding-assistant session on a developer workstation.
Invoke-ShLoopback 443 'compromised SaaS provider -> hijack of active AI coding-assistant session' 'initial access marker'
$dev='C$\Users\devuser'
$devRoot=Join-Path $p.Repos 'DEV-WORKSTATION'
# The assistant, trusted as an interpreter, recommends installing an attacker-poisoned external package. Represent the assistant transcript/session artifacts.
Write-ShFile (Join-Path $devRoot "$dev\.ai-assistant\session-history.log") @"
[assistant session - GENERATED CANARY transcript]
user: my build fails resolving a JSON helper, what should I add?
assistant: You can add the helper package 'json-fastparse' - run: pip install json-fastparse
  (NOTE: this recommendation was injected by an attacker who hijacked the active session; the package is poisoned.)
user: ok, installing
--------------------------------------------------------------------
GENERATED FORENSIC CANARY - no assistant was run and no package was installed.
"@ 'hijacked AI coding-assistant session transcript canary'
Write-ShJson (Join-Path $devRoot "$dev\.ai-assistant\config.json") ([ordered]@{reportedTrustModel='assistant treated as trusted interpreter';reportedHijack='active session hijacked via compromised SaaS provider';reportedRecommendedPackage='json-fastparse (poisoned)';humanApprovalRequired=$false;sessionHijacked=$false}) assistant-session
# Developer accepts the recommendation: poisoned PyPI package installs an infostealer.
$pip=Join-Path $p.Payloads 'pip.exe';New-ShDecoy $pip 'python package manager command stand-in'
Invoke-ShDecoy $pip 'pip install json-fastparse (attacker-poisoned PyPI package; AI-recommended)' 'AI coding assistant (hijacked session)'
$stealer=Join-Path $devRoot "$dev\AppData\Local\Temp\jsonfastparse\setup_helper.exe"
New-ShDecoy $stealer 'infostealer delivered via poisoned PyPI package json-fastparse'
Invoke-ShDecoy $stealer 'setup_helper.exe (infostealer; harvests local dev secrets and browser/session tokens)' 'python.exe (poisoned package post-install)'
Write-ShFile (Join-Path $devRoot "$dev\AppData\Local\Temp\jsonfastparse\PKG-INFO") "Name: json-fastparse`nVersion: 9.9.9`nSummary: GENERATED CANARY - poisoned-package metadata stand-in; nothing was installed.`n" 'poisoned package metadata canary'
Write-ShJson (Join-Path $p.Evidence 'poisoned-dependency.json') ([ordered]@{reportedPackage='json-fastparse';reportedRegistry='PyPI';reportedDelivery='AI coding assistant recommendation in a hijacked session';reportedPayload='infostealer';verificationHooksPresent=$false;checksumAllowlistEnforced=$false;packagesInstalled=0;infostealerExecuted=$false}) supply-chain
Add-ShTimeline 0 initial-access 'Compromised SaaS provider hijacks active AI coding-assistant session - represented' @{sessionHijacked=0}
Add-ShTimeline 8 execution 'AI assistant recommends poisoned PyPI package json-fastparse; developer accepts - represented' @{packagesInstalled=0}
Add-ShTimeline 12 execution 'Poisoned package installs infostealer (setup_helper.exe) - represented' @{infostealerExecuted=0}
