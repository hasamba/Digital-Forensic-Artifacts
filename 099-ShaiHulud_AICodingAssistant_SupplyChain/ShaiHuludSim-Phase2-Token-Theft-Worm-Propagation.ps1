#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\ShaiHuludSim-utilities.ps1";Assert-ShSafety -LabConfirmed:$LabConfirmed;$p=Initialize-ShEnvironment
# The attacker uses the developer's active session to harvest GitHub OAuth tokens. All values are canaries.
Write-ShFile (Join-Path $p.Creds 'github-oauth-tokens.txt') @"
# GENERATED CANARY - harvested credential store representation. No real token was read or collected.
github.com  oauth_token=[NOT COLLECTED]
github.com  pat=[NOT COLLECTED]
npm_registry  authToken=[NOT COLLECTED]
"@ 'harvested OAuth token canary (no real tokens)'
Write-ShJson (Join-Path $p.Evidence 'token-harvest.json') ([ordered]@{reportedTargets=@('GitHub OAuth tokens','Personal Access Tokens','registry auth tokens');localCredentialsIsolated=$false;tokensCollected=0;tokenValuesRead=$false}) credential-access
# Deploy the self-propagating Shai-Hulud worm across internal repositories. Reported ~100 repos; we generate a representative set of canary repo trees.
$reportedRepoCount=100;$generated=12
$wormWorkflow=@"
# GENERATED CANARY - represents the Shai-Hulud worm's dropped CI workflow. It is inert text and runs nothing.
name: shai-hulud
on: [push]
jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - run: echo "SHAIHULUD-LAB-CANARY - repository secrets would be harvested and exfiltrated here (no action taken)"
"@
for($i=1;$i-le$generated;$i++){
 $repo=Join-Path $p.Repos ('internal-repo-{0:D3}' -f $i)
 New-Item (Join-Path $repo '.github\workflows') -ItemType Directory -Force|Out-Null
 Write-ShFile (Join-Path $repo '.github\workflows\shai-hulud-workflow.yml') $wormWorkflow 'worm-dropped CI workflow canary'
 Write-ShFile (Join-Path $repo 'data.json') '{"note":"GENERATED CANARY - Shai-Hulud worm marker; no secrets collected."}' 'worm marker canary'
 Write-ShFile (Join-Path $repo 'stolen-secrets.canary.json') '{"repoSecrets":"[NOT COLLECTED]","npmTokens":"[NOT COLLECTED]","cloudKeys":"[NOT COLLECTED]"}' 'repository-secret theft canary (no real secrets)'
 Write-ShFile (Join-Path $repo 'src\product.py') "# GENERATED CANARY source file for internal-repo-$('{0:D3}' -f $i); represents proprietary source that would be exfiltrated.`nprint('lab canary')`n" 'proprietary source canary'
}
# Programmatic exfiltration of repository secrets and proprietary source to attacker infrastructure - represented by loopback, zero bytes.
Invoke-ShLoopback 443 'attacker-controlled repository (secrets + proprietary source exfiltration)' 'worm exfiltration marker'
Write-ShJson (Join-Path $p.Evidence 'worm-propagation.json') ([ordered]@{worm='Shai-Hulud';reportedRepositoriesInfected=$reportedRepoCount;generatedCanaryRepositories=$generated;reportedActions=@('self-propagation across internal repos','repository-secret theft','proprietary source-code exfiltration');repositoriesContacted=0;secretsCollected=0;sourceExfiltrated=0;bytesTransferred=0}) worm
Add-ShTimeline 20 credential-access 'GitHub OAuth tokens harvested via active session - represented' @{tokensCollected=0}
Add-ShTimeline 28 lateral-movement ('Shai-Hulud worm propagated across ~{0} internal repositories - represented ({1} canary trees)' -f $reportedRepoCount,$generated) @{repositoriesInfected=0}
Add-ShTimeline 35 exfiltration 'Repository secrets and proprietary source exfiltrated to attacker repo - represented' @{sourceExfiltrated=0;bytesTransferred=0}
