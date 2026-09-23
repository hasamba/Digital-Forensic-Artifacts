# 099 - Shai-Hulud worm via a hijacked AI coding-assistant session

Lab-safe companion to Mandiant / Google Cloud's [AI Risk and Resilience 2026](https://cloud.google.com/security/resources/ai-risk-and-resilience-2026) special report (September 2026), reproducing **Case Study 1: "Weaponizing active developer AI sessions to deploy the Shai-Hulud worm"** end to end, plus the report's described downstream namespace-poisoning secondary infection.

Attack chain represented:

1. **Session hijack** - a compromised SaaS provider is used to hijack an *active* AI coding-assistant session on a developer workstation. The assistant, trusted as an interpreter, recommends installing an attacker-poisoned external package.
2. **Poisoned dependency** - the developer accepts, and a poisoned PyPI package (`json-fastparse`) installs an infostealer.
3. **Token harvest** - the attacker uses the developer's active session to harvest GitHub OAuth tokens.
4. **Worm propagation** - the self-propagating Shai-Hulud worm spreads across ~100 internal repositories, dropping a CI workflow, stealing repository secrets, and exfiltrating proprietary source code.
5. **Namespace poisoning** - the actor poisons a package inside the organization's official namespace (`@acme-internal/utils`), causing a downstream secondary infection when another employee pulls the compromised version.

Run elevated with the standard lab gate via `.\ShaiHuludSim-Complete.ps1 -LabConfirmed`; artifacts remain under `%PUBLIC%\ShaiHuludSim`, and cleanup is separate (`.\Cleanup-ShaiHuludSim.ps1 -LabConfirmed`). Executable-looking artifacts are fixed-echo signed `cmd.exe` decoys. Twelve canary repository trees represent the reported ~100 infected repos. **Every credential is a `[NOT COLLECTED]` canary, no real package is installed, no token/secret/source is ever read or collected, no repository is contacted, and nothing is exfiltrated** - all network actions are `127.0.0.1` with zero bytes. Real DCs are refused.

The report's defensive controls this scenario is built to exercise (for detection engineering): IDE/CLI verification hooks validating AI-recommended dependencies against cryptographic checksums/allowlists, local credential isolation from extensions, workstation egress restricted through internal repositories, and continuous secrets scanning across workspaces.

Behavior maps to T1195.001/T1195.002 (supply-chain compromise of dependencies), T1059 (assistant-driven execution), T1528 (steal application access token), T1552.001 (credentials in files), T1567/T1041 (exfiltration to attacker repo), and T1080-style tainted internal shared content (namespace poisoning).
