# Forensic Artifact Repository

Lab-only attack simulation scripts built from real DFIR incident writeups. Each simulation reproduces a documented attack chain on a disposable VM so a forensic analyst can practice artifact extraction and investigation.

## Workflow

1. User supplies a URL to a real-world forensic/IR investigation writeup.
2. Read and fully understand the attack chain: initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, impact.
3. Build a simulation script (or phase-split script set) that reproduces it end-to-end on a clean machine.
4. Target OS (Windows PowerShell or Linux bash) is chosen per-investigation to match the original case — not fixed.
5. Prefer real published PoCs/tools where available (e.g. actual Mimikatz, real C2 beacon configs/domains from the report) over safe stand-ins, to maximize artifact fidelity for detection engineering (YARA/SIGMA/Suricata/Snort/Zeek).
6. If report details are missing, synthesize logically consistent artifacts based on the malware family's known behavior — note where this was done.
7. Scripts must require explicit confirmation before executing and assume administrative/root privileges in an isolated, disposable lab VM (never a networked or production machine).

## Full task prompt template

See `DFIR reports script creation Claude PROMPT.txt` — the canonical brief used to spin up a new simulation: full attack chain coverage, authentic artifacts (executables matching YARA sigs, event logs triggering the same SIGMA rules, network traffic matching Suricata/Snort/Zeek rules, identical registry changes), real external C2 addresses (not localhost), actual system changes (registry, scheduled tasks, services, filesystem, shell/command history, event logs, process trees), and simulated anti-forensic techniques.

## Repo conventions

- Each incident gets a numbered folder or file: `NNN-ShortIncidentName` (e.g. `002-BlackSuit_Simulation.ps1`, `003-Buzzing on Christmas Eve Trigona Ransomware in 3 Hours/`).
- For multi-stage attacks, split into phase scripts following ATT&CK-ish tactic naming, e.g.:
  - `<Name>-Phase1-InitialAccess.ps1`
  - `<Name>-Phase2-ExecutionPrivEsc.ps1`
  - `<Name>-Phase3-DefenseEvasion.ps1`
  - `<Name>-Phase4-CredentialAccess.ps1`
  - `<Name>-Phase5-LateralMovement.ps1`
  - `<Name>-Phase6-Collection.ps1`
  - `<Name>-Phase7-Impact.ps1`
  - `<name>-utilities.ps1` — shared helper functions (logging, artifact helpers) sourced by phase scripts.
  - `<Name>-Complete.ps1` — single combined script running all phases in order, for cases where phase-by-phase isn't needed.
- `kape command.bat` — reference KAPE invocation used for post-simulation artifact collection/triage.

## Safety

All scripts are destructive/system-modifying by design (registry, scheduled tasks, services, persistence, simulated ransomware impact). Never run outside an isolated, snapshot-able VM. Always keep prompts for explicit confirmation before the destructive/impact phase executes.
