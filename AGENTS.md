# DFIR adversary-emulation workspace

## Standing workflow

- When the user provides a DFIR, incident-response, threat-intelligence, or intrusion-report URL, read the complete report before creating artifacts.
- Create a new, report-specific PowerShell adversary-emulation script and a concise operator guide that map the observed intrusion phases and relevant MITRE ATT&CK techniques.
- Favor realistic filenames, process ancestry, command-line telemetry, persistence artifacts, staging paths, and cleanup records so the scenario is useful for forensic investigation.
- Keep every scenario lab-safe: do not retrieve or embed live malware, contact real command-and-control infrastructure, collect real credentials, access LSASS/NTDS secrets, propagate to remote systems, modify real GPO/SYSVOL, impair security controls, clear logs, delete shadow copies, or encrypt user data.
- Replace dangerous actions with clearly documented, inert equivalents confined to generated canary data and loopback-only network attempts. Include an explicit lab confirmation gate, domain-controller refusal, a manifest, and deterministic cleanup.
- Preserve report IOCs as investigation metadata, but never connect to them directly. If process/network telemetry includes an IOC hostname, force the connection to loopback and disable proxy use.
- Leave generated artifacts in place after execution for investigation; make cleanup a separate explicit action.
