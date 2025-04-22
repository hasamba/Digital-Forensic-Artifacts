DFIR Report: https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/

Claude (Sonnet 3.7) Prompt:
```
Create a full-fidelity forensic simulation script for the [INSERT THREAT NAME] attack detailed in [INSERT REPORT SOURCE/URL]. The script must:

1. Simulate the COMPLETE attack chain including initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, and impact phases

2. Generate AUTHENTIC forensic artifacts that would trigger the same detection rules as the original malware:
   - Executables that match YARA signatures of the original malware
   - Event logs that trigger the same SIGMA rules
   - Network traffic that would be detected by Suricata/Snort/Zeek rules
   - Registry modifications identical to the malware

3. Include realistic C2 communications to external domains/IPs mentioned in the report

4. Create actual system changes:
   - Registry modifications
   - Scheduled tasks
   - Services
   - File system artifacts
   - PowerShell command history
   - Event log entries
   - Process tree sequences

5. Simulate anti-forensic techniques used by the attackers

This will run in an isolated lab environment with VM snapshots, so don't worry about system damage - maximize realism. The script should follow the exact techniques, tactics, and procedures in the report to create a high-fidelity training environment for incident responders and forensic analysts.

Include external C2 addresses from the report rather than localhost to ensure network traffic analysis is realistic. If any elements are missing from the report, synthesize logical artifacts based on the malware family's known behaviors.

The script should be designed to be run with administrative privileges and require explicit confirmation before executing.
```
