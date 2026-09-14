# 027 - WordPress 3DPrint Lite, Godzilla, and Dirty Pipe

Lab-safe PowerShell reconstruction of The DFIR Report's [WordPress Plugin Exploit Leads to Godzilla Web Shell, Discovery & New CVE](https://thedfirreport.com/2024/03/04/threat-brief-wordpress-exploit-leads-to-godzilla-web-shell-discovery-new-cve/) (March 4, 2024).

The report describes exploitation of the 3DPrint Lite upload handler (CVE-2021-4436), a Godzilla PHP web shell, extensive Linux discovery, LinEnum, failed Dirty Pipe exploitation, and timestomping over roughly six hours. Because the original host was Linux, this scenario creates a synthetic Linux/WordPress tree and Apache/process evidence on a Windows lab endpoint.

## Evidence generated

- Synthetic `/var/www/html` and Apache log hierarchy beneath `%PUBLIC%\WordPressGodzillaSim\linux-root`, including the vulnerable endpoint, both source IPs, both user agents, and the report's shift in operator IP.
- An actual `123.php` filename containing only inert plain text—no PHP opening tag, decoder, session handling, input processing, or `eval`—plus Godzilla password, payload-name, and key fingerprints as JSON metadata.
- Apache (`www-data`, UID 33) to `/usr/bin/dash` ancestry mapped to a signed `cmd.exe` copy that only echoes safely escaped reported command lines.
- Inert `1.sh` and `Dirty-Pipe.sh` filename canaries with negative records for credential access, MySQL authentication, compilation, `/etc/passwd` manipulation, and privilege escalation.
- The failed quoted `touch` command and successful `touch -r index.html 123.php` represented by changing only the generated canary's timestamp and recording before/reference/after values.
- A relative six-hour timeline, runtime artifact manifest, and loopback-only markers for the reported IPs.

## Safety boundaries

The scenario requires explicit lab confirmation and refuses domain controllers. It does not contain or retrieve malware, run PHP or a Linux shell, execute LinEnum or Dirty Pipe, compile exploit code, read credentials, contact reported infrastructure, authenticate to MySQL, escalate privileges, or remove artifacts. Reported commands and indicators are evidence strings; the only network destination is `127.0.0.1`, with no proxy and zero transferred bytes.

## Run and cleanup

```powershell
.\WordPressGodzillaSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\WordPressGodzillaSim` for forensic examination.

```powershell
.\Cleanup-WordPressGodzillaSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-WordPressGodzillaSim.ps1 -LabConfirmed
```

ATT&CK mappings and all indicators published in the public report are recorded in [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json). ATT&CK entries not explicitly labeled by the report are identified as derived from its observed commands.
