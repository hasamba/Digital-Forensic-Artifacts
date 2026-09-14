# 028 - Gootloader, Cobalt Strike, SystemBC, and Domain Control

Lab-safe PowerShell reconstruction of The DFIR Report's [SEO Poisoning to Domain Control: The Gootloader Saga Continues](https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/) (February 26, 2024).

It follows the SEO-poisoned “Implied Employment Agreement” lure, Gootloader persistence and registry stages, nine-hour delay to Cobalt Strike, discovery and attempted remote deployment, SystemBC-assisted RDP, domain-controller and backup-server activity, five-hour lull, interactive document review, and eviction.

## Evidence generated

- Realistic lure, MOTW, JavaScript, scheduled-task, process-chain, virtual-registry, and rotating-endpoint records with all published hashes kept as metadata.
- Cobalt HTTPS/SMB configuration, watermark, JA3/JA3S, pipes, discovery strings, injection and LSASS negative records, Defender event 1117, and synthetic service/SMB/WMI evidence.
- Inert `s5.ps1`, `socks_powershell` metadata, loopback-only SystemBC traffic, attacker hostnames, and RDP/WinRM event replicas.
- Generated DC, backup, password-share, contract, `payload.txt`, and Advanced IP Scanner canaries; no real network or data source is queried.

## Safety boundaries

The explicit lab gate and domain-controller refusal are mandatory. The scenario never registers a task or run key, writes the registry, loads malware, injects a process, accesses LSASS or credentials, changes Defender/firewall/RDP settings, creates a service, queries AD or shares, moves remotely, scans a network, tunnels SOCKS/RDP, or exfiltrates data. Reported commands are escaped echo-only strings run by signed `cmd.exe` copies; all socket attempts use `127.0.0.1` and transfer zero bytes.

```powershell
.\GootSagaSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\GootloaderSagaSim`. Cleanup is explicit and separately gated:

```powershell
.\Cleanup-GootSagaSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-GootSagaSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
