# 010 - BengalSEO MayaBot SEO Poisoning

Lab-safe PowerShell adversary emulation based on The DFIR Report's [BengalSEO Part 1: Anatomy of the Operation](https://thedfirreport.com/2026/08/24/bengalseo-part-1-anatomy-of-the-operation/) (August 24, 2026).

## Report fidelity

This report documents a scam and delivery ecosystem, not a ransomware intrusion. The scenario therefore stops at the behavior the report supports:

1. A local Bitdefender-themed SEO lure records Bing-referrer, keyword-stuffing, site-verification, and Matomo artifacts.
2. A Base64URL tracking token represents the TDS redirect parameter, followed by a CAPTCHA allow verdict and an HTTP 302-style handoff record.
3. IOC-bearing `curl.exe` command lines represent Matomo and redirector traffic. Every request uses `--resolve <IOC>:443:127.0.0.1` and `--noproxy *`.
4. A ZIP named `Bitdefender_Central_Setup.zip` contains `BitdefenderSupportInstaller.exe.js`, matching the reported JavaScript-as-EXE masquerade.
5. The extracted script is genuinely launched by `wscript.exe`, but it only creates canary files and one non-persistent `HKCU\Software\BengalSEOSim` value.
6. MayaBot C2 domain strings are retained in session metadata and loopback-only command lines. An alternate local phone-scam page uses a reserved fictional `555-0100` number.

The report does not disclose MayaBot's full host behavior in Part 1. This scenario does not invent credential theft, discovery, lateral movement, defense evasion, or ransomware phases.

## Safety controls

- Requires the single explicit `-LabConfirmed` switch; no environment variable is needed.
- Refuses Windows systems with `Win32_ComputerSystem.DomainRole` 4 or 5, or an `NTDS` service.
- Downloads nothing and contains no malware.
- Never resolves or connects to a report IOC: hostname-bearing requests are pinned to `127.0.0.1`, use proxy bypass, and time out in two seconds.
- Does not disable security controls, collect credentials, access LSASS, propagate, change GPO/SYSVOL, clear logs, touch shadow copies, or encrypt data.
- Leaves evidence in place. Cleanup is a separate, explicit script with fixed target checks and `-WhatIf` support.

## Run

From Windows PowerShell 5.1 or later:

```powershell
.\BengalSEOSim-Complete.ps1 -LabConfirmed
```

Add `-LaunchVisibleBrowser` to open the local lure in Microsoft Edge. The lure contains no remote resource references.

Artifacts are written beneath:

- `%PUBLIC%\BengalSEOSim`
- `%LOCALAPPDATA%\MayaCache`
- `%USERPROFILE%\Downloads\Bitdefender_Central_Setup*`
- `HKCU\Software\BengalSEOSim`

The runtime `artifact-manifest.jsonl` records paths, actions, hashes, and loopback network safeguards.

## Cleanup

Preview, then perform the separate deterministic cleanup:

```powershell
.\Cleanup-BengalSEOSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-BengalSEOSim.ps1 -LabConfirmed
```

## Scenario ATT&CK mapping

| Observed or represented behavior | Technique |
|---|---|
| Register and rotate campaign domains | T1583.001 - Acquire Infrastructure: Domains |
| Abuse hosted services for lure pages | T1583.006 - Acquire Infrastructure: Web Services |
| Stage a JavaScript payload in a ZIP | T1608.001 - Stage Capabilities: Upload Malware |
| SEO lure and malicious link target | T1608.005 - Stage Capabilities: Link Target |
| User opens a masquerading script | T1204.002 - User Execution: Malicious File |
| JavaScript runs through `wscript.exe` | T1059.007 - Command and Scripting Interpreter: JavaScript/JScript |
| `*.exe.js` double-extension disguise | T1036.007 - Masquerading: Double File Extension |
| ZIP/payload transfer representation | T1105 - Ingress Tool Transfer |
| Matomo/TDS/MayaBot web traffic representation | T1071.001 - Application Layer Protocol: Web Protocols |

## Investigation cues

- Reconstruct `powershell.exe -> curl.exe` and `powershell.exe -> wscript.exe` process chains.
- Compare ZIP, extracted JavaScript, cache markers, registry values, Prefetch, Amcache, MFT, USN Journal, and browser artifacts.
- Inspect `loopback-network-command-lines.log` and confirm every IOC was pinned to loopback.
- Use [IOC-METADATA.md](IOC-METADATA.md) as offline investigation metadata only.
- Do not clean up until acquisition and timeline work are complete.
