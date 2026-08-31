# 057 - Cobalt Strike, a Defender's Guide - Part 2

Lab-safe PowerShell companion to The DFIR Report's [Cobalt Strike, a Defender's Guide - Part 2](https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/).

This is a defensive synthetic telemetry lab, not a reconstruction of one intrusion. It creates an annotated malleable-profile canary, all 17 published server/URI pairs, a domain-fronting relationship, SOCKS port 8888/RDP type-3 evidence, 148 generated DNS task records, `my_pipes` SMB parent/child markers, a one-hour synthetic beacon series, a RITA-like score, and JA3/JA3S/JARM/Arkime reference evidence.

No Cobalt Strike payload or team server is created. No CDN, SOCKS listener, RDP session, DNS query, SMB connection, named pipe, remote scan, JARM probe, real PCAP, IOC contact, or data transfer occurs. The only socket attempts terminate on `127.0.0.1`, with proxy use disabled and zero bytes transferred.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\CSNetGuideSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\CSNetGuideSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
