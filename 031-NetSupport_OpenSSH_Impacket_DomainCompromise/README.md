# 031 - NetSupport, OpenSSH, Impacket, and Domain Compromise

Lab-safe PowerShell reconstruction of The DFIR Report's [NetSupport Intrusion Results in Domain Compromise](https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/) (October 30, 2023).

The scripts preserve the eight-day sequence: JavaScript/PowerShell NetSupport deployment and Run-key evidence; day-five discovery, OpenSSH reverse tunneling, Impacket atexec/wmiexec, CAB transfer, secondary NetSupport, WMI and RDP; then day-eight NTDS/LSASS activity, PingCastle, Netscan, event/document staging, attempted accounts, failed Nim tooling, and eviction.

The explicit lab gate and domain-controller refusal are mandatory. No RMM or malware runs, no registry/task/service/account/firewall/Defender changes occur, no SSH tunnel opens, no remote host or SYSVOL is queried, no WMI/RDP/SMB movement occurs, no NTDS/LSASS/real event/document is read, and nothing is exfiltrated. All commands are escaped echo telemetry; all connections are literal loopback with zero bytes.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\NetSupportDomainSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\NetSupportDomainSim`; cleanup is separate:

```powershell
.\Cleanup-NetSupportDomainSim.ps1 -LabConfirmed -WhatIf
.\Cleanup-NetSupportDomainSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
