# 077 - Bazar and Cobalt Strike, but No Ryuk

Lab-safe companion to The DFIR Report's [Bazar, No Ryuk?](https://thedfirreport.com/2021/01/31/bazar-no-ryuk/) (internal case 1013). It preserves the DocuSign Excel 4.0 macro chain, Bazar Run-key persistence, quiet day-one, `.bazar` DNS and Nltest on day two, infrastructure contact on day three, and day-four Cobalt execution, injection, discovery, credential markers, lateral movement, domain-controller toolkit, `Get-DataInfo`, and abrupt disconnect before the assessed Ryuk objective.

## Run

Use an elevated PowerShell prompt on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\BazarNoRyukSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\BazarNoRyukSim`; cleanup is separate:

```powershell
.\Cleanup-BazarNoRyukSim.ps1 -LabConfirmed
```

## Exercise map

| Report period | Script | Evidence represented |
|---|---|---|
| Days 1-3 | `BazarNoRyukSim-Phase1-Bazar-Dwell.ps1` | XLSM → `ResizeFormToFit.exe` → `M1E1626.exe`, Run-key marker, `.bazar` DNS, Nltest, Cobalt ping, and quiet dwell |
| Day 4 | `BazarNoRyukSim-Phase2-Cobalt-Domain.ps1` | Cobalt DLL/rundll32, WerFault/dllhost injection markers, Get-System pipe, PowerSploit discovery, LSASS marker, pass-the-hash, SMB/service, PowerShell service, RDP, and generated DC compromise |
| Day 4 + ~1 hour | `BazarNoRyukSim-Phase3-DataInfo-Cutoff.ps1` | AdFind, `7z.exe`, `comps.txt`, `Get-DataInfo.ps1`, `netscan.exe`, `start.bat`, then access termination and explicit no-Ryuk outcome |

Investigators can pivot from `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl` into reported-vs-actual process arguments, `days1-3.json`, `getsystem-pipe.json`, `discovery.json`, `credential-movement.json`, the generated DC host tree, `adfind-getdatainfo.json`, and `access-ended-no-ryuk.json`. `IOC-METADATA.json` retains the report's infrastructure, hashes, TLS fingerprints, detections, and YARA names.

All executables are copied, signed `cmd.exe` decoys invoked only with a fixed benign `echo`. Scripts and DLLs are inert text. Network attempts are forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. The scenario performs no malware retrieval, macro execution, registry or named-pipe creation, injection, discovery, LDAP/LSASS/credential access, pass-the-hash, SMB/RDP/service movement, real DC access, collection, compression, exfiltration, payload deletion, log clearing, or ransomware impact. Real domain controllers are refused.

The report's ATT&CK mappings are T1566.002, T1204, T1059, T1482, T1550.002, T1021.001, T1021.002, T1087.002, T1069.002, T1082, T1124, T1518.001, T1518, T1218.011, T1071.004, T1043, T1569.002, T1059.001, and T1547.001.
