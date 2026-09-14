# 087 - Dridex, Empire, AdFind, and PsExec domain propagation

Lab-safe companion to The DFIR Report's [Dridex - From Word to Domain Dominance](https://thedfirreport.com/2020/08/03/dridex-from-word-to-domain-dominance/) (internal case 1002). The live article is currently broken, so this scenario was built only after reading the complete original September 29, 2020 Internet Archive capture. It preserves the Word/Dridex entry, `Zvhlxdonjwfvei` task and Run key, `rvhz1.dll`, initial Dridex C2, `J10B9.cmd`, Empire stage, AdFind download/recon/exfiltration, Whoami/Net discovery, open-directory tooling, WMI attempts, Defender blocks, renamed `pse.exe`, PSEXESVC/ADMIN$ mechanics, `ufo.exe` propagation, failed credential dumping, and continuing Dridex beacons.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\DridexDomainSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\DridexDomainSim`; cleanup is separate with `.\Cleanup-DridexDomainSim.ps1 -LabConfirmed`.

Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then inspect persistence, Empire/AdFind, exfiltration, open-directory inventory, propagation, synthetic PsExec log, and objective outcome. The generated eight-hour axis preserves ordering because the report states only relative timing.

All executable/DLL names are signed `cmd.exe` decoys; executable stand-ins run only fixed benign `echo`, DLLs are never loaded, and the Word/PHP artifacts are inert. All endpoints are forced to `127.0.0.1`, no proxy is used, and zero bytes transfer. No macro, malware, download, task/registry change, WMI, Defender change, SMB/PsExec/service, remote execution, LSASS access, credential collection, or ransomware action occurs. Real DCs are refused. The scenario explicitly does not simulate the report's hypothesized ransomware end state.

The report uses the Unified Kill Chain rather than ATT&CK; observed behavior maps to T1566.001, T1204.002, T1053.005, T1547.001, T1218.011, T1059.001, T1071.001, T1018, T1482, T1087.002, T1041, T1047, T1021.002, T1569.002, T1105, and T1003.
