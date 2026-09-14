# 072 - Conti Ransomware

Lab-safe companion to The DFIR Report's [Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/) (case 3584). It preserves the moderate-confidence ZIP/JavaScript IcedID origin, over-two-day dormancy, 2.5-hour Cobalt hands-on window, GetSystem/DC movement and scanning, 15-minute pause before PsExec fan-out, proxied RDP, `nuuser`, Defender GPO/service impairment, runonce-to-LSASS and overpass-the-hash, then in-memory Conti at 2 days 11 hours.

Executables are signed `cmd.exe` decoys with fixed benign arguments. No malware, injection, credential/LSASS access, account/GPO/SYSVOL/service/registry/firewall action, authentication, scan, SMB/PsExec/RDP/proxy, external C2, user-data encryption, or host impairment occurs. DC paths and impact files are generated canaries only; real DCs are refused.

```powershell
.\IcedContiSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\IcedContiSim`; run `.\Cleanup-IcedContiSim.ps1 -LabConfirmed` separately.
