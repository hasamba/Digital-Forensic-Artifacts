# 079 - Trickbot, Cobalt Strike, NTDS, and Overpass-the-Hash

Lab-safe companion to The DFIR Report's [Trickbot Still Alive and Well](https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/) (internal case 1012). It preserves the unknown-but-assessed email delivery, manual Trickbot execution, wermgr injection, two Cobalt payloads, GetSystem, LSASS and NTDS IFM markers, AdFind/Net/Nltest/BloodHound/PowerView discovery, registry PowerShell/service movement, SMB/WMI/ADMIN$ movement, overpass-the-hash, backup-server pivot, and removal before the assessed Ryuk objective.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\TrickAliveSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\TrickAliveSim`; cleanup is separate with `.\Cleanup-TrickAliveSim.ps1 -LabConfirmed`.

The three phases cover Trickbot/Cobalt execution, credential and domain discovery, then movement/cutoff. Investigators should start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then inspect reported-vs-actual arguments, `process-injection.json`, `getsystem-pipe.json`, `lsass-ntds-ifm.json`, generated AdFind/BloodHound outputs, `movement-authentication.json`, generated host roles, and `cutoff-no-ryuk.json`.

Every executable is a copied, signed `cmd.exe` decoy invoked only with a fixed benign `echo`; batches and discovery outputs are inert canaries. Network attempts are forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. No malware, injection, pipe/token change, registry PowerShell, LDAP, LSASS/NTDS/credential access, WMI/SMB/service execution, pass/overpass-the-hash, ticket request, remote host/DC access, exfiltration, or ransomware impact occurs. Real domain controllers are refused.

The report's ATT&CK mappings are T1204, T1550.002, T1021.002, T1055, T1003, T1087, T1087.002, T1069.002, T1482, T1018, T1021, T1047, T1059.001, T1059, T1043, T1571, T1071, and T1041.
