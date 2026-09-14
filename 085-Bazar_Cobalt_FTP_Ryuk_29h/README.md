# 085 - Bazar, Cobalt Strike, FTP, and Ryuk in 29 hours

Lab-safe companion to The DFIR Report's [Ryuk's Return](https://thedfirreport.com/2020/10/08/ryuks-return/) (internal case 1005). It preserves `Document-Preview.exe`, Bazar injection/shell behavior, immediate AdFind/day-one discovery, the quiet period, day-two AdFind/Rubeus/PowerView/AD/AV recon, vsftpd exfiltration, a non-vulnerable MS17-010 check, failed WMI and PowerShell-service movement, the final SMB/service Cobalt method, remote-drive access metadata, DC C2, encoded Defender-disable metadata, backup-first `fx16_multi_for_crypt_x86.exe` deployment, pre-impact Veeam/SQL command lines, and the one-minute transfer-to-execution interval. The complete 29-hour axis is retained.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\RyukReturnSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\RyukReturnSim`; cleanup is separate with `.\Cleanup-RyukReturnSim.ps1 -LabConfirmed`.

Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then inspect day-one/day-two discovery, FTP, MS17-010, movement, Defender, backup preparation, pre-impact, and impact records. Synthetic `AllWindows.csv` and generated host trees give analysts evidence without querying a domain or touching user data.

Every executable/DLL name is a copied, signed `cmd.exe` decoy; executable stand-ins run only with fixed benign `echo` arguments, and DLLs are never loaded. All IOC attempts are forced to `127.0.0.1`, use no proxy, and transfer zero bytes. No malware, credential/ticket collection, scanner, WMI/service/SMB/RDP action, FTP, remote mount, PowerShell, Defender change, wbadmin action, process/service termination, ACL change, or encryption occurs. Real domain controllers are refused.

The report's legacy ATT&CK mapping is preserved: T1204, T1047, T1035, T1064, T1086, T1085, T1055, T1078, T1089, T1087, T1482, T1046, T1012, T1018, T1063, T1021, T1043, T1071, and T1486.
