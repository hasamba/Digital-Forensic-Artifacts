# 078 - RDP, Mimikatz, Advanced IP Scanner, and XMRig in Two Hours

Lab-safe companion to The DFIR Report's [All That for a Coinminer?](https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/) (internal case 1014). It preserves the prior-day RDP brute force/account creation, valid RDP from the reported sources and `winstation`, Mimikatz LogonPasswords and Kerberos-ticket export, Advanced IP Scanner, Task Manager and `net accounts`, unexecuted masscan, RDP to DC/backup roles, `svshost.exe`, hidden XMRig artifacts, pool attempts, password change, and two-hour logout.

Run from an elevated PowerShell prompt on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\RdpMinerSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\RdpMinerSim`; cleanup is separate with `.\Cleanup-RdpMinerSim.ps1 -LabConfirmed`.

The three scripts cover RDP/account access, credential/discovery/lateral movement, and XMRig deployment/impact. Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then examine `rdp-account.json`, the synthetic `mimikatz.log` and `.kirbi.CANARY` files, `credential-discovery-movement.json`, the generated host tree, `password-change.json`, `impact.json`, and the generated `PolicyDefinitions` tree.

All executables are signed `cmd.exe` decoys invoked with a fixed benign `echo`; scripts and miner configuration are inert canaries. Network attempts are forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. No authentication, brute force, account/password change, RDP, LSASS/credential/ticket access, discovery/scan, DC access, file hiding, mining, CPU load, or pool contact occurs. Real domain controllers are refused.

The report's ATT&CK mappings are T1059, T1136, T1003, T1133, T1061, T1564.001, T1087.001, T1046, T1021, and T1496. Deprecated IDs are retained as published.
