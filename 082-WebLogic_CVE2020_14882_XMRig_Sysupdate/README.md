# 082 - WebLogic CVE-2020-14882 to XMRig

Lab-safe companion to The DFIR Report's [Cryptominers Exploiting WebLogic RCE CVE-2020-14882](https://thedfirreport.com/2020/11/12/cryptominers-exploiting-weblogic-rce-cve-2020-14882/) (internal case 1009). It preserves the WebLogic images-path exploit request, `wbw.xml`, PowerShell retrieval of `1.ps1`, XMRig/config staging, `sysupdate` masquerading, 30-minute update task, absent `update.ps1`, miner-process check, six pool endpoints, and reported 100% CPU impact.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\WebLogicMinerSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\WebLogicMinerSim`; cleanup is separate with `.\Cleanup-WebLogicMinerSim.ps1 -LabConfirmed`.

Begin with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then inspect `images-request.json`, reported-vs-actual PowerShell and miner ancestry, inert `wbw.xml`/`1.ps1`, `stage-behavior.json`, `scheduled-task.json`, `config.json`, and `impact.json`.

All executables are copied, signed `cmd.exe` decoys invoked only with a fixed benign `echo`; XML, PowerShell, and config files are inert. Every endpoint attempt is forced to `127.0.0.1`, proxy use is false, and zero bytes are transferred. No WebLogic request/exploitation, download, policy bypass, PowerShell, task, process termination/query, miner, CPU load, mining share, or external connection occurs. Real domain controllers are refused.

The report maps T1190, T1059, T1053.005, T1496, and T1036.
