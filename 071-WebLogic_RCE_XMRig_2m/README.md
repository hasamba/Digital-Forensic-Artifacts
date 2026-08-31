# 071 - WebLogic RCE Leads to XMRig

Lab-safe companion to The DFIR Report's [WebLogic RCE Leads to XMRig](https://thedfirreport.com/2021/06/03/weblogic-rce-leads-to-xmrig/) (case 3580). It preserves the automated two-minute sequence: 12 WebLogic CVE-2020-14882 probes/exploit requests, Java→Cmd→PowerShell ancestry, `poc.xml`/`ldr.ps1`, randomized `sysvr013.exe`, minute-frequency `BrowserUpdate`, Run-key and `npf.sys` task persistence, firewall-disable and rival-miner discovery markers, then `[kthreaddi].exe` XMRig configuration and pool telemetry.

No exploit request is sent. Executables are signed `cmd.exe` decoys with fixed benign arguments. No malware, download, task, registry/firewall change, process kill, driver, mining, pool/C2 traffic, or resource hijacking occurs. Network attempts are loopback-only with zero bytes; real DC execution is refused.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\WebXMRSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\WebXMRSim`; run `.\Cleanup-WebXMRSim.ps1 -LabConfirmed` separately.
