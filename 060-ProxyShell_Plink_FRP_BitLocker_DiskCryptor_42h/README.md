# 060 - Exchange Exploit Leads to Domain Wide Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [Exchange Exploit Leads to Domain Wide Ransomware](https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/), internal case 6898.

The generated 42-hour chronology preserves three ProxyShell web shells across three observed days, Exchange discovery/export commands, `CacheTask` FRP persistence, masquerading `dllhost.exe`, Plink reverse RDP, `DefaultAccount`, KPortScan, server/DC RDP, an Impacket WMI event, reported Task Manager LSASS staging, `setup.bat` BitLocker impact, workstation DiskCryptor deployment, and the USD 8,000 ransom-note observation.

Web shells are inert text and executable names are signed `cmd.exe` copies with fixed benign arguments. Reported commands and normalized hashes are investigation metadata. Network attempts are loopback-only with proxy use disabled. No Exchange/mailbox action, account/group change, task/service, remote action, scan, RDP/WMI, LSASS access, security/log impairment, configuration/boot/reboot change, driver, BitLocker, DiskCryptor, deletion, or encryption occurs. Generated originals remain intact beside impact markers.

```powershell
.\ProxyEncryptSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ProxyEncryptSim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
