# 053 - PHOSPHORUS Automates Initial Access Using ProxyShell

Lab-safe PowerShell reconstruction of The DFIR Report's [PHOSPHORUS Automates Initial Access Using ProxyShell](https://thedfirreport.com/2022/03/21/phosphorus-automates-initial-access-using-proxyshell/).

The generated 72-hour chronology preserves two nearly identical automated bursts separated by roughly two days: the three-CVE ProxyShell chain, Exchange role and mailbox-export web-shell mechanics, POST activity about twenty seconds later, `Wininet.xml`/`Wininet.bat` scheduled-task persistence, fake `dllhost.exe` FRP traffic, DefaultAccount/RDP changes, Defender/WDigest/LSA impairment, discovery, the reversed `ssasl.pmd` LSASS dump name, archive/exfiltration, and eviction before the assessed ransomware outcome.

All dangerous actions are representations. Web shells are inert text, executable names are signed `cmd.exe` copies, reported command lines are manifest metadata while executed arguments are fixed benign text, and every network attempt is forced to `127.0.0.1` with no proxy and zero transferred bytes. No Exchange cmdlet, mailbox operation, task, account, group, password, firewall, service, registry, Defender, credential, LSASS, archive, exfiltration, or ransomware action occurs.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\PhosphorusSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\PhosphorusSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
