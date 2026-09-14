# 050 - SEO Poisoning: A Gootloader Story

Lab-safe PowerShell reconstruction of The DFIR Report's [SEO Poisoning - A Gootloader Story](https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/).

The two-day timeline preserves the Bing SEO query, ZIP/JavaScript Gootloader lure, two `Phone` registry values, in-memory .NET/Cobalt decode, user-logon task, SharpHound at 15 minutes, Defender impairment, Mimikatz and LaZagne, WMI/service beacon movement, Restricted Admin RDP to a domain controller, legal/insurance document review, and day-two Advanced IP Scanner sweep. Five published file-hash triplets, three C2 profiles, download URLs, and named pipes remain investigation metadata.

The mandatory gate refuses domain controllers. No search/download, JavaScript or malware execution, registry/task change, assembly load, injection, credential/directory access, Defender change, remote action, Restricted Admin setting, real share/document access, network scan, IOC contact, or impact occurs. Executable decoys are signed `cmd.exe` copies and all socket markers target loopback with zero bytes transferred.

```powershell
.\GootRdpSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\GootRdpSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
