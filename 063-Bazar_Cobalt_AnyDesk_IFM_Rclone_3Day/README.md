# 063 - BazarLoader and the Conti Leaks

Lab-safe PowerShell reconstruction of The DFIR Report's [BazarLoader and the Conti Leaks](https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/), internal case 5426.

The generated three-day chronology preserves the assessed macro-document vector, rundll32 BazarLoader, 20-minute Cobalt transition, misspelled discovery and `av_query`, AdFind, process injection, LSASS access, reverse-proxy RDP, two DC pivots, leaked-manual local accounts with redacted password, an 11-hour AnyDesk channel, PowerSploit, IFM/NtdsAudit artifacts, Advanced IP Scanner, Seatbelt, XMPP/SSH oddities, day-three `Shares` staging, a remote-open alert, Rclone/MEGA exfiltration, and eviction before suspected Conti deployment.

All tools and scripts are inert text or signed `cmd.exe` decoys with fixed benign arguments. Network attempts are loopback-only. Generated IFM, pwdump, user, and staged document artifacts contain no real credentials or data. No malware, injection, LSASS/NTDS access, account change, RDP/remote action, AnyDesk, scan/query, real collection, cloud access, exfiltration, ransomware, or encryption occurs.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\LeakBazarSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\LeakBazarSim`; cleanup is separately gated. The script refuses domain controllers. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
