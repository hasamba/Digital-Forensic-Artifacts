# 037 - 2022 Year in Review composite

Lab-safe PowerShell companion to The DFIR Report's [2022 Year in Review](https://thedfirreport.com/2023/03/06/2022-year-in-review/).

This source is an aggregate of 13 public cases, not one intrusion. The scripts therefore create three clearly labeled synthetic chains covering the report's major trends: phishing/ISO/SEO/exploit access and PowerShell/WMI/DLL execution; early/late persistence, credential-access evidence, and AdFind/ShareFinder discovery; then RDP/SMB movement, Rclone/C2 exfiltration, and ransomware deployment.

The mandatory gate refuses domain controllers. No malware, exploit, task, run key, WMI subscription, web shell, account, credential/LSASS/Kerberos access, directory/share query, remote action, real collection, exfiltration, or encryption occurs. Network markers terminate on loopback and generated originals remain intact.

```powershell
.\YearReviewSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\YearReview2022Sim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) for the aggregate-provenance warning and [IOC-METADATA.json](IOC-METADATA.json) for the report's common TLS fingerprints.
