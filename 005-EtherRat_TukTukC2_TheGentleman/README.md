# 005 - EtherRAT, TukTuk C2, and The Gentlemen

Lab-safe companion to [the source report](https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/). It preserves the fake RAMMap MSI, EtherHiding/EtherRAT, Run persistence, TukTuk side-loading and SaaS channels, credential and NetExec command evidence, GoTo Resolve, Wasabi/Rclone, and GPO-shaped Gentlemen deployment artifacts.

Run elevated with `./GentlemanSim-Complete.ps1 -LabConfirmed`. Artifacts remain in `%PUBLIC%\GentlemanSim`; cleanup is separate. No software is downloaded, IOC traffic leaves the host, credentials are accessed, accounts/tasks/services/GPOs are created, remote systems are touched, security controls or logs/shadows are changed, or files are encrypted.
