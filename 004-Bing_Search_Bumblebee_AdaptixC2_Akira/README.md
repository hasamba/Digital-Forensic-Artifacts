# 004 - Bing search, Bumblebee, AdaptixC2, and Akira

Lab-safe companion to [the source report](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/). It preserves the OpManager lure, Bumblebee DLL side-loading, WMI/AdaptixC2, account and RMM persistence metadata, discovery, NTDS/Veeam/LSASS command evidence, reverse SSH, FileZilla/SFTP, and Akira impact shape.

Run elevated with `./AkiraSim-Complete.ps1 -LabConfirmed`. No environment variable is needed. Artifacts remain in `%PUBLIC%\AkiraSim`; use `Cleanup-AkiraSim.ps1` separately. Executable-looking files are signed fixed-echo decoys, IOC connections are loopback-only and zero-byte, and no accounts, services, credentials, remote systems, security controls, logs, shadows, or user files are touched.
