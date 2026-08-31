# 009 - Blurring the lines: Play, RansomHub, and DragonForce

Lab-safe companion to [the source report](https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/). It preserves the six-day EarthTime/SectopRAT/SystemBC chain, BITS/account/DCSync evidence, RDP/Grixba/NetScan/Veeam/SharpHound/AdFind sequence, WinRAR/FTP exfiltration, Betruger/wmiexec, and three-gang attribution.

Run elevated with the standard environment gate and `./BlurringLinesSim-Complete.ps1 -LabConfirmed`. Artifacts remain in `%PUBLIC%\BlurringLinesSim`; cleanup is separate. No credentials, accounts, BITS jobs, services, registry, remote systems, IOC infrastructure, security controls, or user data are touched. Ransomware was prevented in the real case and is not simulated.
