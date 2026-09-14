# 002 - Fake Zoom ends in BlackSuit ransomware

Lab-safe companion to [the complete source report](https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/). It preserves the fake Zoom/d3f@ckloader and IDAT chain, SectopRAT, Brute Ratel, Cobalt Strike, QDoor/RDP, WinRAR/Bublup collection, and PsExec/WMIC BlackSuit deployment over a generated 194-hour axis. Published hashes and IOCs are investigation metadata only.

Run elevated with `./BlackSuit_Simulation.ps1 -LabConfirmed`. Artifacts remain in `%PUBLIC%\BlackSuitZoomSim`; cleanup is separate. No download, live malware, Defender change, injection, credential/LSASS access, remote service/RDP, external traffic, collection/exfiltration, shadow deletion, or encryption occurs.
