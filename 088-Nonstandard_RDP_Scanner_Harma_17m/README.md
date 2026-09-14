# 088 - Nonstandard-port RDP, Network Scanner, and Harma in 17 minutes

Lab-safe companion to The DFIR Report's [Ransomware Again...But We Changed the RDP Port!?!?!](https://thedfirreport.com/2020/07/13/ransomware-again-but-we-changed-the-rdp-port/) (internal case 1001). It preserves the exact 07:00–07:17 UTC timeline: RDP from `212.102.45.98` to a nonstandard port, Task Manager, SoftPerfect Network Scanner, RDP to a DC representation, repeat inspection/scanning, Harma on the DC at minute 13, and Harma on the entry system at minute 17. Both payload names, hashes, and the reported Startup path are retained.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\Harma17Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\Harma17Sim`; cleanup is separate with `.\Cleanup-Harma17Sim.ps1 -LabConfirmed`.

All executable names are copied, signed `cmd.exe` decoys invoked only with fixed benign `echo`. The RDP source is metadata; socket markers go only to `127.0.0.1`, use no proxy, and transfer zero bytes. No authentication, RDP, Task Manager session inspection, scan packet, remote write, startup change, malware, DC action, or encryption occurs. Impact markers touch only generated host data. Real domain controllers are refused.

The report maps T1133, T1135, T1486, and T1078.
