# 008 - Lunar Spider, Latrodectus, Brute Ratel, and BackConnect

Lab-safe companion to [the source report](https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/). It preserves the tax-form lure, Brute Ratel/Latrodectus/Cobalt Strike/.NET payload shapes and hashes, Run/task evidence, credential/discovery commands, Zerologon/PsExec/RDP markers, Rclone/FTP, and the near-two-month ordering.

Run elevated with the standard environment gate and `./LunarSpiderSim-Complete.ps1 -LabConfirmed`. Artifacts remain in `%PUBLIC%\LunarSpiderSim`; cleanup is separate. No malware, injection, credential access, UAC/persistence change, exploit, scan, remote action, exfiltration, or encryption occurs. Consistent with the report, ransomware is not simulated.
