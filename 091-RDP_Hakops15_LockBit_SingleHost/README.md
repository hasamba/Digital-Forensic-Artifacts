# 091 - RDP, Hakops15, and single-host LockBit

Lab-safe companion to [Lockbit Ransomware, Why You No Spread?](https://thedfirreport.com/2020/06/10/lockbit-ransomware-why-you-no-spread/). It preserves RDP from `165.231.142.36`, the DA account switch after 15 minutes, `%APPDATA%\svchost.exe`, firewall/Security Center/Defender commands, Hakops15 daily FTP keylog metadata, unused `screensaver.exe`, `9689A16B72D48DAB.exe`, recovery-destruction commands, unpublished registry markers, `/16` ping/SMB activity, successful authentication/share enumeration, and the one-host/no-spread outcome.

Run elevated with the standard lab gate via `.\LockBitSingleSim-Complete.ps1 -LabConfirmed`; artifacts remain under `%PUBLIC%\LockBitSingleSim`, and cleanup is separate. All executables are fixed-echo signed `cmd.exe` decoys. The report publishes no hashes or FTP endpoint, so none are invented. No authentication, RDP, keylogging, FTP, defense/recovery/registry change, scanning, SMB, remote infection, or encryption occurs; real DCs are refused.

Observed behavior maps to T1133, T1078, T1562.004, T1562.001, T1056.001, T1048.003, T1490, T1046, T1021.002, T1135, and T1486.
