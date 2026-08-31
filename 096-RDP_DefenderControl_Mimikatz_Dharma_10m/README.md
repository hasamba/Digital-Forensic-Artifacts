# 096 - Ten-minute RDP-to-Dharma intrusion

Lab-safe companion to [Dharma Ransomware](https://thedfirreport.com/2020/04/14/dharma-ransomware/). It preserves RDP from `178.239.173.172`, the under-ten-minute local-admin-to-domain-admin transition, DefenderControl and `MpCmdRun.exe -DisableService`, Mimikatz, Network Scanner renamed `NSold.exe`, subnet/share-scan metadata, manual RDP deployment to five generated hosts, `findstr.exe /c:system$ /c:sistem$`, `payload.exe`, `Info.hta`, the screenshot-published Run values, `FILES ENCRYPTED.txt`, both ransom contacts, the `.cezar` family identification, and `c:\crysis\release\pdb\payload.pdb`.

Run elevated with the standard lab gate via `.\DharmaTenMinuteSim-Complete.ps1 -LabConfirmed`; artifacts remain under `%PUBLIC%\DharmaTenMinuteSim`, and cleanup is separate. All executables are fixed-echo signed `cmd.exe` decoys. Five generated victim trees receive ransom notes and sidecar markers while their canary originals remain intact. No authentication, RDP, privilege change, Defender impairment, LSASS/credential access, scan, share mount, remote execution, registry change, or encryption occurs; real DCs are refused.

Observed behavior maps to T1133, T1021.001, T1078, T1562.001, T1003, T1046, T1018, T1036, T1059.003, T1547.001, T1218.005, and T1486. These mappings are analyst inferences because the source provides no ATT&CK table.
