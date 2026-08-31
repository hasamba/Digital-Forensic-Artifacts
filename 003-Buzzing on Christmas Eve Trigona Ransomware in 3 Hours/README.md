# 003 - Trigona ransomware in three hours

Lab-safe companion to [the complete source report](https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/). It preserves exposed-RDP and operator-host metadata, the customized NetScan toolkit and `delete.me`, inert Defender/account/RDP scripts, the Rclone/Mega sequence, the source change, and Trigona at 2h49m. Published hashes are attached only to signed decoy metadata.

Run elevated with the standard environment gate and `./TrigonaSim-Complete.ps1 -LabConfirmed`. Artifacts remain in `%PUBLIC%\TrigonaSim`; cleanup is separate. No authentication, scan, user/account/firewall/Defender/registry change, remote RDP/SMB action, exfiltration, shadow deletion, or encryption occurs; the published Support password is deliberately not copied into generated artifacts.
