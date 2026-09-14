# 040 - Ursnif ISO, Cobalt Strike, WMI, and RDP

Lab-safe PowerShell reconstruction of The DFIR Report's [Unwrapping Ursnifs Gifts](https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts/).

The scenario retains the roughly five-day sequence: `3488164.iso`, `6570872.lnk`, the hidden `me` tree, `alsoOne.bat`, `canWell.js`, renamed `rundll32` as `123.com`, `itsIt.db`, registry-resident `ActiveDevice`/`MemoryJunk`, `ManagerText` Run-key evidence, automated discovery into `BD2C.bin1`, the day-four BITS/Cobalt transition, manual and `adcomp.bat` discovery, injection and LSASS-access evidence, Impacket-style WMI/SMB movement, Atera/Splashtop and `firefox.exe` artifacts, Ursnif HTTP POSTs, proxied RDP, and the ten-minute backup-server review from client `WIN-RRRU9REOK18`.

The gate refuses domain controllers. No ISO is mounted; no live payload, registry change, compilation, injection, LSASS/credential access, BITS transfer, directory query, remote WMI/SMB/RDP action, RMM install, backup-console interaction, real collection, or exfiltration occurs. Executables are signed `cmd.exe` stand-ins, remote/network actions are loopback-only with zero bytes, and all published IOCs are metadata. The report's 51-character `vnc64.rar` SHA-256 value is preserved and marked malformed.

```powershell
.\UrsnifGiftSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\UrsnifGiftSim`; cleanup is separately gated:

```powershell
.\Cleanup-UrsnifGiftSim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
