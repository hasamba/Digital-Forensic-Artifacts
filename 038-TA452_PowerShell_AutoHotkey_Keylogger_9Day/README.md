# 038 - TA452 PowerShell and AutoHotkey keylogger

Lab-safe PowerShell reconstruction of The DFIR Report's [Collect, Exfiltrate, Sleep, Repeat](https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/).

The scenario preserves the nine-day chronology and investigation pivots: `Apply Form.docm`, the hidden Microsoft Windows Update path, `Script.ps1`/`temp.ps1`/`Updater.vbs`, the ten-minute `WindowsUpdate` task, AES-CBC `/get` and `/put` traffic, discovery command lines, renamed AutoHotkey `module.exe`, `module.ahk`, `readkey.ps1`, `t.xml`, the `MicrosoftEdgeUpdateTaskMachineUC` logon task, `KeypressValue`, `logFileuyovaqv.bin`, CAB and screenshot-name staging, and collection repeats on days 6, 7, and 9.

The mandatory gate refuses domain controllers. No live payload is retrieved or run; no task, keyboard hook, registry value, screenshot, discovery query, real archive, cleanup command, or exfiltration occurs. Executable telemetry uses signed `cmd.exe` copies with safely echoed reported command lines. All network markers connect only to `127.0.0.1`, disable proxy semantics, and transfer zero bytes. Published hashes are metadata; the report's 57-character `Script.ps1` SHA-256 value is preserved and explicitly marked malformed.

```powershell
.\OilKeySim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\OilKeySim`; cleanup is a separate, equally gated action:

```powershell
.\Cleanup-OilKeySim.ps1 -LabConfirmed
```

See [scenario-manifest.json](scenario-manifest.json) for phase/ATT&CK mapping and [IOC-METADATA.json](IOC-METADATA.json) for published indicators.
