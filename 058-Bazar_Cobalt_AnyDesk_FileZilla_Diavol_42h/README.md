# 058 - Diavol Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [Diavol Ransomware](https://thedfirreport.com/2021/12/13/diavol-ransomware/).

The generated 42-hour chronology preserves the OneDrive ZIP/ISO/LNK Bazar chain, three-hour BITS recurrence, Cobalt DLLs, AdFind and scanning, registry-hive/Rubeus/LSASS/Veeam credential activity, RDP/AnyDesk movement, FileZilla and ufile.io exfiltration, and the final one-hour `kill.bat`/`CryptoLocker64.exe` domain-wide deployment. Generated originals remain intact beside ransomware markers and inert ransom notes.

The gate refuses domain controllers. Executable names are signed `cmd.exe` copies with fixed benign arguments; reported commands are metadata. No download, mount, malware, persistence/RMM, credential access, scan, remote action, collection, exfiltration, shadow-copy deletion, boot/service change, ransomware execution, or encryption occurs. The report does not publish a Diavol executable hash; metadata states that explicitly.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\DiavolSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\DiavolSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
