# 076 - Laravel Debug Secret-Harvesting Scanner

Lab-safe companion to The DFIR Report's [Laravel Apps Leaking Secrets](https://thedfirreport.com/2021/02/28/laravel-debug-leaking-secrets/). It preserves valid-account RDP from the published IP, Python 2.7, four pip package-install commands, `smtp.py`, `.env` and malformed-debug-response probes, provider keyword classification, the `Results` folder, and the `0x[]:androxgh0st` detection marker.

## Run

Use an elevated PowerShell prompt on a disposable Windows member workstation or member server—not a domain controller:

```powershell
.\LaravelLeakSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\LaravelLeakSim`; cleanup is separate:

```powershell
.\Cleanup-LaravelLeakSim.ps1 -LabConfirmed
```

The three phases represent the RDP/Python setup, scanner behavior against generated Laravel target directories, and provider-specific result classification. Investigators should pivot from `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl` into `rdp-valid-account.json`, `python-install.json`, `probe-methods.json`, generated `.env` and debug-response canaries, and the eight `Results` files.

All executables are signed `cmd.exe` decoys with a fixed benign `echo` argument. `smtp.py` contains comments only. Network attempts are loopback-only with proxy disabled and zero bytes. The scenario performs no RDP login, authentication, account use, Python/package installation, external scan or web request, real `.env`/secret access, credential validation, provider API use, email, or exfiltration. All credentials and targets are unmistakable canaries under the owned scenario root; real domain controllers are refused.

The report's ATT&CK mappings are T1078, T1059.006, T1064, T1204, T1061, and T1059. Deprecated technique IDs are retained as published.
