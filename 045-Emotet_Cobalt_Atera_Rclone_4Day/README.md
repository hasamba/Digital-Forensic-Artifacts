# 045 - Dead or Alive? An Emotet Story

Lab-safe PowerShell reconstruction of The DFIR Report's [Dead or Alive? An Emotet Story](https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/).

The four-day scenario preserves the `info_1805.xls` Excel 4.0 lure, macro download paths, `llJyMIOvft.dll` Emotet execution, Run-key and email-spreader evidence, `UOmCgbXygCe.exe` Cobalt delivery, process-injection and SearchIndexer/LSASS telemetry, domain and share discovery, Kerberoasting, renamed AdFind, Pass-the-Hash/PsExec movement, Atera/Splashtop persistence, generated share data, and three Rclone-to-MEGA attempts before eviction. Published hashes, Emotet endpoints, macro URLs, and Cobalt profile values are investigation metadata only.

The mandatory lab gate refuses domain controllers. Payload and installer names are inert canaries; executable decoys are copies of signed `cmd.exe`. No macro, malware, registry write, injection, credential or ticket access, directory/share query, remote action, SMTP transmission, RMM installation, real collection, cloud access, or impact occurs. Every network marker targets `127.0.0.1`, disables proxy use by design, and records zero bytes transferred.

```powershell
.\EmotetRcloneSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\EmotetRcloneSim`; cleanup is a separate gated action. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
