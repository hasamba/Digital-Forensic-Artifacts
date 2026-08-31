# 092 - RDP, AdFind recon, and local-admin creation

Lab-safe companion to [AdFind Recon](https://thedfirreport.com/2020/05/08/adfind-recon/). It preserves RDP from `217.182.242.13`/OVH, client names `WORK9F3B` and `MacBook-Pro`, the 20-second command-prompt delay, the 15-minute return, `whoami /upn`, the nine report-described AdFind selectors and redirected text outputs, and creation of local administrator `Adm.1c`. Commands visible only in the report screenshot are not transcribed and are deliberately not invented. The report publishes no hashes or batch filename.

Run elevated with the standard lab gate via `.\AdFindReconSim-Complete.ps1 -LabConfirmed`; artifacts remain under `%PUBLIC%\AdFindReconSim`, and cleanup is separate. Executables are fixed-echo signed `cmd.exe` decoys, AdFind results are generated canary records, and the batch file is inert. The published password is metadata only. No authentication, real RDP, directory query, account creation, group modification, credential use, or external connection occurs; real DCs are refused.

Observed behavior maps to T1133, T1021.001, T1078, T1033, T1087.002, T1018, T1482, T1016.001, and T1136.001. These mappings are analyst inferences because the source provides no ATT&CK table.
