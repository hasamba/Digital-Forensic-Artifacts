# 080 - Defender Control Profile

Lab-safe companion to The DFIR Report's [Defender Control](https://thedfirreport.com/2020/12/13/defender-control/) (internal case 1011). It preserves the typical exposed-RDP/single-host ransomware context, Defender block followed minutes later by tool staging, v1.6 executable and INI, GUI and command-line execution, two registry/service-start values, driver unload, Local Group Policy state, and reported Windows Security UI effect.

Run elevated on a disposable Windows member workstation or member server—not a domain controller:

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\DefenderControlSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\DefenderControlSim`; cleanup is separate with `.\Cleanup-DefenderControlSim.ps1 -LabConfirmed`.

Start with `artifact-manifest.jsonl` and `evidence\exercise-timeline.jsonl`, then review `intrusion-context.json`, reported-vs-actual decoy arguments, `registry-service-markers.json`, `driver-policy-markers.json`, `reported-ui-state.txt`, and `safety-state.json`.

`DefenderControl.exe` is a copied, signed `cmd.exe` decoy invoked only with a fixed benign `echo`; the INI is inert. The scenario does not inspect or change Defender, registry, WinDefend, drivers, Local Group Policy, GPO/SYSVOL, security controls, RDP, malware, or ransomware state. Real domain controllers are refused. The report maps the behavior to T1562.001.
