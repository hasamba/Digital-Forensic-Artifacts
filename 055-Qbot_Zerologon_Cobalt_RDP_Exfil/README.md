# 055 - Qbot and Zerologon Lead To Full Domain Compromise

Lab-safe PowerShell reconstruction of The DFIR Report's [Qbot and Zerologon Lead To Full Domain Compromise](https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/).

The generated chronology preserves the initial Qbot DLL, first activity five minutes later, `Pvoeooxf`/`Yerqbqokc` registry content and 30-minute task, second DLL and explorer hollowing, `cool.exe` Zerologon at minute 30, domain-controller password/hash/repair and over-pass-the-hash evidence, renamed `find.exe` AdFind discovery, Cobalt `psexec_psh` service beacons, RDP settings and logon type 10, `dce_3d` SMB pipe, file-server staging, three canary-open alerts, and the reported 17:52–18:00 encrypted-C2 exfiltration window.

The mandatory gate refuses domain controllers. All executable names are signed `cmd.exe` copies with fixed benign executed arguments; reported commands are metadata. DCs, file servers, services, RDP sessions, registry keys, tasks, named pipes, and documents are generated canaries. Network attempts terminate on `127.0.0.1` with no proxy and zero bytes transferred. No exploit, password/hash/credential/Kerberos access, remote action, collection, or exfiltration occurs.

```powershell
.\ZeroQbotSim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\ZeroQbotSim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
