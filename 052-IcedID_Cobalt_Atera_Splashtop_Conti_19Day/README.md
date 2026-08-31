# 052 - Stolen Images Campaign Ends in Conti Ransomware

Lab-safe PowerShell reconstruction of The DFIR Report's [Stolen Images Campaign Ends in Conti Ransomware](https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/).

The 19-day timeline preserves the cloud ZIP/ISO/LNK IcedID lure, hourly task, discovery and initial Cobalt, Atera/Splashtop persistence, process injection, LSASS and Defender activity, day-six ShareFinder, day-seven SMB/service domain-controller pivot, AdFind, four Cobalt handoffs, quiet day-nine/ten/fourteen check-ins, day-nineteen directory review, failed first Conti execution, failed SAM-the-Admin CVEs, recovered domain-admin access, and successful `x64.dll`/`backup.bat` deployment twenty minutes after the DC beacons.

The impact phase creates six generated host trees with untouched source canaries, inert payload/service names, extension markers, and ransom-note canaries. It does not modify or encrypt the sources. The mandatory gate refuses domain controllers; no malware, RMM install, LSASS access, AD exploit, remote service/share action, SMB propagation, ransomware execution, IOC contact, or exfiltration occurs.

```powershell
$env:DFIR_LAB_CONFIRMATION = 'I_UNDERSTAND_THIS_IS_A_LAB'
.\Conti19Sim-Complete.ps1 -LabConfirmed
```

Artifacts remain under `%PUBLIC%\Conti19Sim`; cleanup is separately gated. See [scenario-manifest.json](scenario-manifest.json) and [IOC-METADATA.json](IOC-METADATA.json).
