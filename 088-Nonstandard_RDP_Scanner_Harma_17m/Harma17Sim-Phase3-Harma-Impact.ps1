#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\Harma17Sim-utilities.ps1";Assert-H17Safety -LabConfirmed:$LabConfirmed;$p=Initialize-H17Environment
$dc=New-H17HostTree -Name 'DC01-CANARY' -Role 'generated domain-controller representation';$entry=New-H17HostTree -Name 'ENTRY01-CANARY' -Role 'generated entry host'
$dcPayload=Join-Path $p.Payloads '5-NS new.exe';$entryPayload=Join-Path $p.Payloads 'BPY6A7_payload.exe'
New-H17Decoy -Path $dcPayload -Role 'Harma payload stand-in' -PublishedSha256 'f47e3555461472f23ab4766e4d5b6f6fd260e335a6abc31b860e569a720a5446'
New-H17Decoy -Path $entryPayload -Role 'Harma payload and startup-persistence stand-in' -PublishedSha256 '23a3dfe1493dcda00a3d9a00210793553b629bd77f30c39974c8e1ab0ea51c6f'
Invoke-H17Decoy -FilePath $dcPayload -Reported '5-NS new.exe dropped to DC desktop and executed' -Parent 'RDP user session on DC' -Label 'SYNTHETIC-HARMA'
Invoke-H17Decoy -FilePath $entryPayload -Reported 'BPY6A7_payload.exe dropped to entry-host desktop and executed' -Parent 'RDP user session on entry host' -Label 'SYNTHETIC-HARMA'
Write-H17Json -Path(Join-Path $p.Evidence 'startup-persistence.json')-Object([ordered]@{reportedPath='C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BPY6A7_payload.exe';startupFilesWritten=0;actualStartupPathTouched=$false})-Purpose persistence
$records=New-Object System.Collections.Generic.List[object]
foreach($pair in @(@('DC01-CANARY',$dc),@('ENTRY01-CANARY',$entry))){Write-H17File -Path(Join-Path $pair[1] 'C$\Desktop\HARMA-README.txt')-Content "INERT HARMA RANSOM-NOTE CANARY for $($pair[0]). No payment instructions and no original file changed." -Purpose ransom-note-canary;Write-H17File -Path(Join-Path $pair[1] 'C$\Finance\ledger.xlsx.HARMA-CANARY')-Content "INERT ENCRYPTION MARKER for generated host $($pair[0])." -Purpose encryption-canary;$records.Add([ordered]@{hostname=$pair[0];generatedTree=$pair[1];markers=2;userFilesRead=0;userFilesChanged=0;filesEncrypted=0})}
Write-H17Json -Path(Join-Path $p.Evidence 'impact-summary.json')-Object([ordered]@{reportedFamily='Harma variant of Dharma/CrySiS';reportedTargets=@('domain controller at 07:13','entry point at 07:17');generatedHosts=$records;startupFilesWritten=0;remoteFilesWritten=0;userFilesChanged=0;filesEncrypted=0;generatedCanaryMarkers=4})-Purpose impact
Add-H17Timeline 13 impact '07:13 Harma dropped/run on generated DC representation' @{filesEncrypted=0;generatedCanaryMarkers=2}
Add-H17Timeline 17 impact '07:17 Harma dropped/run on generated entry host; intrusion completes' @{filesEncrypted=0;generatedCanaryMarkers=4}
Write-H17Json -Path(Join-Path $p.Evidence 'phase3-negative.json')-Object([ordered]@{liveMalware=0;startupFilesWritten=0;actualStartupPathTouched=$false;remoteFilesWritten=0;userFilesRead=0;userFilesChanged=0;filesEncrypted=0;securityControlsChanged=0;logsCleared=0;shadowCopiesDeleted=0;externalConnections=0})-Purpose safety
