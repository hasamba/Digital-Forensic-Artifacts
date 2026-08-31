#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$LabConfirmed)
. "$PSScriptRoot\NitrogenSim-utilities.ps1"
Assert-NitrogenSafety -LabConfirmed:$LabConfirmed
$p = Initialize-NitrogenEnvironment

$versionZip = Join-Path $p.Initial 'Version.zip'
Write-NitrogenFile $versionZip 'INERT ZIP CANARY - reported fake Advanced IP Scanner malvertising download; no archive or malware content.' 'initial access archive canary'
$setup = Join-Path $p.Initial 'setup.exe'
New-NitrogenDecoy $setup 'legitimate Python setup side-loader decoy' '5DC8B08C7E1B11ABF2B6B311CD7E411DB16A7C3827879C6F93BD0DAC7A71D321'
Write-NitrogenFile (Join-Path $p.Initial 'python311.dll') 'INERT modified-Python-DLL canary. Reported SHA256: 9514035FEA8000A664799E369AE6D3AF6ABFE8E5CDA23CDAFBEDE83051692E63' 'DLL side-loading metadata'
Write-NitrogenFile (Join-Path $p.Initial 'python3.dll') 'INERT hidden DLL canary' 'hidden DLL metadata'
[IO.File]::SetAttributes((Join-Path $p.Initial 'python311.dll'),[IO.FileAttributes]::Hidden)
[IO.File]::SetAttributes((Join-Path $p.Initial 'python3.dll'),[IO.FileAttributes]::Hidden)
Invoke-NitrogenDecoy $setup 'Version.zip\setup.exe'
Add-NitrogenTimeline 0 'initial-access' 'Malvertising fake Advanced IP Scanner archive opened' @{reportedFile='Version.zip';source='fake Advanced IP Scanner site';techniques=@('T1189','T1204.002','T1574.002')}

$scanner = Join-Path $p.PublicDownloads 'advanced_ip_scanner.exe'
New-NitrogenDecoy $scanner 'legitimate Advanced IP Scanner decoy'
$python = Join-Path $p.Notepad 'python.exe'
New-NitrogenDecoy $python 'Python runtime decoy'
foreach ($artifact in @(
    @{Name='slv.py';Hash='4EF1009923FC12C2A3127C929E0AA4515C9F4D068737389AFB3464C28CCF5925';Role='Py-Fuscate-obfuscated Sliver loader'},
    @{Name='data.aes';Hash='3298629DE0489C12E451152E787D294753515855DBF1CE80BFCDED584A84AC62';Role='AES-encrypted Sliver payload'},
    @{Name='worksliv.py';Hash='5F7D438945306BF8A7F35CAB0E2ACC80CDC9295A57798D8165EF6D8B86FBB38D';Role='Sliver loader variant'},
    @{Name='work.aes';Hash='4EE4E1E2CEDF59A802C01FAE9CCFCFDE3E84764C72E7D95B97992ADDD6EDF527';Role='AES payload variant'},
    @{Name='wo14.py';Hash='726F038C13E4C90976811B462E6D21E10E05F7C11E35331D314C546D91FA6D21';Role='Cobalt Strike heap loader'},
    @{Name='wo12.py';Hash='NOT-PUBLISHED';Role='Cobalt Strike loader variant'},
    @{Name='we3p2v5t85';Hash='NOT-APPLICABLE';Role='reported AES key evidence'},
    @{Name='pycryptodome.canary';Hash='NOT-APPLICABLE';Role='dependency inventory'}
)) { Write-NitrogenFile (Join-Path $p.Notepad $artifact.Name) "INERT $($artifact.Role). Reported SHA256: $($artifact.Hash)" $artifact.Role }
Invoke-NitrogenDecoy $python 'python.exe slv.py data.aes StartW'
Add-NitrogenTimeline 8 'execution-c2' 'Sliver loader and in-memory StartW chain represented' @{actual='signed decoy echo only';memoryLoad=$false;apiUnhook=$false;sleepObfuscation=$false;reportedC2=@('194.49.94.18:8443','194.169.175.134:8443')}
Invoke-NitrogenLoopback 8443 '194.49.94.18:8443' 'Sliver HTTPS'
Invoke-NitrogenLoopback 8443 '194.169.175.134:8443' 'Sliver HTTPS'

$persistence = [ordered]@{
    mode='evidence-only; no task or registry change'
    scheduledTasks=@(
        @{name='OneDrive Security Task-S-1-5-21-REDACTED';action='C:\Windows\Temp\UpdateEdge.bat';triggers=@('ONSTART','every 720 minutes')},
        @{name='OneDrive Security Task-S-1-5-21-REDACTED';action='C:\Windows\Temp\upedge.bat';triggers=@('ONSTART','every 720 minutes')},
        @{name='UpdateEdge';action='C:WindowsTempUpdate.exe';trigger='ONIDLE';parseErrorPreserved=$true}
    )
    winlogon=@{key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';value='Userinit';reportedAppend='C:\Windows\Temp\UpdateEdge.bat';modified=$false}
    syntheticProcessAccess=@{source='setup.exe';target='winlogon.exe';grantedAccess='0x143A';injectionPerformed=$false}
}
Write-NitrogenFile (Join-Path $p.Evidence 'persistence-and-winlogon.json') ($persistence | ConvertTo-Json -Depth 8) 'persistence evidence'
Add-NitrogenTimeline 10 'persistence' 'Scheduled task and Winlogon persistence represented as metadata' @{tasksCreated=0;registryWrites=0;techniques=@('T1053.005','T1547.004','T1055.001')}

$profile = [ordered]@{
    mode='metadata-only'
    servers=@('91.92.250.65:443','91.92.250.60:443')
    staging='91.92.245.26:443'
    sleepMs=38500;jitterPercent=27;maxGetSize=13982519
    get='/broadcast';post='/1/events/com.amazon.csm.csa.prod'
    userAgent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36'
    spawnto='gpupdate.exe';watermark=587247372;allocator='NtMapViewOfSection'
    ja3='72a589da586844d7f0818ce684948eea';ja3s='f176ba63b4d68e576b5ba345bec2c7b7'
    actualDestination='127.0.0.1';proxy=$false
}
Write-NitrogenFile (Join-Path $p.Evidence 'cobalt-strike-profile.json') ($profile | ConvertTo-Json -Depth 8) 'Cobalt Strike profile metadata'
Invoke-NitrogenDecoy $python 'python.exe wo14.py we3p2v5t85'
Invoke-NitrogenDecoy $python 'python.exe wo12.py we3p2v5t85'
Invoke-NitrogenLoopback 443 '91.92.250.65:443' 'Cobalt Strike HTTPS'
Invoke-NitrogenLoopback 443 '91.92.250.60:443' 'Cobalt Strike HTTPS'
Invoke-NitrogenLoopback 443 '91.92.245.26:443' 'payload staging HTTPS'
Add-NitrogenTimeline 60 'execution-c2' 'Python Cobalt Strike loaders represented' @{actual='signed decoy echo only';heapAllocation=$false;threadCreation=$false;selfInjection=$false;techniques=@('T1059.006','T1055','T1105','T1071.001')}
