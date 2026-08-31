function Invoke-BengalPayloadDelivery {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Paths)

    $dropperName = 'BitdefenderSupportInstaller.exe.js'
    $sourceDropper = Join-Path $Paths.Payload $dropperName
    $downloadZip = Join-Path $Paths.Downloads 'Bitdefender_Central_Setup.zip'
    $extractedDirectory = Join-Path $Paths.Downloads 'Bitdefender_Central_Setup'
    $extractedDropper = Join-Path $extractedDirectory $dropperName

    $javascript = @'
// BengalSEO MayaBot forensic canary. Inert: creates only local marker files.
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var cache = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") + "\\MayaCache";
if (!fso.FolderExists(cache)) { fso.CreateFolder(cache); }
var marker = fso.CreateTextFile(cache + "\\maya_session.dat", true);
marker.WriteLine("family=MayaBot-CANARY");
marker.WriteLine("campaign=bitdefender-central");
marker.WriteLine("execution=wscript.exe");
marker.WriteLine("c2_mode=LOOPBACK_ONLY");
marker.Close();
shell.RegWrite("HKCU\\Software\\BengalSEOSim\\LastCanaryExecution", new Date().toUTCString(), "REG_SZ");
'@
    Write-BengalEvidenceFile -Path $sourceDropper -Content $javascript -Purpose 'inert JavaScript dropper masquerading as an executable filename'

    if (Test-Path -LiteralPath $downloadZip) { Remove-Item -LiteralPath $downloadZip -Force }
    Compress-Archive -LiteralPath $sourceDropper -DestinationPath $downloadZip -CompressionLevel Optimal
    Add-BengalManifestEntry -Type 'file' -Path $downloadZip -Action 'created' -Details @{ purpose = 'browser-style ZIP payload artifact'; sha256 = (Get-FileHash -LiteralPath $downloadZip -Algorithm SHA256).Hash }

    if (Test-Path -LiteralPath $extractedDirectory) { Remove-Item -LiteralPath $extractedDirectory -Recurse -Force }
    Expand-Archive -LiteralPath $downloadZip -DestinationPath $extractedDirectory -Force
    Add-BengalManifestEntry -Type 'directory' -Path $extractedDirectory -Action 'created' -Details @{ purpose = 'user-extracted payload directory' }

    $zoneIdentifier = @"
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://link72.com/
HostUrl=https://ustechnio.com/Bitdefender_Central_Setup.zip
"@
    Write-BengalEvidenceFile -Path "${downloadZip}.Zone.Identifier.txt" -Content $zoneIdentifier -Purpose 'portable representation of Mark-of-the-Web metadata; not an NTFS ADS'

    if (-not (Test-Path -LiteralPath $extractedDropper)) {
        throw "Expected extracted dropper missing: $extractedDropper"
    }
    Start-Process -FilePath 'wscript.exe' -ArgumentList @('//B', '//NoLogo', "`"$extractedDropper`"") -Wait
    Add-BengalManifestEntry -Type 'process' -Path 'wscript.exe' -Action 'executed-inert-script' -Details @{ script = $extractedDropper; expectedMarker = (Join-Path $Paths.MayaCache 'maya_session.dat') }
    Add-BengalManifestEntry -Type 'registry' -Path 'HKCU:\Software\BengalSEOSim\LastCanaryExecution' -Action 'created-by-inert-jscript' -Details @{ persistence = $false }

    Write-BengalPhaseMarker -Phase '02-PayloadDelivery' -Description 'ZIP download artifact, EXE-masquerading JavaScript, extraction, and real wscript.exe execution.'
}
