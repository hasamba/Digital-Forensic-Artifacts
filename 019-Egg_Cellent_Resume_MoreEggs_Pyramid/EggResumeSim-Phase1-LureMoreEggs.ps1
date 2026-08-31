function Invoke-EggLureMoreEggs{param($Paths);$t=Get-EggTime
$dl=Join-Path $Paths.User 'Downloads';Write-EggFile(Join-Path $dl 'John Shimkus.zip')'PK EGG-CANARY resume archive; no executable archive content' 'resume-lure ZIP canary' $t.Initial;Write-EggFile(Join-Path $dl 'John-_Shimkus.lnk')'EGG-CANARY shortcut metadata; no Shell Link execution data' 'LNK filename canary' $t.Initial;Write-EggFile(Join-Path $dl '2.jpg')'JPEG padding canary' 'unused ZIP padding filename' $t.Initial
Write-EggFile(Join-Path $Paths.User 'AppData\Roaming\Microsoft\ieuinit.inf')@'
[version]
signature="$windows nt$"
[strings]
Questions=com
; EGG CANARY: remote SCT and COM registration removed
'@ 'inert ie4uinit INF canary' $t.Initial
$ie=Join-Path $Paths.User 'AppData\Roaming\Microsoft\ie4uinit.exe';New-EggDecoy $ie 'ie4uinit LOLBin process-name canary';Invoke-EggDecoy $ie 'ie4uinit.exe -basesettings -> http://a92837f.johnshimkus.com/setthevar (actual loopback)';Invoke-EggLoopback 80 'a92837f.johnshimkus.com/setthevar'
foreach($f in @('20350.dll','16304.dll')){Write-EggFile(Join-Path $Paths.User "AppData\Roaming\Microsoft\$f")"MZ EGG inert more_eggs DLL: $f" 'more_eggs DLL filename canary' $t.MoreEggs};foreach($f in @('51D7701F6EB775C7.txt','29D88F75006BE8A.txt','178F2E426.txt')){Write-EggFile(Join-Path $Paths.ProgramData "Microsoft\$f")"EGG CANARY text/XML/JScript stage $f; script removed" 'more_eggs text stage' $t.MoreEggs}
$msxsl=Join-Path $Paths.ProgramData 'Microsoft\msxsl.exe';New-EggDecoy $msxsl 'msxsl LOLBin process-name canary';Invoke-EggDecoy $msxsl 'msxsl.exe 29D88F75006BE8A.txt 29D88F75006BE8A.txt';Write-EggFile(Join-Path $Paths.Evidence 'more-eggs-task.json')(@{task='8766714F94DD';trigger='Boot';xml='51D7701F6EB775C7.txt';action='msxsl more_eggs text';created=$false}|ConvertTo-Json) 'scheduled task canary' $t.MoreEggs
$typeperf=Join-Path $env:SystemRoot 'System32\cmd.exe';1..20|%{Invoke-EggDecoy $typeperf 'typeperf.exe "\System\Processor Queue Length" -si 180 -sc 1'}
foreach($c in @('nltest /trusted_domains','net group /domain "Domain Admins"','whoami /upn')){Invoke-EggDecoy $typeperf $c};Invoke-EggLoopback 443 'pin.howasit.com / 108.174.197.15 more_eggs C2'
Add-EggTimeline $t.Initial 'Initial Access/Execution' 'Resume ZIP and LNK initiated inert ie4uinit/INF telemetry.' @{userExecution=$false;reportedDomain='johnshimkus.com';actual='127.0.0.1'};Add-EggTimeline $t.MoreEggs 'Execution/Persistence/C2' 'DLL, XML/JScript text, msxsl, task, typeperf, and more_eggs C2 canaries were staged.' @{taskCreated=$false;scriptExecuted=$false;remoteC2=$false}}
