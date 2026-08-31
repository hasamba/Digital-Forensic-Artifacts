function Invoke-YouDunPrivilegeImpact{param($Paths)
Write-YouDunFile(Join-Path $Paths.Evidence 'linux-privilege-escalation.json')(@{CDK=@{technique='docker mount-cgroup escape';executed=$false;containerAccessed=$false};traitor=@{filename='traitor-amd64';uploaded=$false;executed=$false};hostPrivilegeChanged=$false}|ConvertTo-Json -Depth 5) 'CDK and traitor non-execution record'
$lb=Join-Path $Paths.OpenDirectory '.local\LB3.exe';New-YouDunDecoy $lb 'LockBit 3 leaked-builder output name canary' '07104f9be906e62be7539e4f81d980dddb480d64dce204c199a2afe5a0bc3367';Invoke-YouDunDecoy $lb 'LB3.exe --custom-note You_Dun (actual echo-only signed decoy)'
foreach($n in @('government.docx','health-records.csv','logistics.xlsx')){Write-YouDunFile(Join-Path $Paths.Impact $n)"Generated intact source: $n" 'generated original';Write-YouDunFile(Join-Path $Paths.Impact "$n.LOCKBIT-YOUDUN-CANARY")'Marker only; no encryption; paired original intact.' 'non-encrypted impact marker'}
Write-YouDunFile(Join-Path $Paths.Impact 'README-YOU_DUN-CANARY.txt')@'
YOU DUN / LOCKBIT FORENSIC CANARY
The report's analyzed sample referenced the public Telegram group You_Dun and administrator EVA.
No clickable contact, payment information, encryption, or data destruction is included.
'@ 'inert custom ransom-note canary';Write-YouDunFile(Join-Path $Paths.Evidence 'impact.json')(@{reportedBinary='.local/LB3.exe';builder='leaked LockBit 3 builder';telegramReferences=@('You_Dun','You_Dun888','juxingchuhai');administrator='EVA / @YD099';ransomwareExecuted=$false;encryption=$false;userFilesTouched=$false}|ConvertTo-Json -Depth 5) 'LockBit/adversary metadata'
Add-YouDunTimeline 'Privilege Escalation/Impact' 'CDK/traitor and custom LockBit builder output were represented with negative execution assertions and generated impact markers.' @{containerEscape=$false;privilegeChange=$false;encryption=$false}}
