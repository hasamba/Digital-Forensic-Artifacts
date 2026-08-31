#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]param([switch]$LabConfirmed)
. "$PSScriptRoot\PhosphorusSim-utilities.ps1"
Assert-PhosphorusSimSafety -LabConfirmed:$LabConfirmed
$paths = Initialize-PhosphorusSimEnvironment

$management = @(
    'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "administrator@<REDACTED>"',
    'New-MailboxExportRequest -ContentFilter {Subject -eq "aspx_wkggiyvttmu"} -FilePath "\\localhost\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth\aspx_wkggiyvttmu.aspx"',
    'Remove-MailboxExportRequest -Identity "77a883a7-470c-471c-a193-f4c54f263fde"'
)
Write-PhosphorusSimFile (Join-Path $paths.Exchange 'proxyshell-request-sequence.json') (@{
    userAgents = @('python-requests/2.26.0', 'python-urllib3/1.26.7')
    vulnerabilities = @('CVE-2021-34473', 'CVE-2021-34523', 'CVE-2021-31207')
    exchangeCommands = $management
    exchangeCommandsExecuted = 0
    mailboxesAccessed = 0
    mailboxesExported = 0
} | ConvertTo-Json -Depth 6) 'reported ProxyShell/Exchange request sequence'

$shellOne = Join-Path $paths.Exchange 'aspx_wkggiyvttmu.aspx'
Write-PhosphorusSimFile $shellOne '<%-- INERT WEB-SHELL-NAME CANARY. Contains no executable server code. --%>' 'first web shell name canary'
Write-PhosphorusSimFile (Join-Path $paths.Exchange 'webshell-posts-first-burst.json') (@{
    delayAfterCreationSeconds = 20
    durationMinutes = 2
    parameters = @('delimiter', 'exec_code', 'get + dst', 'put + dst', 'run')
    behavior = 'reported only; no HTTP server, command handler, upload, or download capability'
} | ConvertTo-Json -Depth 5) 'reported web shell POST behavior'

$dllhost = Join-Path $paths.Windows 'dllhost.exe'
New-PhosphorusSimDecoy $dllhost 'modified-Go-FRP stand-in' '1604e69d17c0f26182a3e3ff65694a49450aafd56a7e8b21697a932409dfd81e'
Invoke-PhosphorusSimDecoy $dllhost 'C:\Windows\dllhost.exe (modified Golang FRP client)' 'w3wp.exe'
Invoke-PhosphorusSimLoopback 80 '148.251.71.182/update.tmp' 'reported HTTP tool transfer'
Invoke-PhosphorusSimLoopback 443 'api.myip.com' 'reported public-IP discovery'
Invoke-PhosphorusSimLoopback 443 'tcp443.msupdate.us / 107.173.231.114' 'reported FRP C2'
Invoke-PhosphorusSimLoopback 53 'kcp53.msupdate.us / 107.173.231.114' 'reported KCP C2'

Write-PhosphorusSimFile (Join-Path $paths.Evidence 'first-burst-negative-record.json') (@{
    proxyShellRequestsSent = 0
    exchangeCmdletsInvoked = 0
    webShellsDeployed = 0
    executablesDownloaded = 0
    malwareExecuted = $false
    remoteConnections = 0
    bytesTransferred = 0
} | ConvertTo-Json) 'phase safety record'
Add-PhosphorusSimTimeline 0 'initial-access' 'First automated ProxyShell chain and Exchange role/export mechanics represented' @{ durationMinutes = 2; exploitRequestsSent = 0; exchangeOperations = 0 }
Add-PhosphorusSimTimeline 0.0056 'persistence' 'First web shell POST burst begins about twenty seconds after shell creation' @{ webShellsCreated = 0; commandsHandled = 0 }
Add-PhosphorusSimTimeline 0.02 'command-and-control' 'Fake dllhost FRP and update traffic represented through loopback-only attempts' @{ remoteConnections = 0; bytesTransferred = 0 }
