# ============================================================================
# AKIRA SIMULATION - PHASE 8: COLLECTION
# ============================================================================
# Simulates the automated collection sweep the threat actor ran across
# credential stores, browser data, cloud CLI configs, password managers,
# dev source trees, and remote-access tool configs (mirrors the exact
# directory list from the report's Event ID 5145 analysis).
# MITRE: T1005 Data from Local System, T1552.001 Credentials In Files,
#        T1539 Steal Web Session Cookie
# ============================================================================

function Simulate-Collection {
    param($SimPaths)

    Write-Host "[+] Phase 8: Collection ..." -ForegroundColor Green

    $base = "$env:USERPROFILE"
    $targets = @(
        "$base\AppData\Roaming\Microsoft\Protect",
        "$base\AppData\Roaming\Microsoft\Crypto\RSA",
        "$base\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates",
        "$base\AppData\Local\Microsoft\Credentials",
        "$base\AppData\Roaming\Microsoft\Credentials",
        "$base\AppData\Local\Google\Chrome\User Data",
        "$base\AppData\Local\Microsoft\Edge\User Data",
        "$base\AppData\Local\BraveSoftware\Brave-Browser\User Data",
        "$base\AppData\Roaming\Mozilla\Firefox\Profiles",
        "$base\.aws",
        "$base\AppData\Roaming\gcloud",
        "$base\AppData\Roaming\Windows Azure Powershell",
        "$base\.azure",
        "$base\AppData\Local\1Password",
        "$base\AppData\Local\LastPass",
        "$base\AppData\Local\KeePass",
        "$base\AppData\Roaming\Dashlane",
        "$base\AppData\Local\Bitwarden",
        "$base\AppData\Local\RoboForm",
        "$base\AppData\Local\StickyPassword",
        "$base\AppData\Local\NordPass",
        "$base\AppData\Local\Enpass",
        "$base\source\repos",
        "$base\workspace",
        "$base\IdeaProjects",
        "$base\PycharmProjects",
        "$base\AndroidStudioProjects",
        "$base\Documents\NetBeansProjects",
        "$base\Documents\Xcode",
        "$base\CLionProjects",
        "$base\RubyMineProjects",
        "$base\Documents\Qt",
        "$base\Documents\CodeBlocks",
        "$base\RiderProjects",
        "$base\PhpStormProjects",
        "$base\AppData\Local\mRemoteNG",
        "$base\AppData\Roaming\mRemoteNG",
        "$base\AppData\Roaming\Notepad++\backup"
    )

    $accessLog = "$($SimPaths.Logs)\collection_5145_sim.log"
    foreach ($t in $targets) {
        # Test-Path against every path generates the same enumeration footprint
        # as the real intrusion's SMB share-access attempts (Event ID 5145 fires
        # on access attempts regardless of whether the target exists).
        $exists = Test-Path -Path $t
        Add-Content -Path $accessLog -Value "$(Get-Date -Format o) ACCESS_ATTEMPT `"$t`" exists=$exists"
    }
    Write-SimEvent -EventId 8001 -Message "SIMULATION: Automated collection sweep enumerated $($targets.Count) credential/config/dev directories (Event ID 5145 pattern)"

    # --- Stage plausible "collected" victim data for the later exfil phase ---
    $victimFiles = @(
        @{ Name = "Q3_Financial_Report.xlsx"; Content = "Simulated financial data and projections" },
        @{ Name = "Employee_Directory.csv"; Content = "Simulated employee contact/credential data" },
        @{ Name = "SYSVOL_GPO_backup.zip"; Content = "Simulated Group Policy / SYSVOL export" },
        @{ Name = "network_credentials.txt"; Content = "Simulated harvested credential dump" }
    )
    foreach ($f in $victimFiles) {
        Set-Content -Path "$($SimPaths.VictimFiles)\$($f.Name)" -Value $f.Content -Force
    }

    Write-Host "  [OK] Collection artifacts created" -ForegroundColor Yellow
}
