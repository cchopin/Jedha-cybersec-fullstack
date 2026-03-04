# ============================================
# SCRIPT 08 : Verification complete du Lab 34
# ============================================
# Ce script verifie toutes les composantes du lab :
# 1. DNS (internal.stellar.local)
# 2. Web Server (IIS accessible)
# 3. Groupe VPN_Users
# 4. Service VPN (RRAS)
# 5. GPOs Intranet
# 6. HTTPS (bonus)
#
# Prerequis : Executer sur DC1
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " VERIFICATION COMPLETE - Lab 34"
Write-Host " Portail Interne StellarTech"
Write-Host "==========================================" -ForegroundColor Cyan

$passed = 0
$failed = 0
$total = 0

function Test-Check {
    param(
        [string]$Name,
        [bool]$Result,
        [string]$Details = ""
    )
    $script:total++
    if ($Result) {
        $script:passed++
        Write-Host "  [OK] $Name" -ForegroundColor Green
        if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }
    } else {
        $script:failed++
        Write-Host "  [KO] $Name" -ForegroundColor Red
        if ($Details) { Write-Host "       $Details" -ForegroundColor Yellow }
    }
}

# ============================================
# 1. VERIFICATION DNS
# ============================================
Write-Host "`n--- DNS ---" -ForegroundColor Cyan

# Test 1 : Enregistrement A pour internal.stellar.local
$dnsRecord = $null
try {
    $dnsRecord = Resolve-DnsName -Name "internal.stellar.local" -Type A -ErrorAction Stop
    Test-Check "Enregistrement DNS internal.stellar.local" $true "IP: $($dnsRecord.IPAddress)"
} catch {
    Test-Check "Enregistrement DNS internal.stellar.local" $false "Enregistrement non trouve"
}

# Test 2 : IP pointe vers SRV1
if ($dnsRecord) {
    Test-Check "DNS pointe vers SRV1 (10.0.0.20)" ($dnsRecord.IPAddress -eq "10.0.0.20") "IP actuelle: $($dnsRecord.IPAddress)"
} else {
    Test-Check "DNS pointe vers SRV1 (10.0.0.20)" $false "DNS non resolu"
}

# ============================================
# 2. VERIFICATION WEB SERVER
# ============================================
Write-Host "`n--- Web Server (IIS) ---" -ForegroundColor Cyan

# Test 3 : Connectivite vers SRV1 port 80
$webTest = Test-NetConnection -ComputerName "10.0.0.20" -Port 80 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Test-Check "SRV1 accessible sur le port 80" ($webTest.TcpTestSucceeded -eq $true) ""

# Test 4 : Site web accessible via HTTP
try {
    $webResponse = Invoke-WebRequest -Uri "http://internal.stellar.local" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Test-Check "Site http://internal.stellar.local accessible" $true "HTTP $($webResponse.StatusCode)"

    # Test 5 : Contenu du site
    $hasTitle = $webResponse.Content -match "StellarTech"
    Test-Check "Le site contient 'StellarTech'" $hasTitle ""
} catch {
    Test-Check "Site http://internal.stellar.local accessible" $false $_.Exception.Message
    Test-Check "Le site contient 'StellarTech'" $false "Site non accessible"
}

# ============================================
# 3. VERIFICATION GROUPE VPN
# ============================================
Write-Host "`n--- Groupe VPN ---" -ForegroundColor Cyan

# Test 6 : Groupe VPN_Users existe
$vpnGroup = Get-ADGroup -Filter "Name -eq 'VPN_Users'" -ErrorAction SilentlyContinue
Test-Check "Groupe VPN_Users existe" ($null -ne $vpnGroup) ""

# Test 7 : Membres du groupe
if ($vpnGroup) {
    $members = (Get-ADGroupMember -Identity "VPN_Users" -ErrorAction SilentlyContinue).SamAccountName
    $expectedMembers = @("anakin", "ahsoka", "obiwan", "padme", "leia", "monmothma")
    $allPresent = $true
    foreach ($m in $expectedMembers) {
        if ($m -notin $members) {
            $allPresent = $false
        }
    }
    Test-Check "6 utilisateurs dans VPN_Users" $allPresent "Membres: $($members -join ', ')"
} else {
    Test-Check "6 utilisateurs dans VPN_Users" $false "Groupe non trouve"
}

# ============================================
# 4. VERIFICATION VPN (RRAS)
# ============================================
Write-Host "`n--- VPN (RRAS) ---" -ForegroundColor Cyan

# Test 8 : Service RRAS sur SRV1
$rrasTest = $null
try {
    $rrasTest = Invoke-Command -ComputerName SRV1 -ScriptBlock {
        Get-Service RemoteAccess -ErrorAction SilentlyContinue
    } -ErrorAction Stop
    Test-Check "Service RRAS sur SRV1" ($rrasTest.Status -eq "Running") "Status: $($rrasTest.Status)"
} catch {
    # Test de connectivite alternative
    $vpnPorts = @(443, 500, 4500)
    $vpnAccessible = $false
    foreach ($port in $vpnPorts) {
        $test = Test-NetConnection -ComputerName "10.0.0.20" -Port $port -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($test.TcpTestSucceeded) {
            $vpnAccessible = $true
            break
        }
    }
    Test-Check "Service RRAS sur SRV1" $vpnAccessible "Test via ports VPN (443/500/4500)"
}

# Test 9 : Ports VPN ouverts
$sslPort = Test-NetConnection -ComputerName "10.0.0.20" -Port 443 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Test-Check "Port SSTP (443) ouvert sur SRV1" ($sslPort.TcpTestSucceeded -eq $true) ""

# ============================================
# 5. VERIFICATION GPOs
# ============================================
Write-Host "`n--- GPOs Intranet ---" -ForegroundColor Cyan

# Test 10 : GPO IntranetShortcutPolicy
$shortcutGPO = Get-GPO -Name "IntranetShortcutPolicy" -ErrorAction SilentlyContinue
Test-Check "GPO IntranetShortcutPolicy existe" ($null -ne $shortcutGPO) ""

# Test 11 : GPO IntranetHomepagePolicy
$homepageGPO = Get-GPO -Name "IntranetHomepagePolicy" -ErrorAction SilentlyContinue
Test-Check "GPO IntranetHomepagePolicy existe" ($null -ne $homepageGPO) ""

# Test 12 : GPOs liees a Stellar Teams
$gpoLinks = (Get-GPInheritance -Target "OU=Stellar Teams,DC=stellar,DC=local" -ErrorAction SilentlyContinue).GpoLinks
$shortcutLinked = $gpoLinks | Where-Object { $_.DisplayName -eq "IntranetShortcutPolicy" }
$homepageLinked = $gpoLinks | Where-Object { $_.DisplayName -eq "IntranetHomepagePolicy" }
Test-Check "IntranetShortcutPolicy liee a Stellar Teams" ($null -ne $shortcutLinked) ""
Test-Check "IntranetHomepagePolicy liee a Stellar Teams" ($null -ne $homepageLinked) ""

# ============================================
# 6. VERIFICATION SCRIPT NETLOGON
# ============================================
Write-Host "`n--- Script NETLOGON ---" -ForegroundColor Cyan

$netlogonScript = Test-Path "C:\Windows\SYSVOL\domain\scripts\create_shortcut.ps1"
Test-Check "Script create_shortcut.ps1 dans NETLOGON" $netlogonScript ""

# ============================================
# 7. VERIFICATION BONUS (HTTPS)
# ============================================
Write-Host "`n--- Bonus ---" -ForegroundColor Cyan

# Test HTTPS
$httpsPort = Test-NetConnection -ComputerName "10.0.0.20" -Port 443 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Test-Check "HTTPS (port 443) accessible sur SRV1" ($httpsPort.TcpTestSucceeded -eq $true) "(bonus)"

# ============================================
# RESUME
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " RESUME" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tests reussis : $passed / $total" -ForegroundColor $(if ($failed -eq 0) { "Green" } elseif ($failed -le 2) { "Yellow" } else { "Red" })
Write-Host "  Tests echoues : $failed / $total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($failed -eq 0) {
    Write-Host "  FELICITATIONS ! Tous les tests sont passes !" -ForegroundColor Green
    Write-Host "  Le portail interne StellarTech est operationnel." -ForegroundColor Green
} elseif ($failed -le 2) {
    Write-Host "  Presque ! Quelques ajustements necessaires." -ForegroundColor Yellow
} else {
    Write-Host "  Plusieurs composants necessitent une configuration." -ForegroundColor Red
    Write-Host "  Consulter SOLUTION.md pour de l'aide." -ForegroundColor Red
}

Write-Host ""
Write-Host "  Test depuis un client VPN :" -ForegroundColor Cyan
Write-Host "    1. Se connecter au VPN (SSTP vers 10.0.0.20)" -ForegroundColor White
Write-Host "    2. nslookup internal.stellar.local" -ForegroundColor White
Write-Host "    3. Ouvrir http://internal.stellar.local dans le navigateur" -ForegroundColor White
Write-Host ""
