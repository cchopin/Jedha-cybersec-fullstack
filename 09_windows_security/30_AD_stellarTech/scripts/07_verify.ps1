# ============================================
# SCRIPT 07 : Verification complete du lab
# ============================================
# Ce script verifie tous les elements du lab :
# 1. Domaine AD operationnel
# 2. Structure OUs
# 3. Utilisateurs et groupes
# 4. Imbrication AGDLP
# 5. Controleurs de domaine
# 6. Partages reseau
# 7. GPOs
#
# Executer sur DC1 en tant qu'Administrateur
# ============================================

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = "DC=stellar,DC=local"
$passed = 0
$failed = 0
$total = 0

function Test-Check {
    param(
        [string]$Description,
        [bool]$Result
    )
    $script:total++
    if ($Result) {
        Write-Host "  [OK] $Description" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "  [KO] $Description" -ForegroundColor Red
        $script:failed++
    }
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " VERIFICATION COMPLETE - Lab StellarTech"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# 1. DOMAINE AD
# ============================================
Write-Host "`n--- 1. Domaine Active Directory ---" -ForegroundColor Yellow

$domainInfo = Get-ADDomain -ErrorAction SilentlyContinue
Test-Check "Domaine stellar.local operationnel" ($domainInfo.DNSRoot -eq "stellar.local")
Test-Check "Nom NetBIOS = STELLAR" ($domainInfo.NetBIOSName -eq "STELLAR")

$forestInfo = Get-ADForest -ErrorAction SilentlyContinue
Test-Check "Foret stellar.local" ($forestInfo.Name -eq "stellar.local")

# ============================================
# 2. STRUCTURE OUs
# ============================================
Write-Host "`n--- 2. Structure OUs ---" -ForegroundColor Yellow

$ous = Get-ADOrganizationalUnit -Filter * -SearchBase $domain | Select-Object -ExpandProperty Name

Test-Check "OU 'Stellar Teams' existe" ($ous -contains "Stellar Teams")
Test-Check "OU 'Engineering' existe" ($ous -contains "Engineering")
Test-Check "OU 'Marketing' existe" ($ous -contains "Marketing")
Test-Check "OU 'HR' existe" ($ous -contains "HR")
Test-Check "OU 'Servers' existe" ($ous -contains "Servers")
Test-Check "OU 'Groups' existe" ($ous -contains "Groups")
Test-Check "OU 'Policies' existe" ($ous -contains "Policies")

# Verifier la hierarchie
$engOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Engineering'" -ErrorAction SilentlyContinue
Test-Check "Engineering est sous Stellar Teams" ($engOU.DistinguishedName -like "*OU=Stellar Teams*")

# ============================================
# 3. UTILISATEURS
# ============================================
Write-Host "`n--- 3. Utilisateurs ---" -ForegroundColor Yellow

$expectedUsers = @("anakin", "ahsoka", "obiwan", "padme", "leia", "monmothma")
foreach ($user in $expectedUsers) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
    Test-Check "Utilisateur '$user' existe" ($null -ne $adUser)
}

# Verifier le placement dans les bonnes OUs
$anakin = Get-ADUser -Filter "SamAccountName -eq 'anakin'" -ErrorAction SilentlyContinue
Test-Check "anakin dans OU Engineering" ($anakin.DistinguishedName -like "*OU=Engineering*")

$padme = Get-ADUser -Filter "SamAccountName -eq 'padme'" -ErrorAction SilentlyContinue
Test-Check "padme dans OU Marketing" ($padme.DistinguishedName -like "*OU=Marketing*")

$monmothma = Get-ADUser -Filter "SamAccountName -eq 'monmothma'" -ErrorAction SilentlyContinue
Test-Check "monmothma dans OU HR" ($monmothma.DistinguishedName -like "*OU=HR*")

# ============================================
# 4. GROUPES ET AGDLP
# ============================================
Write-Host "`n--- 4. Groupes et AGDLP ---" -ForegroundColor Yellow

# Groupes globaux
$ggEng = Get-ADGroup -Filter "Name -eq 'GG_Engineering_Read'" -ErrorAction SilentlyContinue
Test-Check "Groupe GG_Engineering_Read existe (Global)" (($null -ne $ggEng) -and ($ggEng.GroupScope -eq "Global"))

$ggMkt = Get-ADGroup -Filter "Name -eq 'GG_Marketing_Read'" -ErrorAction SilentlyContinue
Test-Check "Groupe GG_Marketing_Read existe (Global)" (($null -ne $ggMkt) -and ($ggMkt.GroupScope -eq "Global"))

$ggHR = Get-ADGroup -Filter "Name -eq 'GG_HR_Read'" -ErrorAction SilentlyContinue
Test-Check "Groupe GG_HR_Read existe (Global)" (($null -ne $ggHR) -and ($ggHR.GroupScope -eq "Global"))

# Groupes domain local
$dlEng = Get-ADGroup -Filter "Name -eq 'DL_Share_Engineering'" -ErrorAction SilentlyContinue
Test-Check "Groupe DL_Share_Engineering existe (DomainLocal)" (($null -ne $dlEng) -and ($dlEng.GroupScope -eq "DomainLocal"))

$dlMkt = Get-ADGroup -Filter "Name -eq 'DL_Share_Marketing'" -ErrorAction SilentlyContinue
Test-Check "Groupe DL_Share_Marketing existe (DomainLocal)" (($null -ne $dlMkt) -and ($dlMkt.GroupScope -eq "DomainLocal"))

$dlHR = Get-ADGroup -Filter "Name -eq 'DL_Share_HR'" -ErrorAction SilentlyContinue
Test-Check "Groupe DL_Share_HR existe (DomainLocal)" (($null -ne $dlHR) -and ($dlHR.GroupScope -eq "DomainLocal"))

# Imbrication AGDLP
$dlEngMembers = Get-ADGroupMember -Identity "DL_Share_Engineering" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
Test-Check "GG_Engineering_Read dans DL_Share_Engineering" ($dlEngMembers -contains "GG_Engineering_Read")

$ggEngMembers = Get-ADGroupMember -Identity "GG_Engineering_Read" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
Test-Check "anakin dans GG_Engineering_Read" ($ggEngMembers -contains "anakin")
Test-Check "ahsoka dans GG_Engineering_Read" ($ggEngMembers -contains "ahsoka")
Test-Check "obiwan dans GG_Engineering_Read" ($ggEngMembers -contains "obiwan")

# ============================================
# 5. CONTROLEURS DE DOMAINE
# ============================================
Write-Host "`n--- 5. Controleurs de domaine ---" -ForegroundColor Yellow

$dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
$dcNames = $dcs | Select-Object -ExpandProperty Name

Test-Check "DC1 est un controleur de domaine" ($dcNames -contains "DC1")
Test-Check "DC2 est un controleur de domaine" ($dcNames -contains "DC2")

# Verifier RODC
$dc2Info = $dcs | Where-Object { $_.Name -eq "DC2" }
if ($dc2Info) {
    Test-Check "DC2 est un RODC (Read-Only)" ($dc2Info.IsReadOnly -eq $true)
    Test-Check "DC2 est Global Catalog" ($dc2Info.IsGlobalCatalog -eq $true)
} else {
    Test-Check "DC2 est un RODC (Read-Only)" $false
    Test-Check "DC2 est Global Catalog" $false
}

# ============================================
# 6. GPOs
# ============================================
Write-Host "`n--- 6. Strategies de groupe (GPO) ---" -ForegroundColor Yellow

$gpos = Get-GPO -All | Select-Object -ExpandProperty DisplayName

Test-Check "GPO WallpaperPolicy existe" ($gpos -contains "WallpaperPolicy")
Test-Check "GPO SecurityPolicy existe" ($gpos -contains "SecurityPolicy")

# Verifier les liens GPO
$stellarLinks = (Get-GPInheritance -Target "OU=Stellar Teams,$domain" -ErrorAction SilentlyContinue).GpoLinks | Select-Object -ExpandProperty DisplayName
Test-Check "WallpaperPolicy liee a Stellar Teams" ($stellarLinks -contains "WallpaperPolicy")
Test-Check "SecurityPolicy liee a Stellar Teams" ($stellarLinks -contains "SecurityPolicy")

# Verifier la politique de mots de passe
$pwPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
Test-Check "Longueur min. mot de passe >= 8" ($pwPolicy.MinPasswordLength -ge 8)
Test-Check "Verrouillage apres 5 tentatives" ($pwPolicy.LockoutThreshold -eq 5)

# ============================================
# 7. PARTAGES (test depuis DC1)
# ============================================
Write-Host "`n--- 7. Partages reseau ---" -ForegroundColor Yellow

$sharePaths = @("\\SRV1\share_engineering", "\\SRV1\share_marketing", "\\SRV1\share_hr")
foreach ($path in $sharePaths) {
    $accessible = Test-Path $path -ErrorAction SilentlyContinue
    Test-Check "Partage accessible : $path" $accessible
}

$wallpaperPath = "\\SRV1\shared_wallpaper"
$wpAccessible = Test-Path $wallpaperPath -ErrorAction SilentlyContinue
Test-Check "Partage accessible : $wallpaperPath" $wpAccessible

# ============================================
# RESUME
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " RESUME DE LA VERIFICATION"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tests reussis : $passed / $total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "  Tests echoues : $failed / $total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($failed -eq 0) {
    Write-Host "  TOUS LES TESTS SONT PASSES !" -ForegroundColor Green
    Write-Host "  Felicitations, votre lab StellarTech est complet !" -ForegroundColor Green
} else {
    Write-Host "  Certains tests ont echoue." -ForegroundColor Yellow
    Write-Host "  Verifiez les elements marques [KO] ci-dessus." -ForegroundColor Yellow
    Write-Host "  Consultez SOLUTION.md pour obtenir de l'aide." -ForegroundColor Yellow
}
