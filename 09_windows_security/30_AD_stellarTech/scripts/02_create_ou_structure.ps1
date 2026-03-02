# ============================================
# SCRIPT 02 : Creation de la structure OUs
# ============================================
# Ce script cree la structure d'unites organisationnelles :
#
# stellar.local
# ├── Stellar Teams
# │   ├── Engineering
# │   ├── Marketing
# │   └── HR
# ├── Servers
# ├── Groups
# └── Policies
#
# Prerequis : DC1 promu et redemarrage termine
# Executer sur DC1 en tant qu'Administrateur
# ============================================

Import-Module ActiveDirectory

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Creation de la structure OUs"
Write-Host "==========================================" -ForegroundColor Cyan

$domain = "DC=stellar,DC=local"

# ============================================
# PARTIE 1 : OUs racine
# ============================================
Write-Host "`n[1/2] Creation des OUs racine..." -ForegroundColor Yellow

$rootOUs = @("Stellar Teams", "Servers", "Groups", "Policies")

foreach ($ou in $rootOUs) {
    try {
        New-ADOrganizationalUnit -Name $ou -Path $domain -ProtectedFromAccidentalDeletion $true
        Write-Host "  + OU creee : $ou" -ForegroundColor Green
    } catch {
        Write-Host "  ~ OU existe deja : $ou" -ForegroundColor DarkYellow
    }
}

# ============================================
# PARTIE 2 : Sous-OUs (departements)
# ============================================
Write-Host "`n[2/2] Creation des sous-OUs (departements)..." -ForegroundColor Yellow

$stellarTeamsPath = "OU=Stellar Teams,$domain"
$departments = @("Engineering", "Marketing", "HR")

foreach ($dept in $departments) {
    try {
        New-ADOrganizationalUnit -Name $dept -Path $stellarTeamsPath -ProtectedFromAccidentalDeletion $true
        Write-Host "  + Sous-OU creee : Stellar Teams\$dept" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Sous-OU existe deja : Stellar Teams\$dept" -ForegroundColor DarkYellow
    }
}

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification de la structure OUs"
Write-Host "==========================================" -ForegroundColor Cyan

Get-ADOrganizationalUnit -Filter * -SearchBase $domain |
    Select-Object Name, DistinguishedName |
    Format-Table -AutoSize

Write-Host "Structure OUs creee avec succes !" -ForegroundColor Green
