# ============================================
# SCRIPT 02 : Creation du groupe VPN_Users
# ============================================
# Ce script :
# 1. Cree le groupe de securite VPN_Users dans l'OU Groups
# 2. Ajoute tous les utilisateurs au groupe
# 3. Configure les permissions d'acces distant pour les membres
#
# Prerequis : Executer sur DC1 (Lab 30 configure)
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Creation du groupe VPN_Users"
Write-Host "==========================================" -ForegroundColor Cyan

Import-Module ActiveDirectory

$domain = "DC=stellar,DC=local"
$groupsPath = "OU=Groups,$domain"

# ============================================
# PARTIE 1 : Creer le groupe VPN_Users
# ============================================
Write-Host "`n[1/3] Creation du groupe VPN_Users..." -ForegroundColor Yellow

# Verifier si le groupe existe deja
$existingGroup = Get-ADGroup -Filter "Name -eq 'VPN_Users'" -ErrorAction SilentlyContinue

if ($existingGroup) {
    Write-Host "  Le groupe VPN_Users existe deja" -ForegroundColor Green
} else {
    New-ADGroup -Name "VPN_Users" `
        -SamAccountName "VPN_Users" `
        -GroupScope Global `
        -GroupCategory Security `
        -Path $groupsPath `
        -Description "Utilisateurs autorises a se connecter via VPN"

    Write-Host "  Groupe VPN_Users cree dans $groupsPath" -ForegroundColor Green
}

# ============================================
# PARTIE 2 : Ajouter les utilisateurs
# ============================================
Write-Host "`n[2/3] Ajout des utilisateurs au groupe VPN_Users..." -ForegroundColor Yellow

$vpnMembers = @("anakin", "ahsoka", "obiwan", "padme", "leia", "monmothma")

foreach ($user in $vpnMembers) {
    try {
        Add-ADGroupMember -Identity "VPN_Users" -Members $user -ErrorAction Stop
        Write-Host "  + $user ajoute" -ForegroundColor Green
    } catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Host "  = $user est deja membre" -ForegroundColor Yellow
    } catch {
        Write-Host "  ! Erreur pour $user : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# PARTIE 3 : Configurer l'acces distant
# ============================================
Write-Host "`n[3/3] Configuration de l'acces distant pour les utilisateurs..." -ForegroundColor Yellow

# Autoriser l'acces distant via NPS (Network Policy Server)
# On configure le dial-in sur "Control access through NPS Network Policy"
foreach ($user in $vpnMembers) {
    try {
        # Definir msNPAllowDialin a TRUE (autoriser via NPS)
        Set-ADUser -Identity $user -Replace @{
            "msNPAllowDialin" = $true
        } -ErrorAction SilentlyContinue
        Write-Host "  Acces distant configure pour $user" -ForegroundColor Green
    } catch {
        # Si l'attribut n'existe pas, configurer via ADUC
        Write-Host "  Note : Configurer l'acces distant pour $user via ADUC ou NPS" -ForegroundColor Yellow
    }
}

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$members = Get-ADGroupMember -Identity "VPN_Users" | Select-Object SamAccountName
Write-Host "  Membres du groupe VPN_Users :" -ForegroundColor White
$members | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)" -ForegroundColor White
}
Write-Host "  Total : $($members.Count) membres" -ForegroundColor Green

Write-Host "`n  Prochaine etape : Executer 03_create_dns_record.ps1 sur DC1" -ForegroundColor Yellow
