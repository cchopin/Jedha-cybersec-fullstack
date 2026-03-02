# ============================================
# SCRIPT 03 : Creation des utilisateurs et groupes
# ============================================
# Ce script cree :
# - 6 utilisateurs dans leurs OUs respectives
# - 3 groupes globaux (GG_*)
# - 3 groupes domain local (DL_*)
# - Imbrication selon le modele AGDLP
#
# Prerequis : Script 02 execute (OUs creees)
# Executer sur DC1 en tant qu'Administrateur
# ============================================

Import-Module ActiveDirectory

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Creation des utilisateurs et groupes"
Write-Host "==========================================" -ForegroundColor Cyan

$domain = "DC=stellar,DC=local"
$password = ConvertTo-SecureString "Welcome1!" -AsPlainText -Force

# ============================================
# PARTIE 1 : Creation des utilisateurs
# ============================================
Write-Host "`n[1/4] Creation des utilisateurs..." -ForegroundColor Yellow

# --- Engineering ---
$engPath = "OU=Engineering,OU=Stellar Teams,$domain"
$engineeringUsers = @(
    @{ Name = "anakin";  DisplayName = "Anakin Skywalker" },
    @{ Name = "ahsoka";  DisplayName = "Ahsoka Tano" },
    @{ Name = "obiwan";  DisplayName = "Obi-Wan Kenobi" }
)

foreach ($user in $engineeringUsers) {
    try {
        New-ADUser `
            -Name $user.DisplayName `
            -SamAccountName $user.Name `
            -UserPrincipalName "$($user.Name)@stellar.local" `
            -DisplayName $user.DisplayName `
            -Path $engPath `
            -AccountPassword $password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false
        Write-Host "  + Utilisateur cree : $($user.Name) (Engineering)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Utilisateur existe deja : $($user.Name)" -ForegroundColor DarkYellow
    }
}

# --- Marketing ---
$mktPath = "OU=Marketing,OU=Stellar Teams,$domain"
$marketingUsers = @(
    @{ Name = "padme"; DisplayName = "Padme Amidala" },
    @{ Name = "leia";  DisplayName = "Leia Organa" }
)

foreach ($user in $marketingUsers) {
    try {
        New-ADUser `
            -Name $user.DisplayName `
            -SamAccountName $user.Name `
            -UserPrincipalName "$($user.Name)@stellar.local" `
            -DisplayName $user.DisplayName `
            -Path $mktPath `
            -AccountPassword $password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false
        Write-Host "  + Utilisateur cree : $($user.Name) (Marketing)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Utilisateur existe deja : $($user.Name)" -ForegroundColor DarkYellow
    }
}

# --- HR ---
$hrPath = "OU=HR,OU=Stellar Teams,$domain"
$hrUsers = @(
    @{ Name = "monmothma"; DisplayName = "Mon Mothma" }
)

foreach ($user in $hrUsers) {
    try {
        New-ADUser `
            -Name $user.DisplayName `
            -SamAccountName $user.Name `
            -UserPrincipalName "$($user.Name)@stellar.local" `
            -DisplayName $user.DisplayName `
            -Path $hrPath `
            -AccountPassword $password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ChangePasswordAtLogon $false
        Write-Host "  + Utilisateur cree : $($user.Name) (HR)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Utilisateur existe deja : $($user.Name)" -ForegroundColor DarkYellow
    }
}

# ============================================
# PARTIE 2 : Creation des groupes globaux
# ============================================
Write-Host "`n[2/4] Creation des groupes globaux..." -ForegroundColor Yellow

$groupsPath = "OU=Groups,$domain"

$globalGroups = @(
    @{ Name = "GG_Engineering_Read"; Description = "Global Group - Engineering Read Access" },
    @{ Name = "GG_Marketing_Read";   Description = "Global Group - Marketing Read Access" },
    @{ Name = "GG_HR_Read";          Description = "Global Group - HR Read Access" }
)

foreach ($group in $globalGroups) {
    try {
        New-ADGroup `
            -Name $group.Name `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $groupsPath `
            -Description $group.Description
        Write-Host "  + Groupe global cree : $($group.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Groupe existe deja : $($group.Name)" -ForegroundColor DarkYellow
    }
}

# ============================================
# PARTIE 3 : Creation des groupes domain local
# ============================================
Write-Host "`n[3/4] Creation des groupes domain local..." -ForegroundColor Yellow

$domainLocalGroups = @(
    @{ Name = "DL_Share_Engineering"; Description = "Domain Local - Share Engineering Access" },
    @{ Name = "DL_Share_Marketing";   Description = "Domain Local - Share Marketing Access" },
    @{ Name = "DL_Share_HR";          Description = "Domain Local - Share HR Access" }
)

foreach ($group in $domainLocalGroups) {
    try {
        New-ADGroup `
            -Name $group.Name `
            -GroupScope DomainLocal `
            -GroupCategory Security `
            -Path $groupsPath `
            -Description $group.Description
        Write-Host "  + Groupe domain local cree : $($group.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Groupe existe deja : $($group.Name)" -ForegroundColor DarkYellow
    }
}

# ============================================
# PARTIE 4 : Imbrication AGDLP
# ============================================
Write-Host "`n[4/4] Imbrication AGDLP..." -ForegroundColor Yellow

# Ajouter les utilisateurs aux groupes globaux
Write-Host "  Ajout des utilisateurs aux groupes globaux..." -ForegroundColor Cyan
Add-ADGroupMember -Identity "GG_Engineering_Read" -Members "anakin", "ahsoka", "obiwan"
Write-Host "    + anakin, ahsoka, obiwan -> GG_Engineering_Read" -ForegroundColor Green

Add-ADGroupMember -Identity "GG_Marketing_Read" -Members "padme", "leia"
Write-Host "    + padme, leia -> GG_Marketing_Read" -ForegroundColor Green

Add-ADGroupMember -Identity "GG_HR_Read" -Members "monmothma"
Write-Host "    + monmothma -> GG_HR_Read" -ForegroundColor Green

# Imbriquer les groupes globaux dans les groupes domain local
Write-Host "  Imbrication GG dans DL..." -ForegroundColor Cyan
Add-ADGroupMember -Identity "DL_Share_Engineering" -Members "GG_Engineering_Read"
Write-Host "    + GG_Engineering_Read -> DL_Share_Engineering" -ForegroundColor Green

Add-ADGroupMember -Identity "DL_Share_Marketing" -Members "GG_Marketing_Read"
Write-Host "    + GG_Marketing_Read -> DL_Share_Marketing" -ForegroundColor Green

Add-ADGroupMember -Identity "DL_Share_HR" -Members "GG_HR_Read"
Write-Host "    + GG_HR_Read -> DL_Share_HR" -ForegroundColor Green

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification"
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`nUtilisateurs :" -ForegroundColor Yellow
Get-ADUser -Filter * -SearchBase "OU=Stellar Teams,$domain" -Properties DisplayName |
    Select-Object SamAccountName, DisplayName, DistinguishedName |
    Format-Table -AutoSize

Write-Host "Groupes :" -ForegroundColor Yellow
Get-ADGroup -Filter * -SearchBase "OU=Groups,$domain" |
    Select-Object Name, GroupScope |
    Format-Table -AutoSize

Write-Host "Membres de DL_Share_Engineering :" -ForegroundColor Yellow
Get-ADGroupMember -Identity "DL_Share_Engineering" | Select-Object Name | Format-Table -AutoSize

Write-Host "Utilisateurs et groupes crees avec succes !" -ForegroundColor Green
