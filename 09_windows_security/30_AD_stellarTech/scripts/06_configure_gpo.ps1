# ============================================
# SCRIPT 06 : Configuration des GPOs
# ============================================
# Ce script cree et configure les GPOs suivantes :
# 1. WallpaperPolicy - Fond d'ecran corporate
# 2. SecurityPolicy  - Desactive Panneau de config, cmd, registre
# 3. PasswordPolicy  - Politique de mots de passe
# 4. BONUS: DriveMapping - Mappage de lecteurs reseau
#
# Prerequis : DC1 operationnel, SRV1 configure
# Executer sur DC1 en tant qu'Administrateur
# ============================================

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration des strategies de groupe (GPO)"
Write-Host "==========================================" -ForegroundColor Cyan

$domain = "DC=stellar,DC=local"
$stellarTeamsOU = "OU=Stellar Teams,$domain"

# ============================================
# GPO 1 : WallpaperPolicy
# ============================================
Write-Host "`n[1/4] Creation de la GPO WallpaperPolicy..." -ForegroundColor Yellow

try {
    $gpoWallpaper = New-GPO -Name "WallpaperPolicy" -Comment "Definit le fond d'ecran corporate"
    Write-Host "  + GPO creee : WallpaperPolicy" -ForegroundColor Green
} catch {
    $gpoWallpaper = Get-GPO -Name "WallpaperPolicy"
    Write-Host "  ~ GPO existe deja : WallpaperPolicy" -ForegroundColor DarkYellow
}

# Configurer le chemin du wallpaper
Set-GPRegistryValue -Name "WallpaperPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "Wallpaper" `
    -Type String `
    -Value "\\SRV1\shared_wallpaper\wallpaper.jpg"

# Style du wallpaper (2 = Stretch)
Set-GPRegistryValue -Name "WallpaperPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "WallpaperStyle" `
    -Type String `
    -Value "2"

# Empecher le changement de wallpaper
Set-GPRegistryValue -Name "WallpaperPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" `
    -ValueName "NoChangingWallPaper" `
    -Type DWord `
    -Value 1

# Lier la GPO a l'OU Stellar Teams
try {
    New-GPLink -Name "WallpaperPolicy" -Target $stellarTeamsOU
    Write-Host "  + GPO liee a : Stellar Teams" -ForegroundColor Green
} catch {
    Write-Host "  ~ Lien GPO existe deja" -ForegroundColor DarkYellow
}

Write-Host "  Wallpaper : \\SRV1\shared_wallpaper\wallpaper.jpg" -ForegroundColor Cyan

# ============================================
# GPO 2 : SecurityPolicy
# ============================================
Write-Host "`n[2/4] Creation de la GPO SecurityPolicy..." -ForegroundColor Yellow

try {
    $gpoSecurity = New-GPO -Name "SecurityPolicy" -Comment "Restrictions de securite utilisateur"
    Write-Host "  + GPO creee : SecurityPolicy" -ForegroundColor Green
} catch {
    $gpoSecurity = Get-GPO -Name "SecurityPolicy"
    Write-Host "  ~ GPO existe deja : SecurityPolicy" -ForegroundColor DarkYellow
}

# Desactiver le Panneau de configuration
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoControlPanel" `
    -Type DWord `
    -Value 1
Write-Host "  + Panneau de configuration : DESACTIVE" -ForegroundColor Green

# Desactiver l'invite de commandes (cmd)
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
    -ValueName "DisableCMD" `
    -Type DWord `
    -Value 1
Write-Host "  + Invite de commandes (cmd) : DESACTIVE" -ForegroundColor Green

# Desactiver l'acces au registre
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableRegistryTools" `
    -Type DWord `
    -Value 1
Write-Host "  + Editeur du registre : DESACTIVE" -ForegroundColor Green

# Lier la GPO
try {
    New-GPLink -Name "SecurityPolicy" -Target $stellarTeamsOU
    Write-Host "  + GPO liee a : Stellar Teams" -ForegroundColor Green
} catch {
    Write-Host "  ~ Lien GPO existe deja" -ForegroundColor DarkYellow
}

# ============================================
# GPO 3 : PasswordPolicy
# ============================================
Write-Host "`n[3/4] Configuration de la politique de mots de passe..." -ForegroundColor Yellow
Write-Host "  (Modification de la Default Domain Policy)" -ForegroundColor Cyan

# La politique de mots de passe doit etre dans la Default Domain Policy
# On utilise secedit pour configurer les parametres de securite

# Creer un fichier de configuration temporaire
$secTemplate = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 5
MaximumPasswordAge = 90
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Version]
signature="$CHICAGO$"
Revision=1
"@

$tempFile = "$env:TEMP\password_policy.inf"
$secTemplate | Out-File -FilePath $tempFile -Encoding Unicode

# Appliquer avec secedit
secedit /configure /db "$env:TEMP\password_policy.sdb" /cfg $tempFile /areas SECURITYPOLICY /quiet

Write-Host "  + Longueur minimale : 8 caracteres" -ForegroundColor Green
Write-Host "  + Complexite : ACTIVE" -ForegroundColor Green
Write-Host "  + Historique : 5 derniers mots de passe" -ForegroundColor Green
Write-Host "  + Verrouillage apres : 5 tentatives" -ForegroundColor Green
Write-Host "  + Duree verrouillage : 30 minutes" -ForegroundColor Green
Write-Host "  + Reset compteur : 30 minutes" -ForegroundColor Green

# Nettoyage
Remove-Item $tempFile -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\password_policy.sdb" -ErrorAction SilentlyContinue

# ============================================
# BONUS : GPO DriveMapping (GPP)
# ============================================
Write-Host "`n[4/4] BONUS : Configuration du mappage de lecteurs..." -ForegroundColor Yellow

try {
    $gpoDrives = New-GPO -Name "DriveMapping" -Comment "Mappage automatique des lecteurs reseau"
    Write-Host "  + GPO creee : DriveMapping" -ForegroundColor Green
} catch {
    $gpoDrives = Get-GPO -Name "DriveMapping"
    Write-Host "  ~ GPO existe deja : DriveMapping" -ForegroundColor DarkYellow
}

# Le mappage de lecteurs via GPP necessite une configuration XML
# On cree les fichiers XML dans le SYSVOL
$gpoId = (Get-GPO -Name "DriveMapping").Id
$gppPath = "\\stellar.local\SYSVOL\stellar.local\Policies\{$gpoId}\User\Preferences\Drives"

# Creer le dossier GPP
New-Item -Path $gppPath -ItemType Directory -Force | Out-Null

# XML pour le mappage des lecteurs
$drivesXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20163A}">
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="P:" status="P:" image="2" changed="2024-01-01 00:00:00" uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234560001}" bypassErrors="1">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\SRV1\share_engineering" label="Engineering Share" persistent="1" useLetter="1" letter="P"/>
        <Filters>
            <FilterGroup bool="AND" not="0" name="STELLAR\GG_Engineering_Read" sid="" userContext="1" primaryGroup="0" localGroup="0"/>
        </Filters>
    </Drive>
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="P:" status="P:" image="2" changed="2024-01-01 00:00:00" uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234560002}" bypassErrors="1">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\SRV1\share_marketing" label="Marketing Share" persistent="1" useLetter="1" letter="P"/>
        <Filters>
            <FilterGroup bool="AND" not="0" name="STELLAR\GG_Marketing_Read" sid="" userContext="1" primaryGroup="0" localGroup="0"/>
        </Filters>
    </Drive>
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="P:" status="P:" image="2" changed="2024-01-01 00:00:00" uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234560003}" bypassErrors="1">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\SRV1\share_hr" label="HR Share" persistent="1" useLetter="1" letter="P"/>
        <Filters>
            <FilterGroup bool="AND" not="0" name="STELLAR\GG_HR_Read" sid="" userContext="1" primaryGroup="0" localGroup="0"/>
        </Filters>
    </Drive>
</Drives>
"@

$drivesXml | Out-File -FilePath "$gppPath\Drives.xml" -Encoding UTF8

# Lier la GPO
try {
    New-GPLink -Name "DriveMapping" -Target $stellarTeamsOU
    Write-Host "  + GPO liee a : Stellar Teams" -ForegroundColor Green
} catch {
    Write-Host "  ~ Lien GPO existe deja" -ForegroundColor DarkYellow
}

Write-Host "  + P: -> \\SRV1\share_engineering (Engineering)" -ForegroundColor Green
Write-Host "  + P: -> \\SRV1\share_marketing (Marketing)" -ForegroundColor Green
Write-Host "  + P: -> \\SRV1\share_hr (HR)" -ForegroundColor Green

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification des GPOs"
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`nGPOs creees :" -ForegroundColor Yellow
Get-GPO -All | Where-Object { $_.DisplayName -in @("WallpaperPolicy", "SecurityPolicy", "DriveMapping") } |
    Select-Object DisplayName, CreationTime, GpoStatus |
    Format-Table -AutoSize

Write-Host "Liens GPO sur Stellar Teams :" -ForegroundColor Yellow
(Get-GPInheritance -Target $stellarTeamsOU).GpoLinks |
    Select-Object DisplayName, Enabled, Order |
    Format-Table -AutoSize

Write-Host "`nPolitique de mots de passe :" -ForegroundColor Yellow
net accounts

Write-Host "`nGPOs configurees avec succes !" -ForegroundColor Green
Write-Host "N'oubliez pas de lancer 'gpupdate /force' sur les postes clients." -ForegroundColor Yellow
