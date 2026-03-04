# ============================================
# SCRIPT 06 : GPO Intranet (Raccourci + Homepage)
# ============================================
# Ce script :
# 1. Cree une GPO pour ajouter un raccourci bureau vers le portail
# 2. Cree une GPO pour definir la page d'accueil Edge/Chrome
# 3. Lie les GPOs a l'OU Stellar Teams
#
# Prerequis : Executer sur DC1
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration GPO Intranet"
Write-Host "==========================================" -ForegroundColor Cyan

Import-Module GroupPolicy

$domain = "DC=stellar,DC=local"
$targetOU = "OU=Stellar Teams,$domain"
$intranetUrl = "http://internal.stellar.local"

# ============================================
# PARTIE 1 : GPO Raccourci Bureau
# ============================================
Write-Host "`n[1/3] Creation de la GPO 'IntranetShortcutPolicy'..." -ForegroundColor Yellow

# Creer la GPO
$shortcutGPO = New-GPO -Name "IntranetShortcutPolicy" -Comment "Raccourci bureau vers le portail interne StellarTech"

# Configurer le raccourci via les preferences GPO (Group Policy Preferences)
# Le raccourci est cree via le registre RunOnce pour simuler la creation
# En production, on utiliserait les GPP Shortcuts dans GPMC

# Alternative : Creer un script de connexion qui cree le raccourci
$loginScriptPath = "\\DC1\NETLOGON\create_shortcut.ps1"

# Creer le script de connexion
$shortcutScript = @'
# Script de connexion - Cree le raccourci vers l'intranet
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "Portail StellarTech.url"

if (-not (Test-Path $shortcutPath)) {
    $shortcutContent = @"
[InternetShortcut]
URL=http://internal.stellar.local
IconIndex=0
IconFile=C:\Windows\System32\shell32.dll,14
"@
    $shortcutContent | Out-File -FilePath $shortcutPath -Encoding ASCII
}
'@

# Sauvegarder le script dans NETLOGON
$netlogonPath = "C:\Windows\SYSVOL\domain\scripts"
$shortcutScript | Out-File -FilePath "$netlogonPath\create_shortcut.ps1" -Encoding UTF8

Write-Host "  Script de connexion cree dans NETLOGON" -ForegroundColor Green

# Configurer la GPO pour executer le script a la connexion
Set-GPRegistryValue -Name "IntranetShortcutPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "StellarTechIntranet" `
    -Type String `
    -Value "powershell.exe -ExecutionPolicy Bypass -File \\DC1\NETLOGON\create_shortcut.ps1"

# Lier la GPO a l'OU Stellar Teams
New-GPLink -Name "IntranetShortcutPolicy" -Target $targetOU

Write-Host "  GPO 'IntranetShortcutPolicy' creee et liee a Stellar Teams" -ForegroundColor Green

# ============================================
# PARTIE 2 : GPO Page d'accueil Edge
# ============================================
Write-Host "`n[2/3] Creation de la GPO 'IntranetHomepagePolicy'..." -ForegroundColor Yellow

# Creer la GPO
New-GPO -Name "IntranetHomepagePolicy" -Comment "Page d'accueil Edge/Chrome vers le portail interne"

# Configurer la page d'accueil pour Microsoft Edge (Chromium)
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "HomepageLocation" `
    -Type String `
    -Value $intranetUrl

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "HomepageIsNewTabPage" `
    -Type DWord `
    -Value 0

# Configurer le bouton d'accueil Edge
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "ShowHomeButton" `
    -Type DWord `
    -Value 1

# Configurer la page de demarrage Edge
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs" `
    -ValueName "1" `
    -Type String `
    -Value $intranetUrl

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "RestoreOnStartup" `
    -Type DWord `
    -Value 4

# Configurer pour Google Chrome (si installe)
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Google\Chrome" `
    -ValueName "HomepageLocation" `
    -Type String `
    -Value $intranetUrl

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Google\Chrome" `
    -ValueName "HomepageIsNewTabPage" `
    -Type DWord `
    -Value 0

# Configurer pour Internet Explorer (legacy)
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKCU\Software\Microsoft\Internet Explorer\Main" `
    -ValueName "Start Page" `
    -Type String `
    -Value $intranetUrl

# Lier la GPO
New-GPLink -Name "IntranetHomepagePolicy" -Target $targetOU

Write-Host "  GPO 'IntranetHomepagePolicy' creee et liee a Stellar Teams" -ForegroundColor Green

# ============================================
# PARTIE 3 : Ajouter le site en zone Intranet
# ============================================
Write-Host "`n[3/3] Ajout du site dans la zone Intranet de confiance..." -ForegroundColor Yellow

# Ajouter internal.stellar.local dans la zone Intranet locale
# Cela evite les avertissements de securite
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\stellar.local\internal" `
    -ValueName "http" `
    -Type DWord `
    -Value 1

Write-Host "  Site ajoute dans la zone Intranet de confiance" -ForegroundColor Green

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Lister les GPOs
Write-Host "  GPOs du domaine :" -ForegroundColor Cyan
Get-GPO -All | Select-Object DisplayName, CreationTime | Format-Table -AutoSize

# Verifier les liens sur l'OU Stellar Teams
Write-Host "  Liens GPO sur Stellar Teams :" -ForegroundColor Cyan
(Get-GPInheritance -Target $targetOU).GpoLinks |
    Select-Object DisplayName, Enabled | Format-Table -AutoSize

# Verifier le script NETLOGON
Write-Host "  Script NETLOGON :" -ForegroundColor Cyan
if (Test-Path "$netlogonPath\create_shortcut.ps1") {
    Write-Host "    create_shortcut.ps1 present" -ForegroundColor Green
} else {
    Write-Host "    create_shortcut.ps1 MANQUANT" -ForegroundColor Red
}

Write-Host "`n  Prochaine etape : Executer 07_configure_https_bonus.ps1 sur SRV1 (bonus)" -ForegroundColor Yellow
Write-Host "  Ou directement 08_verify.ps1 sur DC1" -ForegroundColor Yellow
