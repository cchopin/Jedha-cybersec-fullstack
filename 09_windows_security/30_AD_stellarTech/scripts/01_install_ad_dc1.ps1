# ============================================
# SCRIPT 01 : Installation AD DS sur DC1
# ============================================
# Ce script :
# 1. Configure l'IP statique de DC1
# 2. Renomme le serveur en DC1
# 3. Installe le role AD DS
# 4. Promeut DC1 en controleur de domaine
#
# Prerequis : Executer sur DC1 via la console GNS3
# IMPORTANT : Le serveur redemarrera automatiquement apres la promotion
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Installation AD DS sur DC1"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Configuration reseau
# ============================================
Write-Host "`n[1/4] Configuration de l'adresse IP statique..." -ForegroundColor Yellow

# Identifier l'interface reseau active
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

# Supprimer la configuration DHCP existante
Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

# Configurer l'IP statique
New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.10" `
    -PrefixLength 24 `
    -DefaultGateway "10.0.0.1"

# Configurer le DNS (pointe vers lui-meme apres promotion)
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses "127.0.0.1"

Write-Host "  IP configuree : 10.0.0.10/24" -ForegroundColor Green
Write-Host "  Passerelle    : 10.0.0.1" -ForegroundColor Green
Write-Host "  DNS           : 127.0.0.1" -ForegroundColor Green

# ============================================
# PARTIE 2 : Renommer le serveur
# ============================================
Write-Host "`n[2/4] Renommage du serveur en DC1..." -ForegroundColor Yellow

$currentName = $env:COMPUTERNAME
if ($currentName -ne "DC1") {
    Rename-Computer -NewName "DC1" -Force
    Write-Host "  Serveur renomme : $currentName -> DC1" -ForegroundColor Green
    Write-Host "  ATTENTION : Un redemarrage sera necessaire" -ForegroundColor Red
} else {
    Write-Host "  Le serveur s'appelle deja DC1" -ForegroundColor Green
}

# ============================================
# PARTIE 3 : Installation du role AD DS
# ============================================
Write-Host "`n[3/4] Installation du role AD DS..." -ForegroundColor Yellow

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Write-Host "  Role AD DS installe avec succes" -ForegroundColor Green

# ============================================
# PARTIE 4 : Promotion en controleur de domaine
# ============================================
Write-Host "`n[4/4] Promotion en controleur de domaine..." -ForegroundColor Yellow
Write-Host "  Domaine : stellar.local" -ForegroundColor Cyan
Write-Host "  NetBIOS : STELLAR" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ATTENTION : Le serveur va redemarrer automatiquement !" -ForegroundColor Red
Write-Host ""

Install-ADDSForest `
    -DomainName "stellar.local" `
    -DomainNetBIOSName "STELLAR" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDNS:$true `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Force:$true

# Le serveur redemarrera automatiquement ici
