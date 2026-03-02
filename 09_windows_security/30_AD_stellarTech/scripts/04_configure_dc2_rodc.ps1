# ============================================
# SCRIPT 04 : Configuration de DC2 en RODC
# ============================================
# Ce script :
# 1. Configure l'IP statique de DC2
# 2. Renomme le serveur en DC2
# 3. Joint DC2 au domaine stellar.local
# 4. Installe AD DS
# 5. Promeut DC2 en RODC avec Global Catalog
#
# Prerequis : DC1 operationnel avec stellar.local
# Executer sur DC2 via la console GNS3
# IMPORTANT : Redemarrage necessaire entre certaines etapes
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration de DC2 (RODC + Global Catalog)"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Configuration reseau
# ============================================
Write-Host "`n[1/5] Configuration de l'adresse IP statique..." -ForegroundColor Yellow

$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.11" `
    -PrefixLength 24 `
    -DefaultGateway "10.0.0.1"

# DNS pointe vers DC1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses "10.0.0.10"

Write-Host "  IP configuree : 10.0.0.11/24" -ForegroundColor Green
Write-Host "  Passerelle    : 10.0.0.1" -ForegroundColor Green
Write-Host "  DNS           : 10.0.0.10 (DC1)" -ForegroundColor Green

# ============================================
# PARTIE 2 : Renommer le serveur
# ============================================
Write-Host "`n[2/5] Renommage du serveur en DC2..." -ForegroundColor Yellow

$currentName = $env:COMPUTERNAME
if ($currentName -ne "DC2") {
    Rename-Computer -NewName "DC2" -Force
    Write-Host "  Serveur renomme : $currentName -> DC2" -ForegroundColor Green
    Write-Host ""
    Write-Host "  !! REDEMARREZ LE SERVEUR MAINTENANT !!" -ForegroundColor Red
    Write-Host "  Puis relancez ce script apres le redemarrage." -ForegroundColor Red
    Write-Host "  Commande : Restart-Computer -Force" -ForegroundColor Yellow
    return
}

# ============================================
# PARTIE 3 : Verifier la connectivite vers DC1
# ============================================
Write-Host "`n[3/5] Verification de la connectivite vers DC1..." -ForegroundColor Yellow

$testDC1 = Test-NetConnection -ComputerName 10.0.0.10 -Port 389 -WarningAction SilentlyContinue
if ($testDC1.TcpTestSucceeded) {
    Write-Host "  DC1 joignable sur le port LDAP (389)" -ForegroundColor Green
} else {
    Write-Host "  ERREUR : DC1 non joignable ! Verifiez le reseau." -ForegroundColor Red
    return
}

$testDNS = Resolve-DnsName "stellar.local" -DnsOnly -ErrorAction SilentlyContinue
if ($testDNS) {
    Write-Host "  Resolution DNS stellar.local : OK" -ForegroundColor Green
} else {
    Write-Host "  ERREUR : Impossible de resoudre stellar.local" -ForegroundColor Red
    return
}

# ============================================
# PARTIE 4 : Joindre le domaine (si pas deja fait)
# ============================================
Write-Host "`n[4/5] Jonction au domaine stellar.local..." -ForegroundColor Yellow

$isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if (-not $isDomainJoined) {
    Write-Host "  Entrez les identifiants de l'administrateur du domaine :" -ForegroundColor Cyan
    $cred = Get-Credential -Message "Identifiants STELLAR\Administrator"

    Add-Computer -DomainName "stellar.local" -Credential $cred -Force
    Write-Host "  Serveur joint au domaine stellar.local" -ForegroundColor Green
    Write-Host ""
    Write-Host "  !! REDEMARREZ LE SERVEUR MAINTENANT !!" -ForegroundColor Red
    Write-Host "  Puis relancez ce script apres le redemarrage." -ForegroundColor Red
    Write-Host "  Commande : Restart-Computer -Force" -ForegroundColor Yellow
    return
} else {
    Write-Host "  Deja membre du domaine" -ForegroundColor Green
}

# ============================================
# PARTIE 5 : Promotion en RODC avec Global Catalog
# ============================================
Write-Host "`n[5/5] Installation AD DS et promotion en RODC..." -ForegroundColor Yellow

# Installer le role AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Write-Host "  Role AD DS installe" -ForegroundColor Green

Write-Host ""
Write-Host "  Promotion en RODC avec Global Catalog..." -ForegroundColor Cyan
Write-Host "  ATTENTION : Le serveur va redemarrer automatiquement !" -ForegroundColor Red
Write-Host ""

$cred = Get-Credential -Message "Identifiants STELLAR\Administrator pour la promotion"

Install-ADDSDomainController `
    -DomainName "stellar.local" `
    -ReadOnlyReplica:$true `
    -InstallDNS:$true `
    -NoGlobalCatalog:$false `
    -SiteName "Default-First-Site-Name" `
    -ReplicationSourceDC "DC1.stellar.local" `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Credential $cred `
    -Force:$true

# Le serveur redemarrera automatiquement ici
