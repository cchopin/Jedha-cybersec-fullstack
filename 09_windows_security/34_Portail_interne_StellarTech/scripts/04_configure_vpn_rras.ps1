# ============================================
# SCRIPT 04 : Configuration VPN (RRAS)
# ============================================
# Ce script :
# 1. Installe le role RRAS (Routing and Remote Access)
# 2. Configure le serveur VPN avec SSTP
# 3. Definit le pool d'adresses IP pour les clients VPN
# 4. Configure le DNS pour les clients
#
# Prerequis : Executer sur SRV1 (joint au domaine)
# NOTE : SSTP fonctionne sur un seul NIC (port 443)
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration VPN (RRAS)"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Installation des roles
# ============================================
Write-Host "`n[1/4] Installation des roles VPN..." -ForegroundColor Yellow

# Installer RRAS (Remote Access) et NPS
Install-WindowsFeature -Name RemoteAccess -IncludeManagementTools
Install-WindowsFeature -Name DirectAccess-VPN -IncludeManagementTools
Install-WindowsFeature -Name Routing -IncludeManagementTools
Install-WindowsFeature -Name NPAS -IncludeManagementTools

Write-Host "  Roles RRAS et NPS installes" -ForegroundColor Green

# ============================================
# PARTIE 2 : Configuration RRAS
# ============================================
Write-Host "`n[2/4] Configuration du service RRAS..." -ForegroundColor Yellow

# Installer le service VPN
Install-RemoteAccess -VpnType Vpn -ErrorAction SilentlyContinue

Write-Host "  Service VPN configure" -ForegroundColor Green

# ============================================
# PARTIE 3 : Configurer le pool d'adresses IP
# ============================================
Write-Host "`n[3/4] Configuration du pool d'adresses IP..." -ForegroundColor Yellow

# Configurer le pool d'adresses statiques pour les clients VPN
# Les clients VPN recevront une IP entre 10.0.0.100 et 10.0.0.120
$remoteAccess = Get-RemoteAccess -ErrorAction SilentlyContinue

# Configurer via netsh (plus fiable pour RRAS)
netsh ras ip set addrassign method = pool
netsh ras ip add range from = 10.0.0.100 to = 10.0.0.120

Write-Host "  Pool d'adresses : 10.0.0.100 - 10.0.0.120" -ForegroundColor Green

# ============================================
# PARTIE 4 : Configurer le DNS pour les clients VPN
# ============================================
Write-Host "`n[4/4] Configuration DNS pour les clients VPN..." -ForegroundColor Yellow

# Les clients VPN doivent utiliser DC1 comme serveur DNS
netsh ras ip set dns mode = statik dnsserver = 10.0.0.10

Write-Host "  DNS pour clients VPN : 10.0.0.10 (DC1)" -ForegroundColor Green

# Configurer les ports VPN
# Activer SSTP (port 443) et IKEv2 (ports 500/4500)
Write-Host "`n  Configuration des protocoles VPN..." -ForegroundColor Yellow

# SSTP - fonctionne sur un seul NIC via port 443
# IKEv2 - protocole moderne et securise
# Desactiver PPTP (non securise) et L2TP

# Redemarrer le service RRAS
Restart-Service RemoteAccess -Force
Write-Host "  Service RRAS redemarre" -ForegroundColor Green

# ============================================
# Configurer le pare-feu
# ============================================
Write-Host "`n  Configuration du pare-feu..." -ForegroundColor Yellow

# Autoriser SSTP (TCP 443)
New-NetFirewallRule -DisplayName "VPN SSTP (TCP 443)" `
    -Direction Inbound -Protocol TCP -LocalPort 443 `
    -Action Allow -ErrorAction SilentlyContinue

# Autoriser IKEv2 (UDP 500 et 4500)
New-NetFirewallRule -DisplayName "VPN IKEv2 (UDP 500)" `
    -Direction Inbound -Protocol UDP -LocalPort 500 `
    -Action Allow -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "VPN IKEv2 (UDP 4500)" `
    -Direction Inbound -Protocol UDP -LocalPort 4500 `
    -Action Allow -ErrorAction SilentlyContinue

Write-Host "  Regles de pare-feu creees (SSTP + IKEv2)" -ForegroundColor Green

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Verifier le service RRAS
$rrasService = Get-Service RemoteAccess
Write-Host "  Service RRAS : $($rrasService.Status)" -ForegroundColor $(if ($rrasService.Status -eq "Running") { "Green" } else { "Red" })

# Verifier les ports ouverts
$sslPort = Get-NetTCPConnection -LocalPort 443 -ErrorAction SilentlyContinue
if ($sslPort) {
    Write-Host "  Port 443 (SSTP) : Actif" -ForegroundColor Green
} else {
    Write-Host "  Port 443 (SSTP) : En attente de connexion" -ForegroundColor Yellow
}

# Afficher la configuration
Write-Host "`n  Configuration VPN :" -ForegroundColor Cyan
netsh ras ip show config

Write-Host "`n  Prochaine etape : Executer 05_configure_nps.ps1 sur SRV1" -ForegroundColor Yellow
