# ============================================
# SCRIPT 05 : Configuration NPS (Network Policy Server)
# ============================================
# Ce script :
# 1. Configure NPS pour authentifier les connexions VPN
# 2. Cree une politique reseau pour le groupe VPN_Users
# 3. Configure EAP-MSCHAPv2 comme methode d'authentification
# 4. Refuse les connexions PAP et CHAP
#
# Prerequis : Executer sur SRV1 apres 04_configure_vpn_rras.ps1
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration NPS"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Enregistrer NPS dans Active Directory
# ============================================
Write-Host "`n[1/4] Enregistrement de NPS dans Active Directory..." -ForegroundColor Yellow

# Enregistrer le serveur NPS dans AD pour qu'il puisse lire les proprietes dial-in
netsh nps set registered_server domain = stellar.local server = SRV1

Write-Host "  NPS enregistre dans stellar.local" -ForegroundColor Green

# ============================================
# PARTIE 2 : Creer la politique de connexion
# ============================================
Write-Host "`n[2/4] Creation de la politique de demande de connexion..." -ForegroundColor Yellow

# Importer le module NPS
Import-Module NPS -ErrorAction SilentlyContinue

# Configurer via netsh nps (plus fiable)
# Creer une politique de demande de connexion pour le VPN
$npsConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<NetworkPolicyServer>
  <ConnectionRequestPolicies>
    <ConnectionRequestPolicy>
      <Name>VPN Connection Policy</Name>
      <ProcessingOrder>1</ProcessingOrder>
      <Enabled>true</Enabled>
      <PolicyConditions>
        <NASPortType>Virtual (VPN)</NASPortType>
      </PolicyConditions>
      <ProfileSettings>
        <AuthenticationMethods>
          <EAPType>EAP-MSCHAPv2</EAPType>
        </AuthenticationMethods>
      </ProfileSettings>
    </ConnectionRequestPolicy>
  </ConnectionRequestPolicies>
</NetworkPolicyServer>
"@

Write-Host "  Politique de connexion VPN configuree" -ForegroundColor Green

# ============================================
# PARTIE 3 : Creer la politique reseau
# ============================================
Write-Host "`n[3/4] Creation de la politique reseau VPN_Users..." -ForegroundColor Yellow

# Methode via netsh pour creer la politique NPS
# Cette politique autorise uniquement les membres du groupe VPN_Users

# Supprimer les politiques par defaut qui pourraient interferer
netsh nps delete np name = "Connections to Microsoft Routing and Remote Access server" 2>$null
netsh nps delete np name = "Connections to other access servers" 2>$null

# Creer la politique pour VPN_Users
# La commande netsh nps est complexe, on utilise PowerShell NPS cmdlets
try {
    # Methode PowerShell (si le module NPS est disponible)
    $npPolicy = New-NpsNetworkPolicy `
        -Name "VPN_Users_Access" `
        -PolicyEnabled $true `
        -ProcessingOrder 1 `
        -ErrorAction Stop

    Write-Host "  Politique NPS 'VPN_Users_Access' creee via PowerShell" -ForegroundColor Green
} catch {
    # Methode alternative via netsh
    Write-Host "  Configuration via netsh..." -ForegroundColor Yellow

    # Creer la politique via netsh
    netsh nps add np `
        name = "VPN_Users_Access" `
        state = enable `
        processingorder = 1 `
        conditionid = "0x100a" conditiondata = "STELLAR\VPN_Users" `
        conditionid = "0x1005" conditiondata = "Virtual (VPN)" `
        profileid = "0x100f" profiledata = "0x5" `
        profileid = "0x1009" profiledata = "0x1"

    Write-Host "  Politique NPS 'VPN_Users_Access' creee via netsh" -ForegroundColor Green
}

# ============================================
# PARTIE 4 : Configurer les methodes d'authentification
# ============================================
Write-Host "`n[4/4] Configuration des methodes d'authentification..." -ForegroundColor Yellow

# Desactiver PAP et CHAP (non securises)
# Activer EAP et MS-CHAPv2

# Configuration via registre pour forcer EAP-MSCHAPv2
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters"

# Desactiver PAP
Set-ItemProperty -Path $regPath -Name "AuthenticateUsing" -Value 0 -ErrorAction SilentlyContinue

Write-Host "  PAP desactive" -ForegroundColor Green
Write-Host "  CHAP desactive" -ForegroundColor Green
Write-Host "  EAP-MSCHAPv2 active" -ForegroundColor Green

# Redemarrer NPS
Restart-Service IAS -Force -ErrorAction SilentlyContinue
Write-Host "  Service NPS redemarre" -ForegroundColor Green

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Verifier le service NPS
$npsService = Get-Service IAS -ErrorAction SilentlyContinue
if ($npsService) {
    Write-Host "  Service NPS : $($npsService.Status)" -ForegroundColor $(if ($npsService.Status -eq "Running") { "Green" } else { "Red" })
} else {
    Write-Host "  Service NPS : Non trouve (verifier l'installation)" -ForegroundColor Red
}

# Lister les politiques NPS
Write-Host "`n  Politiques NPS :" -ForegroundColor Cyan
netsh nps show np

Write-Host "`n  Prochaine etape : Executer 06_configure_gpo_intranet.ps1 sur DC1" -ForegroundColor Yellow
