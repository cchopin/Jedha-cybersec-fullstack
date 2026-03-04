# ============================================
# SCRIPT 07 : HTTPS avec certificat auto-signe (BONUS)
# ============================================
# Ce script :
# 1. Genere un certificat auto-signe pour internal.stellar.local
# 2. Configure le binding HTTPS dans IIS
# 3. Exporte le certificat pour distribution aux clients
# 4. Configure les permissions NTFS sur le dossier web
#
# Prerequis : Executer sur SRV1 apres 01_install_iis_website.ps1
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " BONUS : Configuration HTTPS"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Generer le certificat auto-signe
# ============================================
Write-Host "`n[1/4] Generation du certificat SSL auto-signe..." -ForegroundColor Yellow

$cert = New-SelfSignedCertificate `
    -DnsName "internal.stellar.local", "srv1.stellar.local", "SRV1" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -FriendlyName "StellarTech Intranet SSL" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256

Write-Host "  Certificat genere :" -ForegroundColor Green
Write-Host "    Subject     : $($cert.Subject)" -ForegroundColor White
Write-Host "    Thumbprint  : $($cert.Thumbprint)" -ForegroundColor White
Write-Host "    Expiration  : $($cert.NotAfter)" -ForegroundColor White

# ============================================
# PARTIE 2 : Configurer HTTPS dans IIS
# ============================================
Write-Host "`n[2/4] Configuration du binding HTTPS dans IIS..." -ForegroundColor Yellow

Import-Module WebAdministration

# Ajouter le binding HTTPS sur le port 443
$existingBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -ErrorAction SilentlyContinue

if (-not $existingBinding) {
    New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "internal.stellar.local"
    Write-Host "  Binding HTTPS cree sur le port 443" -ForegroundColor Green
} else {
    Write-Host "  Binding HTTPS existe deja" -ForegroundColor Yellow
}

# Associer le certificat au binding
$binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
$binding.AddSslCertificate($cert.Thumbprint, "My")

Write-Host "  Certificat associe au site" -ForegroundColor Green

# ============================================
# PARTIE 3 : Exporter le certificat
# ============================================
Write-Host "`n[3/4] Export du certificat pour les clients..." -ForegroundColor Yellow

$exportPath = "C:\Shares\Certificates"
New-Item -Path $exportPath -ItemType Directory -Force | Out-Null

# Exporter le certificat public (sans cle privee) pour les clients
Export-Certificate -Cert $cert -FilePath "$exportPath\stellartech_intranet.cer" -Force

Write-Host "  Certificat exporte : $exportPath\stellartech_intranet.cer" -ForegroundColor Green

# Creer un partage SMB pour le certificat
$existingShare = Get-SmbShare -Name "certificates" -ErrorAction SilentlyContinue
if (-not $existingShare) {
    New-SmbShare -Name "certificates" -Path $exportPath `
        -ReadAccess "STELLAR\Domain Users" `
        -FullAccess "STELLAR\Domain Admins"
    Write-Host "  Partage \\SRV1\certificates cree" -ForegroundColor Green
}

# Instructions pour les clients
Write-Host "`n  Pour faire confiance au certificat sur un client :" -ForegroundColor Cyan
Write-Host "    1. Copier \\SRV1\certificates\stellartech_intranet.cer" -ForegroundColor White
Write-Host "    2. Double-cliquer -> Installer le certificat" -ForegroundColor White
Write-Host "    3. Selectionner 'Ordinateur local'" -ForegroundColor White
Write-Host "    4. Placer dans 'Autorites de certification racine de confiance'" -ForegroundColor White

# ============================================
# PARTIE 4 : Permissions NTFS sur le dossier web
# ============================================
Write-Host "`n[4/4] Configuration des permissions NTFS sur le dossier web..." -ForegroundColor Yellow

$wwwroot = "C:\inetpub\wwwroot"
$acl = Get-Acl $wwwroot

# Desactiver l'heritage et copier les regles existantes
$acl.SetAccessRuleProtection($true, $false)

# Administrateurs - Full Control
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

# SYSTEM - Full Control
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

# Domain Admins - Full Control (seuls eux peuvent modifier le site)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "STELLAR\Domain Admins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

# IIS_IUSRS - Read only (necessaire pour servir les fichiers)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

Set-Acl $wwwroot $acl

Write-Host "  Permissions NTFS configurees :" -ForegroundColor Green
Write-Host "    - Domain Admins : Full Control (modification)" -ForegroundColor White
Write-Host "    - Administrators : Full Control" -ForegroundColor White
Write-Host "    - SYSTEM : Full Control" -ForegroundColor White
Write-Host "    - IIS_IUSRS : Lecture seule (service web)" -ForegroundColor White

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification HTTPS" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Tester HTTPS
try {
    # Ignorer les erreurs de certificat pour le test local
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $response = Invoke-WebRequest -Uri "https://localhost" -UseBasicParsing -ErrorAction Stop
    Write-Host "  HTTPS accessible : HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  Note : HTTPS accessible mais le certificat auto-signe genere un avertissement" -ForegroundColor Yellow
}

# Verifier les bindings IIS
Write-Host "`n  Bindings IIS :" -ForegroundColor Cyan
Get-WebBinding -Name "Default Web Site" | Format-Table Protocol, bindingInformation -AutoSize

# Verifier les permissions NTFS
Write-Host "  Permissions NTFS sur $wwwroot :" -ForegroundColor Cyan
(Get-Acl $wwwroot).Access | Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize

Write-Host "`n  Prochaine etape : Executer 08_verify.ps1 sur DC1" -ForegroundColor Yellow
