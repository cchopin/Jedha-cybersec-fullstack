# ============================================
# SCRIPT 03 : Creation de l'enregistrement DNS
# ============================================
# Ce script :
# 1. Cree un enregistrement A pour internal.stellar.local
#    pointant vers SRV1 (10.0.0.20)
# 2. Verifie la resolution DNS
#
# Prerequis : Executer sur DC1 (serveur DNS)
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Creation de l'enregistrement DNS"
Write-Host "==========================================" -ForegroundColor Cyan

Import-Module DnsServer

# ============================================
# PARTIE 1 : Creer l'enregistrement A
# ============================================
Write-Host "`n[1/2] Creation de l'enregistrement A..." -ForegroundColor Yellow

$zoneName = "stellar.local"
$recordName = "internal"
$ipAddress = "10.0.0.20"

# Verifier si l'enregistrement existe deja
$existing = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Host "  L'enregistrement $recordName.$zoneName existe deja" -ForegroundColor Yellow
    Write-Host "  Suppression et recreation..." -ForegroundColor Yellow
    Remove-DnsServerResourceRecord -ZoneName $zoneName -Name $recordName -RRType A -Force
}

# Creer l'enregistrement A
Add-DnsServerResourceRecordA -ZoneName $zoneName `
    -Name $recordName `
    -IPv4Address $ipAddress `
    -TimeToLive 01:00:00

Write-Host "  Enregistrement cree : $recordName.$zoneName -> $ipAddress" -ForegroundColor Green

# ============================================
# PARTIE 2 : Verification
# ============================================
Write-Host "`n[2/2] Verification de la resolution DNS..." -ForegroundColor Yellow

# Attendre la propagation
Start-Sleep -Seconds 2

# Test avec Resolve-DnsName
try {
    $result = Resolve-DnsName -Name "internal.stellar.local" -Type A -ErrorAction Stop
    Write-Host "  Resolution reussie :" -ForegroundColor Green
    Write-Host "    Nom  : $($result.Name)" -ForegroundColor White
    Write-Host "    IP   : $($result.IPAddress)" -ForegroundColor White
    Write-Host "    Type : $($result.Type)" -ForegroundColor White
} catch {
    Write-Host "  ERREUR : Resolution DNS echouee" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
}

# Afficher tous les enregistrements de la zone
Write-Host "`n  Enregistrements de la zone $zoneName :" -ForegroundColor Cyan
Get-DnsServerResourceRecord -ZoneName $zoneName | Where-Object {
    $_.HostName -notlike "_*" -and $_.HostName -ne "@"
} | Select-Object HostName, RecordType, @{
    Name="Data";
    Expression={$_.RecordData.IPv4Address}
} | Format-Table -AutoSize

Write-Host "`n  Prochaine etape : Executer 04_configure_vpn_rras.ps1 sur SRV1" -ForegroundColor Yellow
