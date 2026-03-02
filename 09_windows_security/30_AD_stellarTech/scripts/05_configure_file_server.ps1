# ============================================
# SCRIPT 05 : Configuration du serveur de fichiers
# ============================================
# Ce script :
# 1. Configure l'IP statique de SRV1
# 2. Joint SRV1 au domaine stellar.local
# 3. Installe le role File Server
# 4. Cree les dossiers partages
# 5. Configure les partages SMB
# 6. Applique les permissions NTFS (modele AGDLP)
#
# Prerequis : DC1 operationnel, groupes crees (script 03)
# Executer sur SRV1 via la console GNS3
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Configuration du serveur de fichiers (SRV1)"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Configuration reseau
# ============================================
Write-Host "`n[1/6] Configuration de l'adresse IP statique..." -ForegroundColor Yellow

$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.20" `
    -PrefixLength 24 `
    -DefaultGateway "10.0.0.1"

Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
    -ServerAddresses "10.0.0.10"

Write-Host "  IP configuree : 10.0.0.20/24" -ForegroundColor Green
Write-Host "  DNS           : 10.0.0.10 (DC1)" -ForegroundColor Green

# ============================================
# PARTIE 2 : Renommer et joindre le domaine
# ============================================
Write-Host "`n[2/6] Renommage et jonction au domaine..." -ForegroundColor Yellow

$currentName = $env:COMPUTERNAME
if ($currentName -ne "SRV1") {
    Rename-Computer -NewName "SRV1" -Force
    Write-Host "  Serveur renomme : $currentName -> SRV1" -ForegroundColor Green
    Write-Host "  !! REDEMARREZ puis relancez ce script !!" -ForegroundColor Red
    return
}

$isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if (-not $isDomainJoined) {
    Write-Host "  Jonction au domaine stellar.local..." -ForegroundColor Cyan
    $cred = Get-Credential -Message "Identifiants STELLAR\Administrator"
    Add-Computer -DomainName "stellar.local" -Credential $cred -OUPath "OU=Servers,DC=stellar,DC=local" -Force
    Write-Host "  !! REDEMARREZ puis relancez ce script !!" -ForegroundColor Red
    return
} else {
    Write-Host "  Deja membre du domaine" -ForegroundColor Green
}

# ============================================
# PARTIE 3 : Installation du role File Server
# ============================================
Write-Host "`n[3/6] Installation du role File Server..." -ForegroundColor Yellow

Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools
Write-Host "  Role File Server installe" -ForegroundColor Green

# ============================================
# PARTIE 4 : Creation des dossiers
# ============================================
Write-Host "`n[4/6] Creation des dossiers partages..." -ForegroundColor Yellow

$shares = @(
    @{ Name = "share_engineering"; Path = "C:\Shares\Engineering"; DLGroup = "DL_Share_Engineering" },
    @{ Name = "share_marketing";   Path = "C:\Shares\Marketing";   DLGroup = "DL_Share_Marketing" },
    @{ Name = "share_hr";          Path = "C:\Shares\HR";          DLGroup = "DL_Share_HR" }
)

foreach ($share in $shares) {
    New-Item -Path $share.Path -ItemType Directory -Force | Out-Null
    Write-Host "  + Dossier cree : $($share.Path)" -ForegroundColor Green
}

# Creer aussi le dossier pour le wallpaper
New-Item -Path "C:\Shares\Wallpaper" -ItemType Directory -Force | Out-Null
Write-Host "  + Dossier cree : C:\Shares\Wallpaper" -ForegroundColor Green

# ============================================
# PARTIE 5 : Creation des partages SMB
# ============================================
Write-Host "`n[5/6] Creation des partages SMB..." -ForegroundColor Yellow

foreach ($share in $shares) {
    try {
        New-SmbShare -Name $share.Name `
            -Path $share.Path `
            -FullAccess "STELLAR\Domain Admins" `
            -ChangeAccess "STELLAR\$($share.DLGroup)" `
            -Description "Partage departement"
        Write-Host "  + Partage cree : \\SRV1\$($share.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  ~ Partage existe deja : $($share.Name)" -ForegroundColor DarkYellow
    }
}

# Partage wallpaper (lecture seule pour tous)
try {
    New-SmbShare -Name "shared_wallpaper" `
        -Path "C:\Shares\Wallpaper" `
        -ReadAccess "STELLAR\Domain Users" `
        -FullAccess "STELLAR\Domain Admins" `
        -Description "Wallpaper corporate"
    Write-Host "  + Partage cree : \\SRV1\shared_wallpaper" -ForegroundColor Green
} catch {
    Write-Host "  ~ Partage existe deja : shared_wallpaper" -ForegroundColor DarkYellow
}

# ============================================
# PARTIE 6 : Configuration des permissions NTFS
# ============================================
Write-Host "`n[6/6] Configuration des permissions NTFS..." -ForegroundColor Yellow

foreach ($share in $shares) {
    Write-Host "  Configuration NTFS pour $($share.Path)..." -ForegroundColor Cyan

    # Recuperer l'ACL actuelle
    $acl = Get-Acl $share.Path

    # Desactiver l'heritage et supprimer les regles heritees
    $acl.SetAccessRuleProtection($true, $false)

    # Ajouter Administrators - Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($adminRule)

    # Ajouter SYSTEM - Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($systemRule)

    # Ajouter le groupe Domain Local - Modify (Read/Write)
    $dlRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "STELLAR\$($share.DLGroup)",
        "Modify",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($dlRule)

    # Appliquer l'ACL
    Set-Acl $share.Path $acl

    Write-Host "    + Administrators : Full Control" -ForegroundColor Green
    Write-Host "    + SYSTEM : Full Control" -ForegroundColor Green
    Write-Host "    + STELLAR\$($share.DLGroup) : Modify" -ForegroundColor Green
    Write-Host "    - Heritage desactive, autres utilisateurs refuses" -ForegroundColor Green
}

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification"
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "`nPartages SMB :" -ForegroundColor Yellow
Get-SmbShare | Where-Object { $_.Name -like "share_*" -or $_.Name -eq "shared_wallpaper" } |
    Select-Object Name, Path, Description |
    Format-Table -AutoSize

Write-Host "Permissions NTFS (share_engineering) :" -ForegroundColor Yellow
(Get-Acl "C:\Shares\Engineering").Access |
    Select-Object IdentityReference, FileSystemRights, AccessControlType |
    Format-Table -AutoSize

Write-Host "Serveur de fichiers configure avec succes !" -ForegroundColor Green
