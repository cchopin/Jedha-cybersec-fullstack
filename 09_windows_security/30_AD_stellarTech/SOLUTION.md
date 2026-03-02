# Lab 30 : AD StellarTech - Solution

Solution complete pour la mise en place de l'infrastructure Active Directory de StellarTech Inc.

---

## Vue d'ensemble

### Etapes dans l'ordre

| Etape | Machine | Script | Description |
|-------|---------|--------|-------------|
| 1 | DC1 | `01_install_ad_dc1.ps1` | Installation AD DS + promotion |
| 2 | DC1 | `02_create_ou_structure.ps1` | Creation des OUs |
| 3 | DC1 | `03_create_users_groups.ps1` | Utilisateurs, groupes, AGDLP |
| 4 | DC2 | `04_configure_dc2_rodc.ps1` | RODC + Global Catalog |
| 5 | SRV1 | `05_configure_file_server.ps1` | Partages + NTFS |
| 6 | DC1 | `06_configure_gpo.ps1` | GPOs |
| 7 | DC1 | `07_verify.ps1` | Verification |

---

## Etape 0 : Deployer la topologie GNS3

![Topologie GNS3](images/gns3_topology.png)

```bash
cd 30_AD_stellarTech
ansible-playbook playbooks/01_create_topology.yml
```

Cela cree :
- 1 NAT (acces Internet)
- 1 pfSense (firewall - LAN 10.0.0.1/24)
- 3 Windows Server 2022 (DC1, DC2, SRV1)

### Configuration de pfSense

1. Acceder a la console pfSense dans GNS3
2. Configurer l'interface LAN :
   - IP : `10.0.0.1/24`
   - DHCP : desactiver (on utilise des IPs statiques)
3. Configurer l'interface WAN en DHCP

---

## Etape 1 : Installation AD DS sur DC1

### Configuration IP de DC1

```powershell
# Identifier l'interface reseau
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

# Supprimer la config existante
Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

# IP statique
New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.10" -PrefixLength 24 -DefaultGateway "10.0.0.1"

# DNS vers lui-meme
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "127.0.0.1"
```

### Renommer le serveur

```powershell
Rename-Computer -NewName "DC1" -Force
Restart-Computer -Force
```

### Installer et promouvoir

```powershell
# Installer le role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promouvoir en DC
Install-ADDSForest `
    -DomainName "stellar.local" `
    -DomainNetBIOSName "STELLAR" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDNS:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Force:$true
```

Le serveur redemarrera automatiquement.

### Verification

```powershell
Get-ADDomain
# DNSRoot: stellar.local
# NetBIOSName: STELLAR
```

---

## Etape 2 : Structure OUs

```powershell
Import-Module ActiveDirectory

$domain = "DC=stellar,DC=local"

# OUs racine
New-ADOrganizationalUnit -Name "Stellar Teams" -Path $domain
New-ADOrganizationalUnit -Name "Servers" -Path $domain
New-ADOrganizationalUnit -Name "Groups" -Path $domain
New-ADOrganizationalUnit -Name "Policies" -Path $domain

# Sous-OUs departements
New-ADOrganizationalUnit -Name "Engineering" -Path "OU=Stellar Teams,$domain"
New-ADOrganizationalUnit -Name "Marketing" -Path "OU=Stellar Teams,$domain"
New-ADOrganizationalUnit -Name "HR" -Path "OU=Stellar Teams,$domain"
```

### Resultat attendu

```
stellar.local
├── Stellar Teams
│   ├── Engineering
│   ├── Marketing
│   └── HR
├── Servers
├── Groups
└── Policies
```

---

## Etape 3 : Utilisateurs et Groupes

### Utilisateurs

```powershell
$password = ConvertTo-SecureString "Welcome1!" -AsPlainText -Force
$domain = "DC=stellar,DC=local"

# Engineering
@("anakin/Anakin Skywalker", "ahsoka/Ahsoka Tano", "obiwan/Obi-Wan Kenobi") | ForEach-Object {
    $parts = $_ -split "/"
    New-ADUser -Name $parts[1] -SamAccountName $parts[0] `
        -UserPrincipalName "$($parts[0])@stellar.local" `
        -Path "OU=Engineering,OU=Stellar Teams,$domain" `
        -AccountPassword $password -Enabled $true
}

# Marketing
@("padme/Padme Amidala", "leia/Leia Organa") | ForEach-Object {
    $parts = $_ -split "/"
    New-ADUser -Name $parts[1] -SamAccountName $parts[0] `
        -UserPrincipalName "$($parts[0])@stellar.local" `
        -Path "OU=Marketing,OU=Stellar Teams,$domain" `
        -AccountPassword $password -Enabled $true
}

# HR
New-ADUser -Name "Mon Mothma" -SamAccountName "monmothma" `
    -UserPrincipalName "monmothma@stellar.local" `
    -Path "OU=HR,OU=Stellar Teams,$domain" `
    -AccountPassword $password -Enabled $true
```

### Groupes et AGDLP

```powershell
$groupsPath = "OU=Groups,$domain"

# Groupes globaux
New-ADGroup -Name "GG_Engineering_Read" -GroupScope Global -Path $groupsPath
New-ADGroup -Name "GG_Marketing_Read" -GroupScope Global -Path $groupsPath
New-ADGroup -Name "GG_HR_Read" -GroupScope Global -Path $groupsPath

# Groupes domain local
New-ADGroup -Name "DL_Share_Engineering" -GroupScope DomainLocal -Path $groupsPath
New-ADGroup -Name "DL_Share_Marketing" -GroupScope DomainLocal -Path $groupsPath
New-ADGroup -Name "DL_Share_HR" -GroupScope DomainLocal -Path $groupsPath

# Utilisateurs -> Groupes globaux
Add-ADGroupMember -Identity "GG_Engineering_Read" -Members "anakin","ahsoka","obiwan"
Add-ADGroupMember -Identity "GG_Marketing_Read" -Members "padme","leia"
Add-ADGroupMember -Identity "GG_HR_Read" -Members "monmothma"

# Groupes globaux -> Groupes domain local
Add-ADGroupMember -Identity "DL_Share_Engineering" -Members "GG_Engineering_Read"
Add-ADGroupMember -Identity "DL_Share_Marketing" -Members "GG_Marketing_Read"
Add-ADGroupMember -Identity "DL_Share_HR" -Members "GG_HR_Read"
```

### Schema AGDLP

```
Utilisateur -> Global Group -> Domain Local Group -> Permission sur la ressource

anakin   ─┐
ahsoka   ─┼─> GG_Engineering_Read ──> DL_Share_Engineering ──> \\SRV1\share_engineering
obiwan   ─┘

padme    ─┐
leia     ─┴─> GG_Marketing_Read ───> DL_Share_Marketing ───> \\SRV1\share_marketing

monmothma ──> GG_HR_Read ──────────> DL_Share_HR ──────────> \\SRV1\share_hr
```

### Verification

```powershell
# Lister les utilisateurs
Get-ADUser -Filter * -SearchBase "OU=Stellar Teams,DC=stellar,DC=local" |
    Select-Object SamAccountName, DistinguishedName | Format-Table

# Verifier l'imbrication
Get-ADGroupMember -Identity "DL_Share_Engineering" | Select-Object Name
# Resultat: GG_Engineering_Read

Get-ADGroupMember -Identity "GG_Engineering_Read" | Select-Object SamAccountName
# Resultat: anakin, ahsoka, obiwan
```

---

## Etape 4 : DC2 en RODC

### Configuration reseau de DC2

```powershell
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.11" -PrefixLength 24 -DefaultGateway "10.0.0.1"
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "10.0.0.10"
Rename-Computer -NewName "DC2" -Force
Restart-Computer -Force
```

### Joindre le domaine

```powershell
$cred = Get-Credential  # STELLAR\Administrator / P@ssw0rd123!
Add-Computer -DomainName "stellar.local" -Credential $cred -Force
Restart-Computer -Force
```

### Promouvoir en RODC

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

$cred = Get-Credential  # STELLAR\Administrator
Install-ADDSDomainController `
    -DomainName "stellar.local" `
    -ReadOnlyReplica:$true `
    -InstallDNS:$true `
    -NoGlobalCatalog:$false `
    -SiteName "Default-First-Site-Name" `
    -ReplicationSourceDC "DC1.stellar.local" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Credential $cred `
    -Force:$true
```

### Verification

```powershell
# Sur DC1
Get-ADDomainController -Filter * | Select-Object Name, IsReadOnly, IsGlobalCatalog | Format-Table

# Resultat attendu:
# Name  IsReadOnly  IsGlobalCatalog
# ----  ----------  ---------------
# DC1   False       True
# DC2   True        True
```

---

## Etape 5 : Serveur de fichiers (SRV1)

### Configuration reseau + jonction

```powershell
# IP
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
    -IPAddress "10.0.0.20" -PrefixLength 24 -DefaultGateway "10.0.0.1"
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "10.0.0.10"

# Renommer
Rename-Computer -NewName "SRV1" -Force
Restart-Computer -Force

# Joindre le domaine dans l'OU Servers
$cred = Get-Credential
Add-Computer -DomainName "stellar.local" -Credential $cred `
    -OUPath "OU=Servers,DC=stellar,DC=local" -Force
Restart-Computer -Force
```

### Partages et NTFS

```powershell
# Installer le role
Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools

# Creer les dossiers
$shares = @(
    @{ Name = "share_engineering"; Path = "C:\Shares\Engineering"; DL = "DL_Share_Engineering" },
    @{ Name = "share_marketing";   Path = "C:\Shares\Marketing";   DL = "DL_Share_Marketing" },
    @{ Name = "share_hr";          Path = "C:\Shares\HR";          DL = "DL_Share_HR" }
)

foreach ($s in $shares) {
    # Creer le dossier
    New-Item -Path $s.Path -ItemType Directory -Force

    # Creer le partage SMB
    New-SmbShare -Name $s.Name -Path $s.Path `
        -FullAccess "STELLAR\Domain Admins" `
        -ChangeAccess "STELLAR\$($s.DL)"

    # Permissions NTFS
    $acl = Get-Acl $s.Path
    $acl.SetAccessRuleProtection($true, $false)

    # Administrators
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

    # SYSTEM
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

    # Groupe DL
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "STELLAR\$($s.DL)", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))

    Set-Acl $s.Path $acl
}

# Partage wallpaper
New-Item -Path "C:\Shares\Wallpaper" -ItemType Directory -Force
New-SmbShare -Name "shared_wallpaper" -Path "C:\Shares\Wallpaper" `
    -ReadAccess "STELLAR\Domain Users" -FullAccess "STELLAR\Domain Admins"
```

### Verification

```powershell
Get-SmbShare | Where-Object { $_.Name -like "share_*" -or $_.Name -eq "shared_wallpaper" }

# Resultat attendu:
# Name               Path                  Description
# ----               ----                  -----------
# share_engineering  C:\Shares\Engineering
# share_hr           C:\Shares\HR
# share_marketing    C:\Shares\Marketing
# shared_wallpaper   C:\Shares\Wallpaper

(Get-Acl "C:\Shares\Engineering").Access | Format-Table IdentityReference, FileSystemRights, AccessControlType

# Resultat attendu:
# IdentityReference              FileSystemRights  AccessControlType
# -----------------              ----------------  -----------------
# BUILTIN\Administrators         FullControl       Allow
# NT AUTHORITY\SYSTEM            FullControl       Allow
# STELLAR\DL_Share_Engineering   Modify            Allow
```

---

## Etape 6 : GPOs

### WallpaperPolicy

```powershell
Import-Module GroupPolicy

New-GPO -Name "WallpaperPolicy"

Set-GPRegistryValue -Name "WallpaperPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "Wallpaper" -Type String -Value "\\SRV1\shared_wallpaper\wallpaper.jpg"

Set-GPRegistryValue -Name "WallpaperPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "WallpaperStyle" -Type String -Value "2"

New-GPLink -Name "WallpaperPolicy" -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

### SecurityPolicy

```powershell
New-GPO -Name "SecurityPolicy"

# Desactiver Panneau de configuration
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoControlPanel" -Type DWord -Value 1

# Desactiver cmd
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
    -ValueName "DisableCMD" -Type DWord -Value 1

# Desactiver registre
Set-GPRegistryValue -Name "SecurityPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableRegistryTools" -Type DWord -Value 1

New-GPLink -Name "SecurityPolicy" -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

### PasswordPolicy

```powershell
# Via secedit (modifie la Default Domain Policy)
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
secedit /configure /db "$env:TEMP\password_policy.sdb" /cfg $tempFile /areas SECURITYPOLICY /quiet
```

### Verification

```powershell
# Lister les GPOs
Get-GPO -All | Select-Object DisplayName, CreationTime | Format-Table

# Verifier les liens
(Get-GPInheritance -Target "OU=Stellar Teams,DC=stellar,DC=local").GpoLinks |
    Select-Object DisplayName, Enabled | Format-Table

# Resultat attendu:
# DisplayName       Enabled
# -----------       -------
# WallpaperPolicy   True
# SecurityPolicy    True

# Verifier la politique de mots de passe
Get-ADDefaultDomainPasswordPolicy

# Resultat attendu:
# MinPasswordLength    : 8
# LockoutThreshold     : 5
# LockoutDuration      : 00:30:00
```

---

## Etape 7 : Test de redondance

### Test 1 : Connexion via DC2

1. Sur DC1, noter que la replication fonctionne :
```powershell
repadmin /replsummary
```

2. Eteindre DC1 dans GNS3

3. Sur SRV1, tester la connexion utilisateur :
```powershell
# Depuis SRV1, se connecter en tant qu'anakin
runas /user:STELLAR\anakin cmd.exe
# Mot de passe : Welcome1!
```

4. Verifier que DC2 repond aux requetes :
```powershell
nltest /dsgetdc:stellar.local
# Devrait montrer DC2
```

5. Rallumer DC1 et verifier la replication :
```powershell
repadmin /replsummary
```

---

## Validation des objectifs

- [x] **Domaine stellar.local** operationnel avec NetBIOS STELLAR
- [x] **Structure OUs** : Stellar Teams (Engineering, Marketing, HR), Servers, Groups, Policies
- [x] **6 utilisateurs** dans les bonnes OUs
- [x] **3 groupes globaux** + 3 groupes domain local
- [x] **Imbrication AGDLP** correcte
- [x] **3 partages** sur SRV1 avec permissions NTFS
- [x] **GPO WallpaperPolicy** liee a Stellar Teams
- [x] **GPO SecurityPolicy** liee a Stellar Teams (cmd, panneau config, registre desactives)
- [x] **PasswordPolicy** : 8+ chars, verrouillage 5 tentatives
- [x] **DC2 RODC** avec Global Catalog
- [x] **Redondance** : connexion possible quand DC1 est eteint
- [x] **BONUS** : Mappage lecteur P: via GPP

---

## Diagramme final

```
                     ┌──────────────────────┐
                     │    stellar.local     │
                     │    (Active Directory)│
                     └──────────┬───────────┘
                                │
        ┌───────────────────────┼─────────────────────┐
        │                       │                     │
  ┌─────┴─────┐          ┌──────┴────┐          ┌─────┴─────┐
  │    DC1    │          │    DC2    │          │   SRV1    │
  │ 10.0.0.10 │          │ 10.0.0.11 │          │ 10.0.0.20 │
  │           │          │           │          │           │
  │ AD DS     │ Repl.    │ AD DS     │          │ File      │
  │ DNS       │<-------->│ DNS (RO)  │          │ Server    │
  │ Primary   │          │ RODC + GC │          │           │
  └───────────┘          └───────────┘          └───────────┘
       │                                              │
       │ GPOs:                                        │ Partages:
       │ - WallpaperPolicy                            │ - share_engineering
       │ - SecurityPolicy                             │ - share_marketing
       │ - PasswordPolicy                             │ - share_hr
       │ - DriveMapping (bonus)                       │ - shared_wallpaper
       │                                              │
       └──────── OUs ────────┐                        │
                             │                        │
                   ┌─────────┴─────────┐              │
                   │  Stellar Teams    │              │
                   │  ├── Engineering  │──── AGDLP ───┘
                   │  ├── Marketing    │
                   │  └── HR           │
                   │  Servers          │
                   │  Groups           │
                   │  Policies         │
                   └───────────────────┘
```
