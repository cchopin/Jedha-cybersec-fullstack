# Lab 34 : Portail Interne StellarTech - Solution

Solution complete pour le deploiement du portail web interne StellarTech avec VPN, DNS et GPOs.

---

## Vue d'ensemble

### Etapes dans l'ordre

| Etape | Machine | Script | Description |
|-------|---------|--------|-------------|
| 1 | SRV1 | `01_install_iis_website.ps1` | Installation IIS + site web |
| 2 | DC1 | `02_create_vpn_group.ps1` | Creation groupe VPN_Users |
| 3 | DC1 | `03_create_dns_record.ps1` | Enregistrement DNS |
| 4 | SRV1 | `04_configure_vpn_rras.ps1` | Configuration VPN (RRAS) |
| 5 | SRV1 | `05_configure_nps.ps1` | Politique NPS |
| 6 | DC1 | `06_configure_gpo_intranet.ps1` | GPOs intranet |
| 7 | SRV1 | `07_configure_https_bonus.ps1` | HTTPS (bonus) |
| 8 | DC1 | `08_verify.ps1` | Verification |

---

## Etape 0 : Prerequis - Lab 30

Ce lab s'appuie sur l'infrastructure du Lab 30. S'assurer que :
- Le domaine `stellar.local` est operationnel
- DC1 (10.0.0.10) est le DC principal avec DNS
- DC2 (10.0.0.11) est le RODC
- SRV1 (10.0.0.20) est joint au domaine
- Les utilisateurs et groupes sont crees

Si ce n'est pas fait, deployer d'abord le Lab 30 :

```bash
cd ../30_AD_stellarTech
ansible-playbook playbooks/01_create_topology.yml
# Puis executer les scripts 01 a 07 du Lab 30
```

---

## Etape 1 : Installation IIS + Site Web (SRV1)

### Installer IIS

```powershell
Install-WindowsFeature -Name Web-Server -IncludeManagementTools -IncludeAllSubFeature
```

### Deployer le site web

Le script `01_install_iis_website.ps1` cree automatiquement un site HTML/CSS complet avec :
- Header avec logo StellarTech
- Section hero avec badge VPN
- 6 cartes de services internes
- Section actualites
- Liens vers les partages reseau
- Footer avec infos infrastructure

```powershell
# Executer sur SRV1
.\scripts\01_install_iis_website.ps1
```

### Verification

```powershell
# Tester localement
Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing
# Doit retourner StatusCode 200
```

---

## Etape 2 : Groupe VPN_Users (DC1)

### Creer le groupe

```powershell
Import-Module ActiveDirectory

New-ADGroup -Name "VPN_Users" `
    -SamAccountName "VPN_Users" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,DC=stellar,DC=local" `
    -Description "Utilisateurs autorises a se connecter via VPN"
```

### Ajouter les utilisateurs

```powershell
$vpnMembers = @("anakin", "ahsoka", "obiwan", "padme", "leia", "monmothma")
foreach ($user in $vpnMembers) {
    Add-ADGroupMember -Identity "VPN_Users" -Members $user
}
```

### Verification

```powershell
Get-ADGroupMember -Identity "VPN_Users" | Select-Object SamAccountName
# Resultat : 6 utilisateurs
```

---

## Etape 3 : Enregistrement DNS (DC1)

### Creer l'enregistrement A

```powershell
Import-Module DnsServer

Add-DnsServerResourceRecordA -ZoneName "stellar.local" `
    -Name "internal" `
    -IPv4Address "10.0.0.20" `
    -TimeToLive 01:00:00
```

### Verification

```powershell
Resolve-DnsName -Name "internal.stellar.local" -Type A
# Resultat :
# Name                  Type   TTL   Section    IPAddress
# ----                  ----   ---   -------    ---------
# internal.stellar.local A     3600  Answer     10.0.0.20

nslookup internal.stellar.local
# Server: DC1.stellar.local
# Address: 10.0.0.10
# Name: internal.stellar.local
# Address: 10.0.0.20
```

---

## Etape 4 : Configuration VPN - RRAS (SRV1)

### Installer les roles

```powershell
Install-WindowsFeature -Name RemoteAccess -IncludeManagementTools
Install-WindowsFeature -Name DirectAccess-VPN -IncludeManagementTools
Install-WindowsFeature -Name Routing -IncludeManagementTools
Install-WindowsFeature -Name NPAS -IncludeManagementTools
```

### Configurer RRAS

```powershell
# Configurer le VPN
Install-RemoteAccess -VpnType Vpn

# Pool d'adresses pour les clients VPN
netsh ras ip set addrassign method = pool
netsh ras ip add range from = 10.0.0.100 to = 10.0.0.120

# DNS pour les clients VPN
netsh ras ip set dns mode = statik dnsserver = 10.0.0.10
```

### Configurer le pare-feu

```powershell
# SSTP (TCP 443)
New-NetFirewallRule -DisplayName "VPN SSTP (TCP 443)" `
    -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# IKEv2 (UDP 500 et 4500)
New-NetFirewallRule -DisplayName "VPN IKEv2 (UDP 500)" `
    -Direction Inbound -Protocol UDP -LocalPort 500 -Action Allow

New-NetFirewallRule -DisplayName "VPN IKEv2 (UDP 4500)" `
    -Direction Inbound -Protocol UDP -LocalPort 4500 -Action Allow
```

### Verification

```powershell
Get-Service RemoteAccess
# Status: Running

netsh ras ip show config
# Pool d'adresses : 10.0.0.100 - 10.0.0.120
# DNS : 10.0.0.10
```

---

## Etape 5 : Configuration NPS (SRV1)

### Enregistrer NPS dans AD

```powershell
netsh nps set registered_server domain = stellar.local server = SRV1
```

### Creer la politique NPS

```powershell
# Supprimer les politiques par defaut
netsh nps delete np name = "Connections to Microsoft Routing and Remote Access server" 2>$null
netsh nps delete np name = "Connections to other access servers" 2>$null

# Creer la politique pour VPN_Users
netsh nps add np `
    name = "VPN_Users_Access" `
    state = enable `
    processingorder = 1 `
    conditionid = "0x100a" conditiondata = "STELLAR\VPN_Users" `
    conditionid = "0x1005" conditiondata = "Virtual (VPN)" `
    profileid = "0x100f" profiledata = "0x5" `
    profileid = "0x1009" profiledata = "0x1"
```

### Verification

```powershell
Get-Service IAS
# Status: Running

netsh nps show np
# VPN_Users_Access : Enabled
```

---

## Etape 6 : GPOs Intranet (DC1)

### GPO Raccourci Bureau

```powershell
Import-Module GroupPolicy

# Creer le script de connexion
$shortcutScript = @'
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "Portail StellarTech.url"
if (-not (Test-Path $shortcutPath)) {
    $content = "[InternetShortcut]`nURL=http://internal.stellar.local`nIconIndex=0`nIconFile=C:\Windows\System32\shell32.dll,14"
    $content | Out-File -FilePath $shortcutPath -Encoding ASCII
}
'@

# Sauvegarder dans NETLOGON
$shortcutScript | Out-File "C:\Windows\SYSVOL\domain\scripts\create_shortcut.ps1" -Encoding UTF8

# Creer et configurer la GPO
New-GPO -Name "IntranetShortcutPolicy"
Set-GPRegistryValue -Name "IntranetShortcutPolicy" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "StellarTechIntranet" `
    -Type String `
    -Value "powershell.exe -ExecutionPolicy Bypass -File \\DC1\NETLOGON\create_shortcut.ps1"

New-GPLink -Name "IntranetShortcutPolicy" -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

### GPO Page d'accueil

```powershell
New-GPO -Name "IntranetHomepagePolicy"

# Microsoft Edge
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "HomepageLocation" -Type String -Value "http://internal.stellar.local"

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "HomepageIsNewTabPage" -Type DWord -Value 0

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "ShowHomeButton" -Type DWord -Value 1

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "RestoreOnStartup" -Type DWord -Value 4

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs" `
    -ValueName "1" -Type String -Value "http://internal.stellar.local"

# Google Chrome
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Google\Chrome" `
    -ValueName "HomepageLocation" -Type String -Value "http://internal.stellar.local"

Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Google\Chrome" `
    -ValueName "HomepageIsNewTabPage" -Type DWord -Value 0

New-GPLink -Name "IntranetHomepagePolicy" -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

### Verification

```powershell
Get-GPO -All | Select-Object DisplayName, CreationTime | Format-Table

(Get-GPInheritance -Target "OU=Stellar Teams,DC=stellar,DC=local").GpoLinks |
    Select-Object DisplayName, Enabled | Format-Table

# Resultat attendu :
# DisplayName               Enabled
# -----------               -------
# WallpaperPolicy           True     (Lab 30)
# SecurityPolicy            True     (Lab 30)
# IntranetShortcutPolicy    True     (Lab 34)
# IntranetHomepagePolicy    True     (Lab 34)
```

---

## Etape 7 : HTTPS (Bonus - SRV1)

### Certificat auto-signe

```powershell
$cert = New-SelfSignedCertificate `
    -DnsName "internal.stellar.local", "srv1.stellar.local", "SRV1" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -FriendlyName "StellarTech Intranet SSL" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256
```

### Binding HTTPS

```powershell
Import-Module WebAdministration
New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -HostHeader "internal.stellar.local"
$binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
$binding.AddSslCertificate($cert.Thumbprint, "My")
```

### Exporter et distribuer le certificat

```powershell
# Exporter pour les clients
New-Item -Path "C:\Shares\Certificates" -ItemType Directory -Force
Export-Certificate -Cert $cert -FilePath "C:\Shares\Certificates\stellartech_intranet.cer"

# Partager
New-SmbShare -Name "certificates" -Path "C:\Shares\Certificates" `
    -ReadAccess "STELLAR\Domain Users" -FullAccess "STELLAR\Domain Admins"
```

### Permissions NTFS

```powershell
$acl = Get-Acl "C:\inetpub\wwwroot"
$acl.SetAccessRuleProtection($true, $false)

$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "STELLAR\Domain Admins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

Set-Acl "C:\inetpub\wwwroot" $acl
```

---

## Test depuis un client VPN

### 1. Configurer la connexion VPN

```powershell
# Sur le client Windows
Add-VpnConnection -Name "StellarTech VPN" `
    -ServerAddress "10.0.0.20" `
    -TunnelType Sstp `
    -AuthenticationMethod Eap `
    -EncryptionLevel Required `
    -RememberCredential

# Se connecter
rasdial "StellarTech VPN" anakin Welcome1!
```

### 2. Tester la resolution DNS

```powershell
nslookup internal.stellar.local
# Resultat :
# Server: DC1.stellar.local
# Address: 10.0.0.10
# Name: internal.stellar.local
# Address: 10.0.0.20
```

### 3. Acceder au portail

Ouvrir le navigateur et naviguer vers `http://internal.stellar.local`

Le site StellarTech doit s'afficher avec :
- Logo et branding
- Section services internes
- Actualites
- Liens vers les partages

---

## Validation des objectifs

- [x] **IIS installe** sur SRV1 avec site web statique
- [x] **Site accessible** via `http://internal.stellar.local`
- [x] **Contenu marketing** : branding, actualites, liens partages
- [x] **Groupe VPN_Users** : 6 membres dans l'OU Groups
- [x] **VPN RRAS** : SSTP + IKEv2, pool 10.0.0.100-120
- [x] **NPS** : politique pour VPN_Users, EAP-MSCHAPv2
- [x] **DNS** : enregistrement A `internal` -> 10.0.0.20
- [x] **GPO raccourci** : `IntranetShortcutPolicy` liee a Stellar Teams
- [x] **GPO homepage** : `IntranetHomepagePolicy` (Edge + Chrome)
- [x] **Zone Intranet** : site ajoute dans la zone de confiance
- [x] **BONUS - HTTPS** : certificat auto-signe, binding 443
- [x] **BONUS - NTFS** : seuls Domain Admins modifient wwwroot
- [x] **BONUS - Certificat** : exporte et partage pour distribution

---

## Diagramme final

```
                     ┌──────────────────────────┐
                     │      stellar.local       │
                     │   (Active Directory)     │
                     └──────────┬───────────────┘
                                │
        ┌───────────────────────┼─────────────────────┐
        │                       │                     │
  ┌─────┴─────┐          ┌──────┴────┐          ┌─────┴──────┐
  │    DC1    │          │    DC2    │          │    SRV1    │
  │ 10.0.0.10 │          │ 10.0.0.11 │          │ 10.0.0.20  │
  │           │          │           │          │            │
  │ AD DS     │ Repl.    │ AD DS     │          │ IIS        │
  │ DNS       │<-------->│ DNS (RO)  │          │ RRAS (VPN) │
  │ Primary   │          │ RODC + GC │          │ NPS        │
  └───────────┘          └───────────┘          └──────┬─────┘
       │                                               │
       │ DNS:                                          │ Services:
       │ - internal.stellar.local                      │ - http://internal.stellar.local
       │   -> 10.0.0.20                                │ - https://internal.stellar.local
       │                                               │ - SSTP VPN (443)
       │ GPOs:                                         │ - IKEv2 VPN (500/4500)
       │ - IntranetShortcutPolicy                      │
       │ - IntranetHomepagePolicy                      │ Pool VPN:
       │ - WallpaperPolicy (Lab 30)                    │ - 10.0.0.100 - 10.0.0.120
       │ - SecurityPolicy (Lab 30)                     │
       │                                               │
       └──── AD Groups ─────┐                          │
                            │                          │
                  ┌─────────┴──────────┐               │
                  │  Groups OU         │               │
                  │  ├── VPN_Users ────┼── Autorise ───┘
                  │  ├── GG_* (Lab 30) │
                  │  └── DL_* (Lab 30) │
                  └────────────────────┘
```

---

## Flux de connexion VPN

```
Client VPN                    SRV1 (VPN)              DC1 (DNS/AD)
    │                            │                        │
    │  1. Connexion SSTP/IKEv2   │                        │
    │ ────────────────────────>  │                        │
    │                            │  2. Auth EAP-MSCHAPv2  │
    │                            │ ────────────────────>  │
    │                            │                        │
    │                            │  3. Verif VPN_Users    │
    │                            │ ────────────────────>  │
    │                            │                        │
    │                            │  4. OK (membre)        │
    │                            │ <────────────────────  │
    │  5. IP assignee (pool)     │                        │
    │ <────────────────────────  │                        │
    │  DNS: 10.0.0.10            │                        │
    │                            │                        │
    │  6. nslookup internal.stellar.local                 │
    │ ───────────────────────────────────────────────────>│
    │  7. Reponse: 10.0.0.20                              │
    │ <───────────────────────────────────────────────────│
    │                            │                        │
    │  8. HTTP GET internal.stellar.local                 │
    │ ────────────────────────>  │                        │
    │  9. Page HTML StellarTech  │                        │
    │ <────────────────────────  │                        │
    │                            │                        │
```
