# Lab 34 : Portail Interne StellarTech

Deploiement d'un portail web interne pour StellarTech Inc., accessible uniquement via VPN, avec resolution DNS interne et integration Active Directory.

**Duree estimee** : 270 minutes

**Niveau** : Exercice intermediaire - Indices fournis

**Prerequis** : Lab 30 (AD StellarTech) doit etre configure et fonctionnel

---

## Table des matieres

1. [Objectifs](#objectifs)
2. [Prerequis](#prerequis)
3. [Architecture](#architecture)
4. [Demarrage rapide](#demarrage-rapide)
5. [Configuration requise](#configuration-requise)
6. [Criteres de validation](#criteres-de-validation)
7. [Indices](#indices)
8. [Depannage](#depannage)

---

## Objectifs

- Deployer un serveur web IIS avec un site statique marketing
- Configurer un VPN (SSTP/IKEv2) avec authentification EAP sur SRV1
- Restreindre l'acces VPN aux membres du groupe `VPN_Users`
- Creer un enregistrement DNS `internal.stellar.local` dans la zone AD
- Deployer des GPOs pour integrer le portail dans l'environnement corporate
- (Bonus) Configurer HTTPS avec un certificat auto-signe

---

## Prerequis

- **Lab 30 configure** : domaine `stellar.local`, DC1, DC2 (RODC), SRV1, OUs, utilisateurs
- GNS3 connecte au serveur distant (IP: voir `group_vars/all.yml`)
- Ansible installe (`brew install ansible` sur macOS)
- Python 3
- Appliances disponibles dans GNS3 :
  - Windows Server 2022 (QEMU)
  - pfSense (routeur/firewall)

---

## Architecture

### Structure du lab

```
34_Portail_interne_StellarTech/
├── ansible.cfg                # Configuration Ansible
├── inventory.yml              # Inventaire GNS3
├── group_vars/
│   └── all.yml                # Variables de configuration
├── playbooks/
│   ├── 00_full_lab.yml        # Deploiement complet
│   ├── 01_create_topology.yml # Creation de la topologie GNS3
│   └── 99_cleanup.yml         # Nettoyage
├── scripts/
│   ├── 01_install_iis_website.ps1        # Installation IIS + site web
│   ├── 02_create_vpn_group.ps1           # Creation groupe VPN_Users
│   ├── 03_create_dns_record.ps1          # Enregistrement DNS
│   ├── 04_configure_vpn_rras.ps1         # Configuration VPN (RRAS)
│   ├── 05_configure_nps.ps1              # Politique NPS
│   ├── 06_configure_gpo_intranet.ps1     # GPOs (raccourci + homepage)
│   ├── 07_configure_https_bonus.ps1      # HTTPS (bonus)
│   └── 08_verify.ps1                     # Script de verification
├── website/                   # Assets web supplementaires
├── server_info.yml            # Genere automatiquement
├── README.md
└── SOLUTION.md                # Solution complete
```

### Topologie reseau

```
                        ┌─────────────────┐
                        │      NAT        │
                        │   (Internet)    │
                        │  192.168.122.1  │
                        └────────┬────────┘
                                 │ WAN
                        ┌────────┴────────┐
                        │    pfSense      │
                        │   (Firewall)    │
                        │  WAN: DHCP      │
                        │  LAN: 10.0.0.1  │
                        └────────┬────────┘
                                 │ LAN
                        ┌────────┴────────┐
                        │    SW-LAN       │
                        │ (Ethernet Sw.)  │
                        └──┬─────┬─────┬──┘
                           │     │     │
                 ┌─────────┘     │     └─────────┐
                 │               │               │
        ┌────────┴────────┐ ┌───┴──────────┐ ┌──┴───────────┐
        │      DC1        │ │     DC2      │ │     SRV1     │
        │ (Windows Server)│ │(Windows Srv) │ │(Windows Srv) │
        │  10.0.0.10      │ │ 10.0.0.11    │ │  10.0.0.20   │
        │                 │ │              │ │              │
        │ AD DS + DNS     │ │ RODC + GC    │ │ IIS + VPN    │
        │ Primary DC      │ │ Secondary    │ │ Web + RRAS   │
        └─────────────────┘ └──────────────┘ └──────────────┘
```

### Plan d'adressage

| Machine | IP | Role | DNS |
|---------|-----|------|-----|
| pfSense | 10.0.0.1 (LAN) | Passerelle | - |
| DC1 | 10.0.0.10 | DC principal + DNS | 127.0.0.1 |
| DC2 | 10.0.0.11 | RODC + Global Catalog | 10.0.0.10 |
| SRV1 | 10.0.0.20 | IIS + VPN (RRAS) | 10.0.0.10 |
| Clients VPN | 10.0.0.100-120 | Pool DHCP VPN | 10.0.0.10 |

### Services deployes

| Service | Serveur | Port(s) | Description |
|---------|---------|---------|-------------|
| IIS (HTTP) | SRV1 | 80 | Portail web interne |
| IIS (HTTPS) | SRV1 | 443 | Portail web securise (bonus) |
| SSTP VPN | SRV1 | 443 | VPN tunnel SSL |
| IKEv2 VPN | SRV1 | 500, 4500 | VPN IPsec |
| DNS | DC1 | 53 | Resolution interne |

---

## Demarrage rapide

### 1. Verifier la connexion au serveur GNS3

```bash
curl -s http://192.168.155.153:80/v2/version
```

### 2. Modifier l'IP si necessaire

Modifier `group_vars/all.yml` si l'IP du serveur GNS3 a change.

### 3. Deployer la topologie (si Lab 30 non deploye)

```bash
cd 34_Portail_interne_StellarTech
ansible-playbook playbooks/01_create_topology.yml
```

### 4. Configurer les serveurs

Apres le demarrage des VMs dans GNS3 (et la configuration du Lab 30), se connecter a chaque serveur via la console GNS3 et executer les scripts PowerShell dans l'ordre :

```
1. Sur SRV1 : scripts/01_install_iis_website.ps1
2. Sur DC1  : scripts/02_create_vpn_group.ps1
3. Sur DC1  : scripts/03_create_dns_record.ps1
4. Sur SRV1 : scripts/04_configure_vpn_rras.ps1
5. Sur SRV1 : scripts/05_configure_nps.ps1
6. Sur DC1  : scripts/06_configure_gpo_intranet.ps1
7. Sur SRV1 : scripts/07_configure_https_bonus.ps1 (bonus)
8. Sur DC1  : scripts/08_verify.ps1
```

---

## Configuration requise

### 1. Portail Web (IIS)

Deployer un site web statique sur SRV1 :

| Parametre | Valeur |
|-----------|--------|
| Serveur web | IIS (Internet Information Services) |
| Chemin | `C:\inetpub\wwwroot\` |
| URL | `http://internal.stellar.local` |
| Contenu | Site marketing StellarTech (HTML/CSS) |

Le site doit contenir :
- Page d'accueil avec branding StellarTech
- Section actualites/annonces
- Liens vers les partages reseau
- Indication d'acces reserve via VPN

### 2. VPN (RRAS + NPS)

Configurer le VPN sur SRV1 :

| Parametre | Valeur |
|-----------|--------|
| Protocole | SSTP (port 443) et/ou IKEv2 |
| Authentification | EAP-MSCHAPv2 (pas PAP/CHAP) |
| Pool IP | 10.0.0.100 - 10.0.0.120 |
| DNS client | 10.0.0.10 (DC1) |
| Groupe autorise | `VPN_Users` |

### 3. Groupe VPN_Users

| Parametre | Valeur |
|-----------|--------|
| Nom | `VPN_Users` |
| Type | Global Security |
| OU | Groups |
| Membres | anakin, ahsoka, obiwan, padme, leia, monmothma |

### 4. DNS

| Type | Nom | Zone | Valeur |
|------|-----|------|--------|
| A | internal | stellar.local | 10.0.0.20 |

Verification : `nslookup internal.stellar.local` depuis un client VPN

### 5. GPOs Intranet

| Nom GPO | OU cible | Description |
|---------|---------|-------------|
| IntranetShortcutPolicy | Stellar Teams | Raccourci bureau vers `http://internal.stellar.local` |
| IntranetHomepagePolicy | Stellar Teams | Page d'accueil Edge/Chrome vers le portail |

### 6. Bonus

- **HTTPS** : Certificat auto-signe pour `internal.stellar.local`
- **NTFS** : Seuls les Domain Admins peuvent modifier le contenu web
- **Logo/Favicon** : Personnalisation du site avec l'identite StellarTech

---

## Criteres de validation

Executer `scripts/08_verify.ps1` sur DC1 et verifier :

- [ ] Enregistrement DNS `internal.stellar.local` -> 10.0.0.20
- [ ] Site web accessible sur `http://internal.stellar.local`
- [ ] Le site contient le branding StellarTech
- [ ] Groupe `VPN_Users` cree avec 6 membres
- [ ] Service RRAS actif sur SRV1
- [ ] Port SSTP (443) ouvert sur SRV1
- [ ] GPO `IntranetShortcutPolicy` liee a Stellar Teams
- [ ] GPO `IntranetHomepagePolicy` liee a Stellar Teams
- [ ] Script `create_shortcut.ps1` dans NETLOGON
- [ ] (Bonus) HTTPS accessible sur le port 443
- [ ] (Bonus) Permissions NTFS restrictives sur wwwroot
- [ ] Client VPN peut resoudre et acceder au portail

---

## Indices

<details>
<summary>Indice 1 : Installation IIS</summary>

```powershell
# Installer le role Web Server
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Verifier l'installation
Get-WindowsFeature Web-Server

# Le site par defaut est dans C:\inetpub\wwwroot\
```

</details>

<details>
<summary>Indice 2 : Creer un enregistrement DNS</summary>

```powershell
# Sur DC1, creer un enregistrement A
Add-DnsServerResourceRecordA -ZoneName "stellar.local" `
    -Name "internal" `
    -IPv4Address "10.0.0.20"

# Verifier
Resolve-DnsName -Name "internal.stellar.local" -Type A
```

</details>

<details>
<summary>Indice 3 : Installation RRAS</summary>

```powershell
# Installer les roles necessaires
Install-WindowsFeature -Name RemoteAccess -IncludeManagementTools
Install-WindowsFeature -Name DirectAccess-VPN -IncludeManagementTools
Install-WindowsFeature -Name Routing -IncludeManagementTools
Install-WindowsFeature -Name NPAS -IncludeManagementTools

# Configurer le VPN
Install-RemoteAccess -VpnType Vpn
```

</details>

<details>
<summary>Indice 4 : Pool d'adresses VPN</summary>

```powershell
# Configurer le pool d'adresses statiques via netsh
netsh ras ip set addrassign method = pool
netsh ras ip add range from = 10.0.0.100 to = 10.0.0.120

# Configurer le DNS pour les clients
netsh ras ip set dns mode = statik dnsserver = 10.0.0.10
```

</details>

<details>
<summary>Indice 5 : GPO page d'accueil Edge</summary>

```powershell
# Creer la GPO
New-GPO -Name "IntranetHomepagePolicy"

# Page d'accueil Edge (Chromium)
Set-GPRegistryValue -Name "IntranetHomepagePolicy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Edge" `
    -ValueName "HomepageLocation" `
    -Type String `
    -Value "http://internal.stellar.local"

# Lier a l'OU
New-GPLink -Name "IntranetHomepagePolicy" `
    -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

</details>

<details>
<summary>Indice 6 : Certificat auto-signe (bonus)</summary>

```powershell
# Generer le certificat
$cert = New-SelfSignedCertificate `
    -DnsName "internal.stellar.local" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -FriendlyName "StellarTech Intranet SSL" `
    -NotAfter (Get-Date).AddYears(2)

# Ajouter le binding HTTPS dans IIS
Import-Module WebAdministration
New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443
$binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
$binding.AddSslCertificate($cert.Thumbprint, "My")
```

</details>

<details>
<summary>Indice 7 : Permissions NTFS restrictives (bonus)</summary>

```powershell
$acl = Get-Acl "C:\inetpub\wwwroot"
$acl.SetAccessRuleProtection($true, $false)

# Domain Admins - Full Control
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "STELLAR\Domain Admins", "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")))

# IIS_IUSRS - Read Only
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\IIS_IUSRS", "ReadAndExecute",
    "ContainerInherit,ObjectInherit", "None", "Allow")))

Set-Acl "C:\inetpub\wwwroot" $acl
```

</details>

---

## Depannage

### IIS ne demarre pas ou le site n'est pas accessible

```powershell
# Verifier le service IIS
Get-Service W3SVC

# Verifier les bindings
Get-WebBinding -Name "Default Web Site"

# Verifier le pare-feu
Get-NetFirewallRule -DisplayGroup "World Wide Web Services (HTTP)"

# Tester localement
Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing
```

### Le DNS ne resout pas internal.stellar.local

```powershell
# Verifier l'enregistrement
Get-DnsServerResourceRecord -ZoneName "stellar.local" -Name "internal"

# Forcer la propagation
Clear-DnsClientCache
ipconfig /flushdns

# Tester
nslookup internal.stellar.local 10.0.0.10
```

### Le VPN ne fonctionne pas

```powershell
# Verifier le service RRAS
Get-Service RemoteAccess

# Verifier la configuration
netsh ras show conf

# Verifier les ports
netstat -an | findstr "443 500 4500"

# Verifier le pare-feu
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*VPN*" }
```

### Les GPOs ne s'appliquent pas

```powershell
# Forcer la mise a jour
gpupdate /force

# Verifier les GPOs appliquees
gpresult /r

# Verifier les liens
Get-GPInheritance -Target "OU=Stellar Teams,DC=stellar,DC=local"
```

### Le client VPN ne recoit pas le bon DNS

```powershell
# Verifier la configuration DNS du VPN
netsh ras ip show dns

# Depuis le client VPN, verifier
ipconfig /all
nslookup internal.stellar.local
```

---

## References

- [IIS Web Server Overview](https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/iis-web-server-overview)
- [Install and Configure RRAS VPN](https://learn.microsoft.com/en-us/windows-server/remote/remote-access/vpn/always-on-vpn/deploy/vpn-deploy-ras)
- [Network Policy Server (NPS)](https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top)
- [DNS Server PowerShell Cmdlets](https://learn.microsoft.com/en-us/powershell/module/dnsserver/)
- [Group Policy for Edge](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge)
- [Self-Signed Certificates](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate)
- [GNS3 API Documentation](https://gns3-server.readthedocs.io/en/latest/api.html)

---

## Solution

Une fois l'exercice termine (ou en cas de blocage), consulter `SOLUTION.md` pour la solution complete.
