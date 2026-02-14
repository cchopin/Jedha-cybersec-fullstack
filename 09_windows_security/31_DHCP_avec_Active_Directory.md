# DHCP avec Active Directory

**Module** : installer et configurer un serveur DHCP dans un environnement AD

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role de DHCP dans un environnement Active Directory
- Installer et configurer le role DHCP sur Windows Server
- Creer et parametrer une etendue (scope) DHCP
- Configurer les options DHCP (DNS, passerelle, reservations)
- Mettre en place la haute disponibilite DHCP

---

## 1. Rappel sur DHCP

### 1.1 Fonctionnement

Le protocole **DHCP** (Dynamic Host Configuration Protocol) permet d'attribuer automatiquement une configuration reseau (adresse IP, masque de sous-reseau, passerelle, serveurs DNS) aux machines du reseau. Sans DHCP, chaque machine devrait etre configuree manuellement.

### 1.2 Processus DORA

L'attribution d'une adresse DHCP suit le processus **DORA** :

| Etape | Message | Direction | Description |
|---|---|---|---|
| **D** | DHCP Discover | Client → Broadcast | Le client cherche un serveur DHCP sur le reseau |
| **O** | DHCP Offer | Serveur → Client | Le serveur propose une adresse IP |
| **R** | DHCP Request | Client → Broadcast | Le client accepte l'offre |
| **A** | DHCP Acknowledge | Serveur → Client | Le serveur confirme l'attribution |

---

## 2. Prerequis : adresse IP statique

Avant d'installer le role DHCP, le serveur **doit** avoir une adresse IP statique. Un serveur DHCP ne peut pas etre configure avec une adresse dynamique.

```powershell
# Verifier la configuration IP actuelle
Get-NetIPAddress -InterfaceAlias "Ethernet"

# Configurer une IP statique si necessaire
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.10" -PrefixLength 24 -DefaultGateway "192.168.1.1"

# Configurer le DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10","8.8.8.8"
```

---

## 3. Installation du role DHCP

### 3.1 Via l'interface graphique

1. Ouvrir **Server Manager**
2. Cliquer sur **Manage > Add Roles and Features**
3. Suivre l'assistant :
   - **Installation Type** : Role-based or feature-based installation
   - **Server Selection** : selectionner le serveur cible
   - **Server Roles** : cocher **DHCP Server**
4. Accepter les fonctionnalites dependantes
5. Lancer l'installation
6. Apres l'installation, completer la configuration post-installation (notification dans Server Manager)

### 3.2 Via PowerShell

```powershell
# Installer le role DHCP
Install-WindowsFeature DHCP -IncludeManagementTools

# Autoriser le serveur DHCP dans Active Directory
Add-DhcpServerInDC -DnsName "DC1.jedha.local" -IPAddress "192.168.1.10"

# Verifier l'autorisation
Get-DhcpServerInDC
```

> **A noter** : dans un environnement Active Directory, un serveur DHCP doit etre **autorise** dans AD pour fonctionner. Cette autorisation empeche les serveurs DHCP non autorises (rogue DHCP) de distribuer des adresses IP sur le reseau. C'est une mesure de securite importante.

---

## 4. Configuration d'une etendue DHCP (Scope)

### 4.1 Parametres d'une etendue

Une **etendue** (scope) DHCP definit la plage d'adresses IP a distribuer et les options associees :

| Parametre | Description | Exemple |
|---|---|---|
| **Plage IP** | Premiere et derniere adresse de la plage | 192.168.1.100 - 192.168.1.200 |
| **Masque de sous-reseau** | Masque du reseau | 255.255.255.0 (/24) |
| **Exclusions** | Adresses a ne pas distribuer au sein de la plage | 192.168.1.150 - 192.168.1.155 |
| **Delai** | Temps avant qu'un DHCP Offer ne soit envoye | 0 milliseconde (par defaut) |
| **Bail (Lease Time)** | Duree de validite de l'attribution IP | 8 jours (par defaut) |

### 4.2 Configuration via l'interface graphique

1. Ouvrir **DHCP Management Console** (dhcpmgmt.msc)
2. Developper le serveur > clic droit sur **IPv4 > New Scope**
3. Suivre l'assistant :
   - Nom et description de l'etendue
   - Plage d'adresses IP (debut et fin)
   - Masque de sous-reseau
   - Exclusions (adresses reservees aux serveurs, imprimantes, etc.)
   - Duree du bail
   - Options DHCP (passerelle, DNS, etc.)
4. Activer l'etendue

### 4.3 Configuration via PowerShell

```powershell
# Creer une etendue DHCP
Add-DhcpServerv4Scope -Name "Reseau_Principal" `
    -StartRange "192.168.1.100" `
    -EndRange "192.168.1.200" `
    -SubnetMask "255.255.255.0" `
    -LeaseDuration (New-TimeSpan -Days 8) `
    -State Active

# Configurer la passerelle par defaut (option 3)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -Router "192.168.1.1"

# Configurer les serveurs DNS (option 6)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -OptionId 6 -Value "192.168.1.10","8.8.8.8"

# Configurer le nom de domaine DNS (option 15)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -DnsDomain "jedha.local"
```

> **A noter** : l'option DHCP **OptionId 6** correspond aux serveurs DNS. C'est une option essentielle dans un environnement AD car les machines doivent pouvoir resoudre les enregistrements DNS du domaine pour fonctionner correctement (authentification Kerberos, localisation des DC, etc.).

---

## 5. Reservations et exclusions

### 5.1 Reservations

Une **reservation** DHCP associe de maniere permanente une adresse IP a une adresse MAC specifique. La machine recevra toujours la meme adresse IP via DHCP, sans avoir besoin d'une configuration statique.

```powershell
# Creer une reservation DHCP
Add-DhcpServerv4Reservation -ScopeId "192.168.1.0" `
    -IPAddress "192.168.1.50" `
    -ClientId "AA-BB-CC-DD-EE-FF" `
    -Name "Imprimante_RDC" `
    -Description "Imprimante du rez-de-chaussee"

# Lister les reservations
Get-DhcpServerv4Reservation -ScopeId "192.168.1.0"
```

### 5.2 Exclusions

Une **exclusion** definit une plage d'adresses au sein de l'etendue qui ne sera pas distribuee par DHCP. Ces adresses sont reservees pour des equipements configures en IP statique.

```powershell
# Ajouter une plage d'exclusion
Add-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0" `
    -StartRange "192.168.1.1" `
    -EndRange "192.168.1.20"

# Lister les exclusions
Get-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0"
```

> **Bonne pratique** : reservez une plage d'adresses au debut ou a la fin de l'etendue pour les equipements en IP statique (serveurs, switches, points d'acces, imprimantes) en utilisant une exclusion. Utilisez les reservations pour les equipements qui doivent avoir une IP fixe mais que vous souhaitez gerer centralement via DHCP.

---

## 6. Haute disponibilite DHCP

### 6.1 Necessite

Si le serveur DHCP est indisponible, les machines dont le bail expire ne pourront plus obtenir de configuration reseau. Il est donc essentiel de mettre en place un mecanisme de haute disponibilite.

### 6.2 Modes de haute disponibilite

Windows Server propose deux modes de haute disponibilite pour DHCP :

| Mode | Description | Cas d'usage |
|---|---|---|
| **Load Balance** | Les deux serveurs DHCP servent activement les clients. La charge est repartie selon un pourcentage configurable (par defaut 50/50) | Les deux serveurs sont sur le meme site |
| **Hot Standby** | Un serveur est actif (primary), l'autre est en attente (standby). Le standby prend le relais uniquement si le primary est indisponible | Les serveurs sont sur des sites differents |

### 6.3 Configuration

La configuration du failover se fait via la console DHCP :

1. Clic droit sur l'etendue > **Configure Failover**
2. Selectionner le serveur partenaire
3. Choisir le mode (Load Balance ou Hot Standby)
4. Configurer les parametres specifiques au mode choisi
5. Definir un **shared secret** (cle partagee pour securiser la communication entre les deux serveurs)

> **Bonne pratique** : dans un environnement a site unique, le mode **Load Balance** est preferable car il repartit la charge et offre une bascule automatique. Dans un environnement multi-sites, le mode **Hot Standby** est adapte pour le serveur DHCP distant qui ne prend le relais qu'en cas de panne du serveur local.

---

## 7. Resume des commandes PowerShell

```powershell
# Installation
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerInDC -DnsName "DC1.jedha.local" -IPAddress "192.168.1.10"

# Creation d'etendue
Add-DhcpServerv4Scope -Name "Reseau" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -State Active

# Options
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -OptionId 6 -Value "192.168.1.10","8.8.8.8"
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -Router "192.168.1.1"

# Reservations
Add-DhcpServerv4Reservation -ScopeId "192.168.1.0" -IPAddress "192.168.1.50" -ClientId "AA-BB-CC-DD-EE-FF" -Name "Imprimante"

# Exclusions
Add-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0" -StartRange "192.168.1.1" -EndRange "192.168.1.20"

# Diagnostic
Get-DhcpServerv4Scope
Get-DhcpServerv4Lease -ScopeId "192.168.1.0"
Get-DhcpServerv4Statistics
```

---

## Pour aller plus loin

- [Documentation Microsoft - DHCP Server](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-top)
- [Documentation Microsoft - DHCP Failover](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-failover)
- [PowerShell DHCP Cmdlets](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/)
- [DHCP Security Best Practices](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-security)
