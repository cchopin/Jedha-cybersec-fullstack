# DHCP avec Active Directory

**Module** : installer et configurer un serveur DHCP dans un environnement AD

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle de DHCP dans un environnement Active Directory
- Installer et configurer le rôle DHCP sur Windows Server
- Créer et paramétrer une étendue (scope) DHCP
- Configurer les options DHCP (DNS, passerelle, réservations)
- Mettre en place la haute disponibilité DHCP

---

## 1. Rappel sur DHCP

### 1.1 Fonctionnement

Le protocole **DHCP** (Dynamic Host Configuration Protocol) permet d'attribuer automatiquement une configuration réseau (adresse IP, masque de sous-réseau, passerelle, serveurs DNS) aux machines du réseau. Sans DHCP, chaque machine devrait être configurée manuellement.

### 1.2 Processus DORA

L'attribution d'une adresse DHCP suit le processus **DORA** :

| Étape | Message | Direction | Description |
|---|---|---|---|
| **D** | DHCP Discover | Client → Broadcast | Le client cherche un serveur DHCP sur le réseau |
| **O** | DHCP Offer | Serveur → Client | Le serveur propose une adresse IP |
| **R** | DHCP Request | Client → Broadcast | Le client accepte l'offre |
| **A** | DHCP Acknowledge | Serveur → Client | Le serveur confirme l'attribution |

---

## 2. Prérequis : adresse IP statique

Avant d'installer le rôle DHCP, le serveur **doit** avoir une adresse IP statique. Un serveur DHCP ne peut pas être configuré avec une adresse dynamique.

```powershell
# Vérifier la configuration IP actuelle
Get-NetIPAddress -InterfaceAlias "Ethernet"

# Configurer une IP statique si nécessaire
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.10" -PrefixLength 24 -DefaultGateway "192.168.1.1"

# Configurer le DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10","8.8.8.8"
```

---

## 3. Installation du rôle DHCP

### 3.1 Via l'interface graphique

1. Ouvrir **Server Manager**
2. Cliquer sur **Manage > Add Roles and Features**
3. Suivre l'assistant :
   - **Installation Type** : Role-based or feature-based installation
   - **Server Selection** : sélectionner le serveur cible
   - **Server Roles** : cocher **DHCP Server**
4. Accepter les fonctionnalités dépendantes
5. Lancer l'installation
6. Après l'installation, compléter la configuration post-installation (notification dans Server Manager)

### 3.2 Via PowerShell

```powershell
# Installer le rôle DHCP
Install-WindowsFeature DHCP -IncludeManagementTools

# Autoriser le serveur DHCP dans Active Directory
Add-DhcpServerInDC -DnsName "DC1.jedha.local" -IPAddress "192.168.1.10"

# Vérifier l'autorisation
Get-DhcpServerInDC
```

> **À noter** : dans un environnement Active Directory, un serveur DHCP doit être **autorisé** dans AD pour fonctionner. Cette autorisation empêche les serveurs DHCP non autorisés (rogue DHCP) de distribuer des adresses IP sur le réseau. C'est une mesure de sécurité importante.

---

## 4. Configuration d'une étendue DHCP (Scope)

### 4.1 Paramètres d'une étendue

Une **étendue** (scope) DHCP définit la plage d'adresses IP à distribuer et les options associées :

| Paramètre | Description | Exemple |
|---|---|---|
| **Plage IP** | Première et dernière adresse de la plage | 192.168.1.100 - 192.168.1.200 |
| **Masque de sous-réseau** | Masque du réseau | 255.255.255.0 (/24) |
| **Exclusions** | Adresses à ne pas distribuer au sein de la plage | 192.168.1.150 - 192.168.1.155 |
| **Délai** | Temps avant qu'un DHCP Offer ne soit envoyé | 0 milliseconde (par défaut) |
| **Bail (Lease Time)** | Durée de validité de l'attribution IP | 8 jours (par défaut) |

### 4.2 Configuration via l'interface graphique

1. Ouvrir **DHCP Management Console** (dhcpmgmt.msc)
2. Développer le serveur > clic droit sur **IPv4 > New Scope**
3. Suivre l'assistant :
   - Nom et description de l'étendue
   - Plage d'adresses IP (début et fin)
   - Masque de sous-réseau
   - Exclusions (adresses réservées aux serveurs, imprimantes, etc.)
   - Durée du bail
   - Options DHCP (passerelle, DNS, etc.)
4. Activer l'étendue

### 4.3 Configuration via PowerShell

```powershell
# Créer une étendue DHCP
Add-DhcpServerv4Scope -Name "Reseau_Principal" `
    -StartRange "192.168.1.100" `
    -EndRange "192.168.1.200" `
    -SubnetMask "255.255.255.0" `
    -LeaseDuration (New-TimeSpan -Days 8) `
    -State Active

# Configurer la passerelle par défaut (option 3)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -Router "192.168.1.1"

# Configurer les serveurs DNS (option 6)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -OptionId 6 -Value "192.168.1.10","8.8.8.8"

# Configurer le nom de domaine DNS (option 15)
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -DnsDomain "jedha.local"
```

> **À noter** : l'option DHCP **OptionId 6** correspond aux serveurs DNS. C'est une option essentielle dans un environnement AD car les machines doivent pouvoir résoudre les enregistrements DNS du domaine pour fonctionner correctement (authentification Kerberos, localisation des DC, etc.).

---

## 5. Réservations et exclusions

### 5.1 Réservations

Une **réservation** DHCP associe de manière permanente une adresse IP à une adresse MAC spécifique. La machine recevra toujours la même adresse IP via DHCP, sans avoir besoin d'une configuration statique.

```powershell
# Créer une réservation DHCP
Add-DhcpServerv4Reservation -ScopeId "192.168.1.0" `
    -IPAddress "192.168.1.50" `
    -ClientId "AA-BB-CC-DD-EE-FF" `
    -Name "Imprimante_RDC" `
    -Description "Imprimante du rez-de-chaussée"

# Lister les réservations
Get-DhcpServerv4Reservation -ScopeId "192.168.1.0"
```

### 5.2 Exclusions

Une **exclusion** définit une plage d'adresses au sein de l'étendue qui ne sera pas distribuée par DHCP. Ces adresses sont réservées pour des équipements configurés en IP statique.

```powershell
# Ajouter une plage d'exclusion
Add-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0" `
    -StartRange "192.168.1.1" `
    -EndRange "192.168.1.20"

# Lister les exclusions
Get-DhcpServerv4ExclusionRange -ScopeId "192.168.1.0"
```

> **Bonne pratique** : réservez une plage d'adresses au début ou à la fin de l'étendue pour les équipements en IP statique (serveurs, switches, points d'accès, imprimantes) en utilisant une exclusion. Utilisez les réservations pour les équipements qui doivent avoir une IP fixe mais que vous souhaitez gérer centralement via DHCP.

---

## 6. Haute disponibilité DHCP

### 6.1 Nécessité

Si le serveur DHCP est indisponible, les machines dont le bail expire ne pourront plus obtenir de configuration réseau. Il est donc essentiel de mettre en place un mécanisme de haute disponibilité.

### 6.2 Modes de haute disponibilité

Windows Server propose deux modes de haute disponibilité pour DHCP :

| Mode | Description | Cas d'usage |
|---|---|---|
| **Load Balance** | Les deux serveurs DHCP servent activement les clients. La charge est répartie selon un pourcentage configurable (par défaut 50/50) | Les deux serveurs sont sur le même site |
| **Hot Standby** | Un serveur est actif (primary), l'autre est en attente (standby). Le standby prend le relais uniquement si le primary est indisponible | Les serveurs sont sur des sites différents |

### 6.3 Configuration

La configuration du failover se fait via la console DHCP :

1. Clic droit sur l'étendue > **Configure Failover**
2. Sélectionner le serveur partenaire
3. Choisir le mode (Load Balance ou Hot Standby)
4. Configurer les paramètres spécifiques au mode choisi
5. Définir un **shared secret** (clé partagée pour sécuriser la communication entre les deux serveurs)

> **Bonne pratique** : dans un environnement à site unique, le mode **Load Balance** est préférable car il répartit la charge et offre une bascule automatique. Dans un environnement multi-sites, le mode **Hot Standby** est adapté pour le serveur DHCP distant qui ne prend le relais qu'en cas de panne du serveur local.

---

## 7. Résumé des commandes PowerShell

```powershell
# Installation
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerInDC -DnsName "DC1.jedha.local" -IPAddress "192.168.1.10"

# Création d'étendue
Add-DhcpServerv4Scope -Name "Reseau" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -State Active

# Options
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -OptionId 6 -Value "192.168.1.10","8.8.8.8"
Set-DhcpServerv4OptionValue -ScopeId "192.168.1.0" -Router "192.168.1.1"

# Réservations
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
