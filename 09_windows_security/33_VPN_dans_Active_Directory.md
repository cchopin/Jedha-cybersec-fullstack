# VPN dans Active Directory

**Module** : déployer et configurer un serveur VPN intégré à Active Directory

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Connaître les protocoles de tunneling VPN et leurs niveaux de sécurité
- Comprendre les protocoles d'authentification VPN
- Installer et configurer un serveur VPN sous Windows Server
- Configurer les politiques d'accès réseau (NPS)
- Configurer un client VPN sous Windows

---

## 1. Protocoles de tunneling

### 1.1 Présentation

Le **tunneling** est le mécanisme qui encapsule les données dans un tunnel chiffré entre le client VPN et le serveur VPN. Plusieurs protocoles de tunneling existent, avec des niveaux de sécurité différents.

### 1.2 Comparaison des protocoles

| Protocole | Statut | Sécurité | Port | Cas d'usage |
|---|---|---|---|---|
| **IKEv2** | Recommandé | Élevé (IPSec, certificats) | UDP 500/4500 | Protocole par défaut recommandé, supporte la reconnexion automatique |
| **L2TP/IPSec** | Legacy acceptable | Correct (IPSec, clé pré-partagée ou certificat) | UDP 1701/500/4500 | Alternative si IKEv2 n'est pas supporté |
| **SSTP** | Legacy acceptable | Correct (SSL/TLS) | TCP 443 | Utile lorsque les ports UDP sont bloqués par le pare-feu |
| **PPTP** | Déprécié | Faible (MS-CHAPv2 cassable) | TCP 1723 + GRE | À éviter absolument, présent uniquement pour rétrocompatibilité |

### 1.3 Détails des protocoles

**IKEv2 (Internet Key Exchange version 2)** :
- Protocole le plus moderne et le plus sécurisé
- Utilise IPSec pour le chiffrement et l'intégrité des données
- Supporte le **MOBIKE** (Mobility and Multihoming), permettant de maintenir la connexion VPN lors d'un changement de réseau (Wi-Fi vers 4G par exemple)
- Authentification par certificats ou EAP
- Reconnexion automatique en cas de perte temporaire de connexion

**L2TP/IPSec (Layer 2 Tunneling Protocol)** :
- Combine L2TP (tunneling) avec IPSec (chiffrement)
- Authentification par clé pré-partagée (PSK) ou certificat
- Double encapsulation (L2TP dans IPSec), ce qui ajoute un overhead
- Fonctionne bien mais est progressivement remplacé par IKEv2

**SSTP (Secure Socket Tunneling Protocol)** :
- Protocole propriétaire Microsoft
- Utilise SSL/TLS sur le port 443 (HTTPS)
- Avantage : traverse facilement les pare-feux et les proxies car il utilise le même port que le trafic web sécurisé
- Limité : uniquement supporté nativement sous Windows

**PPTP (Point-to-Point Tunneling Protocol)** :
- Protocole le plus ancien, créé par Microsoft dans les années 1990
- Chiffrement faible (MPPE basé sur MS-CHAPv2)
- Les outils de craquage permettent de casser MS-CHAPv2 en temps réel
- À ne jamais utiliser en production

> **Bonne pratique** : utilisez **IKEv2** comme protocole de tunneling par défaut. Si les ports UDP sont bloqués, basculez sur **SSTP**. N'utilisez jamais PPTP, même pour des tests.

---

## 2. Protocoles d'authentification

### 2.1 Présentation

Le protocole d'authentification détermine comment le client VPN prouve son identité au serveur. Il est distinct du protocole de tunneling.

### 2.2 Comparaison

| Protocole | Sécurité | Description | Recommandation |
|---|---|---|---|
| **PAP** | Très faible | Envoie le mot de passe en clair | À éviter sauf dans un contexte SAN (Storage Area Network) isolé |
| **MS-CHAPv2** | Correcte | Authentification challenge/response, mot de passe haché | Recommandé lorsqu'il est utilisé avec TLS (SSTP) ou IPSec (IKEv2) |
| **EAP** | Élevée | Framework extensible supportant plusieurs méthodes (certificats, smart cards, etc.) | Le plus sécurisé, recommandé pour les environnements exigeants |

### 2.3 EAP en détail

**EAP** (Extensible Authentication Protocol) est un framework d'authentification qui supporte plusieurs méthodes :

| Méthode EAP | Description |
|---|---|
| **EAP-TLS** | Authentification par certificat client et serveur. Le plus sécurisé |
| **EAP-MSCHAPv2** | MS-CHAPv2 encapsulé dans un tunnel TLS (PEAP). Bon compromis sécurité/simplicité |
| **EAP-TTLS** | Tunnel TLS avec méthode d'authentification interne (similaire à PEAP) |

> **À noter** : **EAP-TLS** nécessite un certificat sur chaque machine cliente, ce qui implique une infrastructure PKI (Public Key Infrastructure). C'est la méthode la plus sécurisée mais aussi la plus complexe à déployer. **EAP-MSCHAPv2** (via PEAP) est le compromis le plus courant en entreprise.

---

## 3. Installation du serveur VPN

### 3.1 Rôles requis

L'installation d'un serveur VPN sous Windows Server nécessite deux rôles :

| Rôle | Description |
|---|---|
| **Remote Access** | Fournit les services VPN (DirectAccess et Routing and Remote Access) |
| **Network Policy and Access Services (NPS)** | Gère les politiques d'accès réseau (conditions d'autorisation, contraintes) |

### 3.2 Installation via l'interface graphique

1. Ouvrir **Server Manager**
2. **Manage > Add Roles and Features**
3. Sélectionner les rôles :
   - **Remote Access** > cocher **DirectAccess and VPN (RAS)**
   - **Network Policy and Access Services**
4. Accepter les fonctionnalités dépendantes
5. Lancer l'installation

### 3.3 Installation via PowerShell

```powershell
# Installer le rôle Remote Access avec VPN
Install-WindowsFeature RemoteAccess -IncludeManagementTools
Install-WindowsFeature DirectAccess-VPN -IncludeManagementTools

# Installer le rôle NPS
Install-WindowsFeature NPAS -IncludeManagementTools
```

---

## 4. Configuration du serveur VPN

### 4.1 Routing and Remote Access (RRAS)

1. Ouvrir **Tools > Routing and Remote Access** (`rrasmgmt.msc`)
2. Clic droit sur le serveur > **Configure and Enable Routing and Remote Access**
3. Sélectionner **Custom configuration**
4. Cocher **VPN access**
5. Démarrer le service

### 4.2 Configuration des propriétés du serveur VPN

Après l'activation de RRAS, configurer les propriétés :

1. Clic droit sur le serveur > **Properties**
2. Onglet **Security** :
   - Sélectionner le certificat SSL (pour SSTP et IKEv2)
   - Configurer le fournisseur d'authentification (Windows Authentication ou RADIUS)
3. Onglet **IPv4** :
   - Configurer la plage d'adresses IP à attribuer aux clients VPN
   - Ou utiliser DHCP pour l'attribution dynamique

---

## 5. Configuration du Network Policy Server (NPS)

### 5.1 Rôle du NPS

Le **NPS** (Network Policy Server) est le composant qui gère les politiques d'accès réseau. Il détermine qui a le droit de se connecter au VPN et dans quelles conditions.

### 5.2 Création d'une politique d'accès

1. Ouvrir **Tools > Network Policy Server** (`nps.msc`)
2. Développer **Policies > Network Policies**
3. Clic droit > **New**
4. Configurer la politique :

#### Conditions d'accès

Les conditions déterminent à qui la politique s'applique :

| Condition | Description | Exemple |
|---|---|---|
| **Windows Groups** | Groupes de sécurité AD autorisés | `GG_VPN_Users` |
| **Tunnel Type** | Type de protocole de tunneling | IKEv2, L2TP, SSTP |
| **Framed Protocol** | Protocole de trame | PPP |
| **NAS Port Type** | Type de port d'accès | Virtual (VPN) |
| **Day and Time Restrictions** | Plages horaires autorisées | Lundi-Vendredi, 08h-20h |
| **Called Station ID** | Adresse IP du serveur VPN | 192.168.1.10 |
| **Calling Station ID** | Plage IP des clients | 10.0.0.0/8 |

#### Contraintes

Les contraintes définissent les méthodes d'authentification autorisées :

- Sélectionner les protocoles d'authentification (EAP, MS-CHAPv2)
- Définir le timeout de la session
- Configurer le type de connexion (VPN uniquement)

#### Paramètres

Les paramètres définissent les options appliquées après l'authentification :

- Attribution d'adresse IP
- Filtres IP
- Chiffrement (obligatoire)

```
Exemple de politique NPS :
- Condition : membre du groupe "GG_VPN_Users"
- Condition : Tunnel Type = IKEv2 ou SSTP
- Condition : Horaire = Lundi-Vendredi 08h-20h
- Contrainte : Authentification = EAP-MSCHAPv2
- Permission : Autoriser l'accès
```

> **Bonne pratique** : créez un groupe de sécurité AD dédié aux utilisateurs VPN (par exemple `GG_VPN_Users`) et utilisez ce groupe comme condition dans la politique NPS. Ne donnez jamais l'accès VPN à "Domain Users" sans filtrage supplémentaire.

---

## 6. Configuration du client VPN

### 6.1 Configuration sous Windows

Windows intègre nativement un client VPN. La configuration se fait via :

1. **Settings > Network & Internet > VPN > Add a VPN connection**
2. Renseigner les paramètres :

| Paramètre | Valeur |
|---|---|
| **VPN provider** | Windows (built-in) |
| **Connection name** | Nom personnalisé (ex: "VPN Jedha") |
| **Server name or address** | FQDN ou IP du serveur VPN (ex: `vpn.jedha.local`) |
| **VPN type** | IKEv2 (recommandé) ou Automatic |
| **Type of sign-in info** | Username and password |
| **Username** | `jedha\jdupont` ou `jdupont@jedha.local` |

### 6.2 Configuration avancée

Après la création de la connexion, des paramètres supplémentaires doivent être vérifiés :

1. Ouvrir **Control Panel > Network and Sharing Center > Change adapter settings**
2. Clic droit sur la connexion VPN > **Properties**
3. Onglet **Security** :
   - Vérifier le type de VPN (IKEv2)
   - Dans **Authentication**, s'assurer que **MS-CHAPv2** est coché (ou EAP selon la politique)

> **À noter** : une erreur fréquente est d'oublier d'activer **MS-CHAPv2** dans les propriétés de la connexion VPN côté client. Si le serveur NPS exige MS-CHAPv2 et que le client ne le propose pas, la connexion échouera avec une erreur d'authentification.

### 6.3 Connexion via PowerShell

```powershell
# Créer une connexion VPN
Add-VpnConnection -Name "VPN Jedha" `
    -ServerAddress "vpn.jedha.local" `
    -TunnelType "Ikev2" `
    -AuthenticationMethod "MSChapv2" `
    -EncryptionLevel "Required"

# Se connecter
rasdial "VPN Jedha" jdupont P@ssw0rd123!

# Vérifier l'état de la connexion
Get-VpnConnection -Name "VPN Jedha"

# Se déconnecter
rasdial "VPN Jedha" /disconnect
```

---

## 7. Diagnostic

### 7.1 Côté serveur

```powershell
# Vérifier le statut du service RRAS
Get-Service RemoteAccess

# Voir les connexions VPN actives
Get-RemoteAccessConnectionStatistics

# Consulter les logs NPS
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=6272 or EventID=6273]]" | Select-Object TimeCreated, Message -First 10
```

Les événements NPS clés :

| Event ID | Description |
|---|---|
| **6272** | Accès accordé par NPS |
| **6273** | Accès refusé par NPS |
| **6274** | Requête rejetée par NPS |
| **6278** | Connexion VPN complètement autorisée |

### 7.2 Côté client

```powershell
# Tester la connectivité vers le serveur VPN
Test-NetConnection -ComputerName "vpn.jedha.local" -Port 443

# Vérifier la résolution DNS du serveur VPN
Resolve-DnsName -Name "vpn.jedha.local"

# Afficher les logs de connexion VPN
Get-WinEvent -LogName "Application" -FilterXPath "*[System[Provider[@Name='RasClient']]]" -MaxEvents 20
```

---

## Pour aller plus loin

- [Documentation Microsoft - Remote Access VPN](https://learn.microsoft.com/en-us/windows-server/remote/remote-access/vpn/vpn-top)
- [Documentation Microsoft - Network Policy Server](https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top)
- [Comparaison des protocoles VPN](https://learn.microsoft.com/en-us/windows-server/remote/remote-access/vpn/vpn-device-tunnel-config)
- [IKEv2 Configuration Guide](https://learn.microsoft.com/en-us/windows-server/remote/remote-access/vpn/always-on-vpn/deploy/vpn-deploy-client-vpn-connections)
- [NIST SP 800-77 - Guide to IPsec VPNs](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)
