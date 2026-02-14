# VPN dans Active Directory

**Module** : deployer et configurer un serveur VPN integre a Active Directory

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Connaitre les protocoles de tunneling VPN et leurs niveaux de securite
- Comprendre les protocoles d'authentification VPN
- Installer et configurer un serveur VPN sous Windows Server
- Configurer les politiques d'acces reseau (NPS)
- Configurer un client VPN sous Windows

---

## 1. Protocoles de tunneling

### 1.1 Presentation

Le **tunneling** est le mecanisme qui encapsule les donnees dans un tunnel chiffre entre le client VPN et le serveur VPN. Plusieurs protocoles de tunneling existent, avec des niveaux de securite differents.

### 1.2 Comparaison des protocoles

| Protocole | Statut | Securite | Port | Cas d'usage |
|---|---|---|---|---|
| **IKEv2** | Recommande | Eleve (IPSec, certificats) | UDP 500/4500 | Protocole par defaut recommande, supporte la reconnexion automatique |
| **L2TP/IPSec** | Legacy acceptable | Correct (IPSec, cle pre-partagee ou certificat) | UDP 1701/500/4500 | Alternative si IKEv2 n'est pas supporte |
| **SSTP** | Legacy acceptable | Correct (SSL/TLS) | TCP 443 | Utile lorsque les ports UDP sont bloques par le pare-feu |
| **PPTP** | Deprecie | Faible (MS-CHAPv2 cassable) | TCP 1723 + GRE | A eviter absolument, present uniquement pour retrocompatibilite |

### 1.3 Details des protocoles

**IKEv2 (Internet Key Exchange version 2)** :
- Protocole le plus moderne et le plus securise
- Utilise IPSec pour le chiffrement et l'integrite des donnees
- Supporte le **MOBIKE** (Mobility and Multihoming), permettant de maintenir la connexion VPN lors d'un changement de reseau (Wi-Fi vers 4G par exemple)
- Authentification par certificats ou EAP
- Reconnexion automatique en cas de perte temporaire de connexion

**L2TP/IPSec (Layer 2 Tunneling Protocol)** :
- Combine L2TP (tunneling) avec IPSec (chiffrement)
- Authentification par cle pre-partagee (PSK) ou certificat
- Double encapsulation (L2TP dans IPSec), ce qui ajoute un overhead
- Fonctionne bien mais est progressivement remplace par IKEv2

**SSTP (Secure Socket Tunneling Protocol)** :
- Protocole proprietaire Microsoft
- Utilise SSL/TLS sur le port 443 (HTTPS)
- Avantage : traverse facilement les pare-feux et les proxies car il utilise le meme port que le trafic web securise
- Limite : uniquement supporte nativement sous Windows

**PPTP (Point-to-Point Tunneling Protocol)** :
- Protocole le plus ancien, cree par Microsoft dans les annees 1990
- Chiffrement faible (MPPE base sur MS-CHAPv2)
- Les outils de craquage permettent de casser MS-CHAPv2 en temps reel
- A ne jamais utiliser en production

> **Bonne pratique** : utilisez **IKEv2** comme protocole de tunneling par defaut. Si les ports UDP sont bloques, basculez sur **SSTP**. N'utilisez jamais PPTP, meme pour des tests.

---

## 2. Protocoles d'authentification

### 2.1 Presentation

Le protocole d'authentification determine comment le client VPN prouve son identite au serveur. Il est distinct du protocole de tunneling.

### 2.2 Comparaison

| Protocole | Securite | Description | Recommandation |
|---|---|---|---|
| **PAP** | Tres faible | Envoie le mot de passe en clair | A eviter sauf dans un contexte SAN (Storage Area Network) isole |
| **MS-CHAPv2** | Correcte | Authentification challenge/response, mot de passe hashe | Recommande lorsqu'il est utilise avec TLS (SSTP) ou IPSec (IKEv2) |
| **EAP** | Elevee | Framework extensible supportant plusieurs methodes (certificats, smart cards, etc.) | Le plus securise, recommande pour les environnements exigeants |

### 2.3 EAP en detail

**EAP** (Extensible Authentication Protocol) est un framework d'authentification qui supporte plusieurs methodes :

| Methode EAP | Description |
|---|---|
| **EAP-TLS** | Authentification par certificat client et serveur. Le plus securise |
| **EAP-MSCHAPv2** | MS-CHAPv2 encapsule dans un tunnel TLS (PEAP). Bon compromis securite/simplicite |
| **EAP-TTLS** | Tunnel TLS avec methode d'authentification interne (similaire a PEAP) |

> **A noter** : **EAP-TLS** necessite un certificat sur chaque machine cliente, ce qui implique une infrastructure PKI (Public Key Infrastructure). C'est la methode la plus securisee mais aussi la plus complexe a deployer. **EAP-MSCHAPv2** (via PEAP) est le compromis le plus courant en entreprise.

---

## 3. Installation du serveur VPN

### 3.1 Roles requis

L'installation d'un serveur VPN sous Windows Server necessite deux roles :

| Role | Description |
|---|---|
| **Remote Access** | Fournit les services VPN (DirectAccess et Routing and Remote Access) |
| **Network Policy and Access Services (NPS)** | Gere les politiques d'acces reseau (conditions d'autorisation, contraintes) |

### 3.2 Installation via l'interface graphique

1. Ouvrir **Server Manager**
2. **Manage > Add Roles and Features**
3. Selectionner les roles :
   - **Remote Access** > cocher **DirectAccess and VPN (RAS)**
   - **Network Policy and Access Services**
4. Accepter les fonctionnalites dependantes
5. Lancer l'installation

### 3.3 Installation via PowerShell

```powershell
# Installer le role Remote Access avec VPN
Install-WindowsFeature RemoteAccess -IncludeManagementTools
Install-WindowsFeature DirectAccess-VPN -IncludeManagementTools

# Installer le role NPS
Install-WindowsFeature NPAS -IncludeManagementTools
```

---

## 4. Configuration du serveur VPN

### 4.1 Routing and Remote Access (RRAS)

1. Ouvrir **Tools > Routing and Remote Access** (`rrasmgmt.msc`)
2. Clic droit sur le serveur > **Configure and Enable Routing and Remote Access**
3. Selectionner **Custom configuration**
4. Cocher **VPN access**
5. Demarrer le service

### 4.2 Configuration des proprietes du serveur VPN

Apres l'activation de RRAS, configurer les proprietes :

1. Clic droit sur le serveur > **Properties**
2. Onglet **Security** :
   - Selectionner le certificat SSL (pour SSTP et IKEv2)
   - Configurer le fournisseur d'authentification (Windows Authentication ou RADIUS)
3. Onglet **IPv4** :
   - Configurer la plage d'adresses IP a attribuer aux clients VPN
   - Ou utiliser DHCP pour l'attribution dynamique

---

## 5. Configuration du Network Policy Server (NPS)

### 5.1 Role du NPS

Le **NPS** (Network Policy Server) est le composant qui gere les politiques d'acces reseau. Il determine qui a le droit de se connecter au VPN et dans quelles conditions.

### 5.2 Creation d'une politique d'acces

1. Ouvrir **Tools > Network Policy Server** (`nps.msc`)
2. Developper **Policies > Network Policies**
3. Clic droit > **New**
4. Configurer la politique :

#### Conditions d'acces

Les conditions determinent a qui la politique s'applique :

| Condition | Description | Exemple |
|---|---|---|
| **Windows Groups** | Groupes de securite AD autorises | `GG_VPN_Users` |
| **Tunnel Type** | Type de protocole de tunneling | IKEv2, L2TP, SSTP |
| **Framed Protocol** | Protocole de trame | PPP |
| **NAS Port Type** | Type de port d'acces | Virtual (VPN) |
| **Day and Time Restrictions** | Plages horaires autorisees | Lundi-Vendredi, 08h-20h |
| **Called Station ID** | Adresse IP du serveur VPN | 192.168.1.10 |
| **Calling Station ID** | Plage IP des clients | 10.0.0.0/8 |

#### Contraintes

Les contraintes definissent les methodes d'authentification autorisees :

- Selectionner les protocoles d'authentification (EAP, MS-CHAPv2)
- Definir le timeout de la session
- Configurer le type de connexion (VPN uniquement)

#### Parametres

Les parametres definissent les options appliquees apres l'authentification :

- Attribution d'adresse IP
- Filtres IP
- Chiffrement (obligatoire)

```
Exemple de politique NPS :
- Condition : membre du groupe "GG_VPN_Users"
- Condition : Tunnel Type = IKEv2 ou SSTP
- Condition : Horaire = Lundi-Vendredi 08h-20h
- Contrainte : Authentification = EAP-MSCHAPv2
- Permission : Autoriser l'acces
```

> **Bonne pratique** : creez un groupe de securite AD dedie aux utilisateurs VPN (par exemple `GG_VPN_Users`) et utilisez ce groupe comme condition dans la politique NPS. Ne donnez jamais l'acces VPN a "Domain Users" sans filtrage supplementaire.

---

## 6. Configuration du client VPN

### 6.1 Configuration sous Windows

Windows integre nativement un client VPN. La configuration se fait via :

1. **Settings > Network & Internet > VPN > Add a VPN connection**
2. Renseigner les parametres :

| Parametre | Valeur |
|---|---|
| **VPN provider** | Windows (built-in) |
| **Connection name** | Nom personnalise (ex: "VPN Jedha") |
| **Server name or address** | FQDN ou IP du serveur VPN (ex: `vpn.jedha.local`) |
| **VPN type** | IKEv2 (recommande) ou Automatic |
| **Type of sign-in info** | Username and password |
| **Username** | `jedha\jdupont` ou `jdupont@jedha.local` |

### 6.2 Configuration avancee

Apres la creation de la connexion, des parametres supplementaires doivent etre verifies :

1. Ouvrir **Control Panel > Network and Sharing Center > Change adapter settings**
2. Clic droit sur la connexion VPN > **Properties**
3. Onglet **Security** :
   - Verifier le type de VPN (IKEv2)
   - Dans **Authentication**, s'assurer que **MS-CHAPv2** est coche (ou EAP selon la politique)

> **A noter** : une erreur frequente est d'oublier d'activer **MS-CHAPv2** dans les proprietes de la connexion VPN cote client. Si le serveur NPS exige MS-CHAPv2 et que le client ne le propose pas, la connexion echouera avec une erreur d'authentification.

### 6.3 Connexion via PowerShell

```powershell
# Creer une connexion VPN
Add-VpnConnection -Name "VPN Jedha" `
    -ServerAddress "vpn.jedha.local" `
    -TunnelType "Ikev2" `
    -AuthenticationMethod "MSChapv2" `
    -EncryptionLevel "Required"

# Se connecter
rasdial "VPN Jedha" jdupont P@ssw0rd123!

# Verifier l'etat de la connexion
Get-VpnConnection -Name "VPN Jedha"

# Se deconnecter
rasdial "VPN Jedha" /disconnect
```

---

## 7. Diagnostic

### 7.1 Cote serveur

```powershell
# Verifier le statut du service RRAS
Get-Service RemoteAccess

# Voir les connexions VPN actives
Get-RemoteAccessConnectionStatistics

# Consulter les logs NPS
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=6272 or EventID=6273]]" | Select-Object TimeCreated, Message -First 10
```

Les evenements NPS cles :

| Event ID | Description |
|---|---|
| **6272** | Acces accorde par NPS |
| **6273** | Acces refuse par NPS |
| **6274** | Requete rejetee par NPS |
| **6278** | Connexion VPN completement autorisee |

### 7.2 Cote client

```powershell
# Tester la connectivite vers le serveur VPN
Test-NetConnection -ComputerName "vpn.jedha.local" -Port 443

# Verifier la resolution DNS du serveur VPN
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
