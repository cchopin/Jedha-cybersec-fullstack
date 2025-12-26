# Modèle OSI et TCP/IP 

## Introduction

Les modèles OSI et TCP/IP sont des frameworks qui décrivent comment les données voyagent d'un appareil à un autre. Comprendre ces couches est essentiel pour :

- **Troubleshooting** : isoler où se situe un problème (câble ? DNS ? routage ?)
- **Standardisation** : tous les appareils parlent le même langage
- **Design modulaire** : améliorer une couche sans affecter les autres
- **Communication claire** : "problème Layer 3" = problème de routage

**Le modèle OSI est conceptuel (7 couches), le modèle TCP/IP est l'implémentation réelle (4 couches).**

---

## Glossaire

### Modèles et concepts généraux

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **OSI** | Open Systems Interconnection | Modèle théorique à 7 couches décrivant les communications réseau |
| **TCP/IP** | Transmission Control Protocol / Internet Protocol | Modèle pratique à 4 couches utilisé sur Internet |
| **PDU** | Protocol Data Unit | Unité de données à chaque couche (bits, trame, paquet, segment, données) |
| **MTU** | Maximum Transmission Unit | Taille maximale d'un paquet pouvant être transmis sans fragmentation |
| **TTL** | Time To Live | Compteur décrémenté à chaque routeur, évite les boucles infinies. Quand TTL=0, le paquet est détruit |

### Couche 1 et 2 (physique et liaison)

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **MAC** | Media Access Control | Adresse physique unique de la carte réseau (48 bits, ex: 00:1A:2B:3C:4D:5E) |
| **CRC** | Cyclic Redundancy Check | Algorithme de détection d'erreurs utilisé dans les trames |
| **FCS** | Frame Check Sequence | Champ de la trame Ethernet contenant le CRC pour vérifier l'intégrité |
| **CSMA/CD** | Carrier Sense Multiple Access with Collision Detection | Méthode d'accès au médium Ethernet : écouter, émettre, détecter les collisions |
| **CSMA/CA** | Carrier Sense Multiple Access with Collision Avoidance | Méthode d'accès Wi-Fi : écouter et éviter les collisions |
| **RTS/CTS** | Request To Send / Clear To Send | Mécanisme Wi-Fi pour réserver le canal avant d'émettre |
| **IEEE** | Institute of Electrical and Electronics Engineers | Organisation qui définit les standards (802.3 = Ethernet, 802.11 = Wi-Fi) |
| **CAM** | Content Addressable Memory | Table du switch associant adresses MAC et ports physiques |
| **STP** | Spanning Tree Protocol | Protocole évitant les boucles dans les réseaux commutés |
| **BPDU** | Bridge Protocol Data Unit | Messages échangés par STP pour élire le root bridge |
| **VLAN** | Virtual Local Area Network | Segmentation logique d'un réseau physique en plusieurs réseaux virtuels |
| **DTP** | Dynamic Trunking Protocol | Protocole Cisco pour négocier automatiquement les trunks (à désactiver pour la sécurité) |

### Couche 3 (réseau)

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **IP** | Internet Protocol | Protocole d'adressage et de routage (IPv4 sur 32 bits, IPv6 sur 128 bits) |
| **ICMP** | Internet Control Message Protocol | Protocole de diagnostic et d'erreur (ping, traceroute) |
| **ARP** | Address Resolution Protocol | Résolution d'adresse IP vers adresse MAC (IPv4 uniquement) |
| **OSPF** | Open Shortest Path First | Protocole de routage interne (IGP) à état de liens |
| **BGP** | Border Gateway Protocol | Protocole de routage entre systèmes autonomes (Internet) |
| **RPKI** | Resource Public Key Infrastructure | Infrastructure cryptographique pour sécuriser les annonces BGP |
| **uRPF** | Unicast Reverse Path Forwarding | Technique anti-spoofing vérifiant la cohérence des adresses source |
| **ACL** | Access Control List | Liste de règles sur un routeur/firewall autorisant ou bloquant le trafic |

### Couche 4 (transport)

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **TCP** | Transmission Control Protocol | Protocole de transport fiable avec connexion, accusés de réception, retransmission |
| **UDP** | User Datagram Protocol | Protocole de transport rapide sans connexion ni garantie de livraison |
| **SYN** | Synchronize | Flag TCP pour initier une connexion (premier message du three-way handshake) |
| **ACK** | Acknowledge | Flag TCP accusant réception des données |
| **RST** | Reset | Flag TCP pour terminer brutalement une connexion |
| **FIN** | Finish | Flag TCP pour terminer proprement une connexion |

### Couches 5-6-7 (session, présentation, application)

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **RPC** | Remote Procedure Call | Protocole permettant d'exécuter des procédures sur une machine distante |
| **NetBIOS** | Network Basic Input/Output System | Interface de communication pour réseaux locaux Windows |
| **SMB** | Server Message Block | Protocole de partage de fichiers Windows (port 445) |
| **SSL** | Secure Sockets Layer | Ancien protocole de chiffrement (obsolète, remplacé par TLS) |
| **TLS** | Transport Layer Security | Protocole de chiffrement des communications (HTTPS, SMTPS, etc.) |
| **ASCII** | American Standard Code for Information Interchange | Encodage de caractères sur 7 bits |
| **UTF-8** | Unicode Transformation Format 8-bit | Encodage de caractères universel |
| **JSON** | JavaScript Object Notation | Format d'échange de données textuelles structurées |
| **XML** | eXtensible Markup Language | Format de données structurées à balises |

### Protocoles applicatifs courants

| Sigle | Nom complet | Port | Description |
|-------|-------------|------|-------------|
| **HTTP** | HyperText Transfer Protocol | 80 | Protocole web non chiffré |
| **HTTPS** | HTTP Secure | 443 | Protocole web chiffré (HTTP + TLS) |
| **FTP** | File Transfer Protocol | 20/21 | Transfert de fichiers (non sécurisé) |
| **SSH** | Secure Shell | 22 | Shell distant chiffré, transfert sécurisé |
| **SMTP** | Simple Mail Transfer Protocol | 25/587 | Envoi d'emails |
| **POP3** | Post Office Protocol v3 | 110 | Récupération d'emails (télécharge et supprime) |
| **IMAP** | Internet Message Access Protocol | 143 | Récupération d'emails (synchronisé avec serveur) |
| **DNS** | Domain Name System | 53 | Résolution de noms de domaine en adresses IP |
| **DHCP** | Dynamic Host Configuration Protocol | 67/68 | Attribution automatique d'adresses IP |
| **SNMP** | Simple Network Management Protocol | 161/162 | Supervision et gestion d'équipements réseau |
| **LDAP** | Lightweight Directory Access Protocol | 389/636 | Accès aux annuaires (Active Directory, etc.) |
| **RDP** | Remote Desktop Protocol | 3389 | Bureau distant Windows |
| **NTP** | Network Time Protocol | 123 | Synchronisation horaire |

### Sécurité réseau

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **IDS** | Intrusion Detection System | Système de détection d'intrusions (alerte sans bloquer) |
| **IPS** | Intrusion Prevention System | Système de prévention d'intrusions (détecte et bloque) |
| **WAF** | Web Application Firewall | Pare-feu applicatif protégeant les applications web |
| **NAC** | Network Access Control | Contrôle d'accès au réseau (vérification avant connexion) |
| **VPN** | Virtual Private Network | Tunnel chiffré à travers un réseau non sécurisé |
| **DAI** | Dynamic ARP Inspection | Fonctionnalité de switch validant les paquets ARP |
| **DPI** | Deep Packet Inspection | Analyse du contenu des paquets au-delà des en-têtes |

### Sécurité applicative et email

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **XSS** | Cross-Site Scripting | Injection de scripts malveillants dans les pages web |
| **CSRF** | Cross-Site Request Forgery | Exploitation de la session pour effectuer des actions non voulues |
| **SQL** | Structured Query Language | Langage de base de données (cible des injections SQL) |
| **OWASP** | Open Web Application Security Project | Organisation définissant les standards de sécurité web (Top 10) |
| **HSTS** | HTTP Strict Transport Security | En-tête forçant l'utilisation de HTTPS |
| **CSP** | Content Security Policy | En-tête limitant les sources de contenu autorisées |
| **SPF** | Sender Policy Framework | Enregistrement DNS listant les serveurs autorisés à envoyer des emails pour un domaine |
| **DKIM** | DomainKeys Identified Mail | Signature cryptographique des emails |
| **DMARC** | Domain-based Message Authentication, Reporting & Conformance | Politique combinant SPF et DKIM avec reporting |

### Types d'attaques

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **DoS** | Denial of Service | Attaque visant à rendre un service indisponible |
| **DDoS** | Distributed Denial of Service | DoS distribué depuis de multiples sources |
| **MitM** | Man-in-the-Middle | Attaque où l'attaquant s'intercale entre deux parties |
| **PoD** | Ping of Death | Attaque historique par paquets ICMP malformés |

---

## Le modèle OSI (7 couches)

Le modèle Open Systems Interconnection est un framework à 7 couches qui standardise les fonctions d'un système de communication.

### Vue d'ensemble

| Couche | Nom | Fonction principale | PDU |
|--------|-----|---------------------|-----|
| 7 | Application | Interface utilisateur | Données |
| 6 | Présentation | Traduction, chiffrement | Données |
| 5 | Session | Gestion des sessions | Données |
| 4 | Transport | Fiabilité, segmentation | Segment |
| 3 | Réseau | Routage, adressage IP | Paquet |
| 2 | Liaison | Adressage MAC, trames | Trame |
| 1 | Physique | Transmission des bits | Bits |

---

## Détail des couches OSI

### Couche 1 : physique

**Fonction** : transmission des bits bruts sur un médium physique (fibre optique, cuivre, Wi-Fi).

**Éléments clés** :
- Niveaux de tension
- Débits de données
- Spécifications des câbles (Ethernet, coaxial)
- Connecteurs physiques
- Modulation du signal

**Exemples** :
- Câbles réseau (Cat5e, Cat6, fibre)
- Hubs
- Répéteurs
- Fréquences radio (Wi-Fi)

**Sécurité couche 1** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| Écoute physique (wiretapping) | Branchement physique sur le câble pour intercepter le signal | Fibre optique (détection d'intrusion), câblage sécurisé, locaux verrouillés |
| Jamming (brouillage) | Perturbation des signaux radio Wi-Fi | Détection de brouillage, fréquences alternatives, câblage filaire pour les zones critiques |
| Accès physique non autorisé | Connexion d'un appareil pirate sur le réseau | Contrôle d'accès physique, port security, NAC (Network Access Control) |
| Keylogger matériel | Dispositif entre le clavier et l'ordinateur | Inspection physique, ports USB verrouillés |

**Applications cyber** :
- Audit de sécurité physique des datacenters
- Détection de dispositifs d'écoute (bug sweeping)
- Analyse des vulnérabilités Wi-Fi (canaux, puissance du signal)
- Vérification de l'intégrité du câblage

---

### Couche 2 : liaison de données

**Fonction** : fournit la détection d'erreurs, le framing et le contrôle d'accès au médium. Assure une transmission fiable sur la couche physique.

#### Le framing (tramage) : emballer les données

La couche 1 (physique) ne transmet que des bits bruts (0 et 1). Elle ne sait pas où commence et où finit un message. Le **framing** consiste à organiser ces bits en unités logiques appelées **trames** (frames).

**Analogie** : une longue suite de lettres sans espaces ni ponctuation serait illisible. Le framing revient à ajouter des espaces et des points pour délimiter les mots et les phrases.

**Structure d'une trame Ethernet** :

```
|  Préambule  | MAC dest | MAC src |  Type  |    Données (payload)    |   FCS   |
|   8 octets  | 6 octets | 6 octets| 2 oct. |    46-1500 octets       | 4 octets|
|<-- Synchro -->|<----- En-tête (header) ----->|<---- Paquet IP ---->|<- Contrôle ->|
```

| Champ | Rôle |
|-------|------|
| Préambule | Synchronisation (permet au récepteur de se caler sur le signal) |
| MAC destination | Adresse physique du destinataire |
| MAC source | Adresse physique de l'émetteur |
| Type/Length | Indique le protocole de couche 3 (0x0800 = IPv4, 0x86DD = IPv6) |
| Données (payload) | Le paquet IP de la couche supérieure |
| FCS (Frame Check Sequence) | Somme de contrôle CRC pour détecter les erreurs de transmission |

**Le framing permet de** :
- Savoir où commence et finit chaque message
- Identifier l'émetteur et le destinataire (adresses MAC)
- Vérifier que les données n'ont pas été corrompues (CRC)

#### L'accès au médium : qui parle et quand ?

Le **médium** (ou support), c'est le canal physique partagé : le câble Ethernet, les ondes Wi-Fi, etc. Quand plusieurs appareils partagent le même médium, il faut des règles pour éviter que tout le monde parle en même temps (collision).

**Analogie** : dans une réunion, si tout le monde parle en même temps, personne ne comprend rien. Il faut un protocole : lever la main, attendre son tour, etc.

**Deux grandes approches** :

| Méthode | Principe | Exemple |
|---------|----------|---------|
| **CSMA/CD** (Carrier Sense Multiple Access with Collision Detection) | Écouter avant de parler. Si collision détectée, arrêter et réessayer après un délai aléatoire | Ethernet filaire (historique, hubs) |
| **CSMA/CA** (Carrier Sense Multiple Access with Collision Avoidance) | Écouter avant de parler + mécanismes pour éviter les collisions (RTS/CTS) | Wi-Fi (802.11) |

**CSMA/CD expliqué** :

```
1. La station veut émettre
2. Elle écoute le médium (Carrier Sense)
   → Si occupé : attendre
   → Si libre : émettre
3. Pendant l'émission, elle surveille les collisions
4. Si collision détectée :
   → Arrêter l'émission
   → Envoyer un signal de collision (jam)
   → Attendre un temps aléatoire (backoff)
   → Recommencer à l'étape 1
```

**Aujourd'hui avec les switches** : les collisions sont rares car chaque port du switch est un domaine de collision séparé (full-duplex). CSMA/CD est moins pertinent qu'à l'époque des hubs.

**CSMA/CA (Wi-Fi)** : les collisions ne peuvent pas être détectées en radio (on ne peut pas écouter et émettre en même temps). Donc on essaie de les **éviter** :
- Écouter si le canal est libre
- Attendre un temps aléatoire avant d'émettre
- Optionnel : demander la permission (RTS/CTS)

#### Implications sécurité du médium partagé

| Risque | Explication |
|--------|-------------|
| Sniffing (écoute passive) | Sur un médium partagé (hub, Wi-Fi), tous les appareils voient tout le trafic |
| Collision attacks | Provoquer des collisions pour perturber le réseau (DoS) |
| Wi-Fi eavesdropping | Les ondes radio sont captables par tous dans le rayon de couverture |

**Éléments clés** :
- Framing des données (organisation en trames)
- Adressage physique (adresses MAC)
- Contrôle d'accès au médium (CSMA/CD, CSMA/CA)
- Détection et correction d'erreurs (CRC)
- Contrôle de flux

**Exemples** :
- Switches
- Ethernet (IEEE 802.3)
- Wi-Fi (IEEE 802.11)
- ARP (Address Resolution Protocol)

**Sécurité couche 2** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| ARP spoofing/poisoning | Usurpation d'adresse MAC pour intercepter le trafic | Dynamic ARP Inspection (DAI), ARP statique, segmentation VLAN |
| MAC flooding | Saturation de la table CAM du switch pour le forcer en mode hub | Port security (limite MAC/port), storm control |
| MAC spoofing | Usurpation d'adresse MAC pour contourner les filtres | Port security, 802.1X authentication |
| VLAN hopping | Accès non autorisé à d'autres VLANs via double tagging | Désactiver DTP, VLAN natif dédié, trunk explicites |
| STP manipulation | Manipulation du Spanning Tree pour devenir root bridge | BPDU Guard, Root Guard, STP security |
| CAM table overflow | Débordement de la table d'adresses MAC | Port security avec limite stricte |

**Applications cyber** :
- Pentest Layer 2 avec des outils comme Yersinia, macchanger
- Configuration sécurisée des switches (port security, BPDU guard)
- Détection d'anomalies ARP avec arpwatch
- Forensics : analyse des trames Ethernet avec Wireshark
- Segmentation réseau par VLAN pour limiter la propagation latérale

---

### Couche 3 : réseau

**Fonction** : routage et adressage logique. Détermine le meilleur chemin pour les données de la source à la destination.

**Éléments clés** :
- Adressage IP (IPv4, IPv6)
- Routage
- Forwarding de paquets
- Fragmentation et réassemblage

**Exemples** :
- Routeurs
- Protocoles IPv4 et IPv6
- ICMP (ping, traceroute)
- Protocoles de routage (OSPF, BGP, RIP)

**Sécurité couche 3** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| IP spoofing | Usurpation d'adresse IP source | Filtrage ingress/egress (BCP38), uRPF |
| ICMP attacks | Smurf attack, ping flood, ICMP redirect | Rate limiting ICMP, filtrage des types ICMP dangereux |
| Route hijacking | Annonce de routes BGP frauduleuses | RPKI, filtrage de préfixes, monitoring BGP |
| Fragmentation attacks | Exploitation de la fragmentation IP (teardrop, ping of death) | Réassemblage sécurisé, IDS/IPS |
| Rogue router | Routeur pirate injectant de fausses routes | Authentification des protocoles de routage (MD5, SHA) |
| Reconnaissance | Scan réseau, traceroute, ping sweep | Firewall, rate limiting, honeypots |

**Applications cyber** :
- Reconnaissance réseau avec nmap, masscan
- Analyse de routage et détection d'anomalies BGP
- Configuration de filtres ACL sur les routeurs
- Détection de scans avec IDS (Snort, Suricata)
- Forensics : analyse des en-têtes IP, TTL analysis
- Géolocalisation IP et attribution

---

### Couche 4 : transport

**Fonction** : communication de bout en bout entre appareils. Contrôle la fiabilité, l'intégrité des données et le flux.

**Éléments clés** :
- Segmentation et réassemblage
- Contrôle de flux
- Récupération d'erreurs
- Adressage par ports

**Protocoles principaux** :

| Protocole | Caractéristiques | Cas d'usage |
|-----------|------------------|-------------|
| TCP | Fiable, orienté connexion, three-way handshake | HTTP, SSH, FTP, SMTP |
| UDP | Non fiable, sans connexion, rapide | DNS, VoIP, streaming, gaming |

**Ports courants** :

| Port | Service | Protocole |
|------|---------|-----------|
| 20/21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67/68 | DHCP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3389 | RDP | TCP |

**Sécurité couche 4** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| SYN flood | Saturation avec des demandes de connexion TCP | SYN cookies, rate limiting, pare-feu stateful |
| UDP flood | Saturation avec des paquets UDP | Rate limiting, filtrage |
| Port scanning | Énumération des services ouverts | Firewall, port knocking, IDS |
| Session hijacking | Prise de contrôle d'une session TCP établie | Chiffrement (TLS), numéros de séquence aléatoires |
| RST injection | Injection de paquets RST pour couper les connexions | Chiffrement, validation des numéros de séquence |
| Amplification attacks | Utilisation de services UDP pour amplifier le DDoS | Filtrage BCP38, rate limiting |

**Applications cyber** :
- Scan de ports avec nmap (SYN scan, connect scan, UDP scan)
- Analyse de trafic TCP/UDP avec Wireshark
- Détection d'anomalies de connexion (trop de SYN, RST anormaux)
- Configuration de pare-feu stateful
- Forensics : reconstruction de sessions TCP
- Test de résilience DDoS

---

### Couche 5 : session

**Fonction** : gestion des sessions entre applications. Établit, maintient et termine les connexions.

**Éléments clés** :
- Établissement et terminaison de session
- Synchronisation
- Contrôle du dialogue

**Exemples** :
- Remote Procedure Calls (RPC)
- NetBIOS
- Sessions SQL
- Sessions SMB

**Sécurité couche 5** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| Session fixation | Forcer l'utilisation d'un ID de session connu | Régénération de session après authentification |
| Session hijacking | Vol de l'identifiant de session | Cookies sécurisés (HttpOnly, Secure), tokens |
| RPC exploitation | Exploitation de vulnérabilités RPC (MS-RPC, DCE-RPC) | Patch management, filtrage des ports RPC |
| NetBIOS enumeration | Énumération d'informations via NetBIOS | Désactiver NetBIOS sur TCP/IP, filtrer port 137-139 |
| Replay attacks | Rejouer des données de session capturées | Timestamps, nonces, chiffrement |

**Applications cyber** :
- Énumération NetBIOS/SMB avec enum4linux, nbtscan
- Exploitation RPC avec rpcclient, impacket
- Analyse de sessions avec Wireshark
- Test de gestion de sessions applicatives (OWASP)
- Forensics : timeline des sessions utilisateur

---

### Couche 6 : présentation

**Fonction** : traduction des données dans un format compréhensible par la couche application. Gère le chiffrement et la compression.

**Éléments clés** :
- Traduction de données
- Chiffrement/Déchiffrement
- Compression

**Exemples** :
- Formats : JPEG, PNG, MP3, JSON, XML, ASCII
- Chiffrement : SSL/TLS
- Encodage : Base64, UTF-8

**Sécurité couche 6** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| SSL stripping | Downgrade HTTPS vers HTTP | HSTS, HSTS preload |
| Weak encryption | Utilisation d'algorithmes obsolètes (DES, RC4, MD5) | Configuration TLS moderne (TLS 1.3), cipher suites fortes |
| Certificate attacks | Certificats frauduleux, expirés, auto-signés | Certificate pinning, validation stricte, CT logs |
| Data format exploits | Exploitation de parseurs (XML injection, JSON hijacking) | Validation des entrées, parseurs sécurisés |
| Compression attacks | CRIME, BREACH (exploitation de la compression TLS) | Désactiver la compression TLS |
| Encoding attacks | Double encoding, Unicode normalization | Canonicalisation, validation stricte |

**Applications cyber** :
- Analyse de certificats SSL/TLS avec sslyze, testssl.sh
- Détection de SSL stripping avec Bettercap
- Audit de configuration TLS (cipher suites, protocoles)
- Forensics : déchiffrement de trafic avec clés privées
- Analyse de malware : déobfuscation, décompression

---

### Couche 7 : application

**Fonction** : interface avec l'utilisateur. Fournit des services réseau directement aux applications.

**Éléments clés** :
- Partage de ressources
- Services réseau
- Protocoles applicatifs

**Protocoles et exemples** :

| Protocole | Port | Usage |
|-----------|------|-------|
| HTTP/HTTPS | 80/443 | Web |
| FTP | 20/21 | Transfert de fichiers |
| SMTP | 25/587 | Envoi d'email |
| POP3/IMAP | 110/143 | Réception d'email |
| DNS | 53 | Résolution de noms |
| SSH | 22 | Shell sécurisé |
| SNMP | 161/162 | Monitoring |
| LDAP | 389/636 | Annuaire |
| RDP | 3389 | Bureau distant |
| SMB | 445 | Partage de fichiers Windows |

**Sécurité couche 7** :

| Menace | Description | Contre-mesure |
|--------|-------------|---------------|
| SQL injection | Injection de code SQL via les entrées utilisateur | Requêtes préparées, validation des entrées, WAF |
| XSS | Injection de scripts dans les pages web | Sanitization, CSP, encoding |
| CSRF | Exploitation de la session pour effectuer des actions | Tokens CSRF, SameSite cookies |
| DNS spoofing/poisoning | Réponses DNS frauduleuses | DNSSEC, DNS over HTTPS/TLS |
| Email spoofing | Usurpation d'expéditeur | SPF, DKIM, DMARC |
| Directory traversal | Accès à des fichiers hors du répertoire web | Validation des chemins, chroot |
| Command injection | Exécution de commandes système | Validation des entrées, sandboxing |
| Brute force | Attaque par force brute sur l'authentification | Rate limiting, MFA, account lockout |
| Man-in-the-Browser | Malware interceptant les données dans le navigateur | Endpoint protection, intégrité du navigateur |

**Applications cyber** :
- Test d'intrusion web (OWASP Top 10) avec Burp Suite, OWASP ZAP
- Analyse DNS avec dig, dnsenum, dnsrecon
- Audit d'email (SPF, DKIM, DMARC)
- Fuzzing d'applications avec ffuf, wfuzz
- Analyse de malware applicatif
- Forensics : analyse de logs applicatifs (access.log, error.log)
- Threat hunting dans les logs DNS, HTTP, SMTP

---

## Encapsulation et décapsulation

### Encapsulation (envoi)

Quand des données sont envoyées, chaque couche ajoute son en-tête (header) :

```
[Données utilisateur]
    ↓ Couche 7 (Application)
[En-tête App + Données]
    ↓ Couche 6 (Présentation)
[Chiffrement/Compression]
    ↓ Couche 5 (Session)
[Gestion session]
    ↓ Couche 4 (Transport)
[En-tête TCP/UDP + Port src/dst + Données] = Segment
    ↓ Couche 3 (Réseau)
[En-tête IP + IP src/dst + Segment] = Paquet
    ↓ Couche 2 (Liaison)
[En-tête Ethernet + MAC src/dst + Paquet + FCS] = Trame
    ↓ Couche 1 (Physique)
[Signal électrique/optique/radio] = Bits
```

### Décapsulation (réception)

Le processus inverse : chaque couche retire son en-tête et passe les données à la couche supérieure.

### Implications sécurité de l'encapsulation

- **Visibilité** : un IDS doit pouvoir inspecter à chaque couche
- **Tunneling** : des protocoles peuvent être encapsulés dans d'autres (VPN, SSH tunnel) pour contourner les filtres
- **Deep Packet Inspection (DPI)** : nécessaire pour analyser au-delà des en-têtes
- **Chiffrement** : le chiffrement en couche 6 ou 7 masque le contenu aux couches inférieures

---

## Le modèle TCP/IP (4 couches)

Le modèle TCP/IP est le framework pratique utilisé sur Internet. Il condense les 7 couches OSI en 4 couches.

### Correspondance OSI / TCP/IP

| TCP/IP | OSI équivalent | Fonction |
|--------|----------------|----------|
| Application | 7 + 6 + 5 | Protocoles applicatifs, présentation, sessions |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP, routage |
| Accès réseau | 2 + 1 | Ethernet, Wi-Fi, ARP, transmission physique |

### Couche 1 TCP/IP : accès réseau (Network Access)

Combine les couches physique et liaison de données OSI.

**Éléments** :
- Transmission physique
- Adressage MAC
- ARP
- Ethernet, Wi-Fi

**Protocoles** : Ethernet (802.3), Wi-Fi (802.11), ARP, PPP

### Couche 2 TCP/IP : Internet

Équivalent de la couche réseau OSI.

**Éléments** :
- Adressage IP
- Routage
- Fragmentation

**Protocoles** : IPv4, IPv6, ICMP, IGMP

### Couche 3 TCP/IP : transport

Identique à la couche transport OSI.

**Éléments** :
- Communication de bout en bout
- Fiabilité (TCP) ou rapidité (UDP)
- Ports

**Protocoles** : TCP, UDP

### Couche 4 TCP/IP : application

Combine les couches session, présentation et application OSI.

**Éléments** :
- Protocoles applicatifs
- Chiffrement
- Gestion de sessions

**Protocoles** : HTTP, HTTPS, FTP, SMTP, DNS, SSH, SNMP, LDAP, etc.

---

## Analyse par couche en cybersécurité

### Méthodologie de troubleshooting sécurité

Quand un incident survient, analyser couche par couche :

```
1. Physique   : Câble branché ? Signal Wi-Fi ? Accès physique compromis ?
2. Liaison    : Adresse MAC correcte ? ARP poisoning ? VLAN correct ?
3. Réseau     : IP valide ? Route correcte ? Firewall bloque ?
4. Transport  : Port ouvert ? Connexion établie ? SYN flood ?
5. Session    : Session active ? Timeout ? Hijacking ?
6. Présentation : Certificat valide ? Chiffrement OK ? Encoding ?
7. Application : Authentification ? Injection ? Erreur applicative ?
```

### Outils par couche

| Couche | Outils d'analyse | Outils d'attaque (pentest) |
|--------|------------------|---------------------------|
| 1 - Physique | Testeurs de câbles, analyseurs de spectre | Wi-Fi jammers, keyloggers HW |
| 2 - Liaison | Wireshark, tcpdump, arpwatch | Yersinia, macchanger, arpspoof |
| 3 - Réseau | ping, traceroute, nmap, Wireshark | hping3, nmap, scapy |
| 4 - Transport | netstat, ss, nmap, Wireshark | nmap, hping3, SYN flood tools |
| 5 - Session | Wireshark, rpcclient | Impacket, session hijacking tools |
| 6 - Présentation | sslyze, testssl.sh, openssl | Bettercap (SSL strip), sslsplit |
| 7 - Application | Burp Suite, curl, dig, nslookup | sqlmap, XSStrike, hydra, ffuf |

### Corrélation d'événements multi-couches

Une attaque sophistiquée implique souvent plusieurs couches :

**Exemple : attaque Man-in-the-Middle complète**

1. **Couche 2** : ARP spoofing pour rediriger le trafic
2. **Couche 3** : Le trafic IP passe par l'attaquant
3. **Couche 4** : Interception des connexions TCP
4. **Couche 6** : SSL stripping pour downgrader HTTPS en HTTP
5. **Couche 7** : Capture des credentials en clair

**Exemple : exfiltration de données**

1. **Couche 7** : Malware collecte les données
2. **Couche 6** : Chiffrement des données (pour échapper au DLP)
3. **Couche 4** : Tunnel sur port 443 (pour passer les firewalls)
4. **Couche 3** : Routage vers un C2 externe
5. **Couche 2** : Sortie via l'interface réseau normale

---

## Mnémotechniques

### OSI de bas en haut (couche 1 → 7)

**Anglais** : "Please Do Not Throw Sausage Pizza Away"
(Physical, Data Link, Network, Transport, Session, Presentation, Application)

**Français** : "Pour Le Réseau Tout Se Passe Automatiquement"
(Physique, Liaison, Réseau, Transport, Session, Présentation, Application)

### OSI de haut en bas (couche 7 → 1)

**Anglais** : "All People Seem To Need Data Processing"
(Application, Presentation, Session, Transport, Network, Data Link, Physical)

**Français** : "Albert Pratique Son Tennis Rapidement, Linéaire et Puissant"
(Application, Présentation, Session, Transport, Réseau, Liaison, Physique)

---

## Tableau récapitulatif sécurité par couche

| Couche | Menaces principales | Contrôles de sécurité |
|--------|--------------------|-----------------------|
| 7 - Application | Injection, XSS, CSRF, brute force | WAF, validation input, authentification forte |
| 6 - Présentation | SSL stripping, weak crypto | TLS 1.3, HSTS, certificate pinning |
| 5 - Session | Session hijacking, replay | Tokens sécurisés, régénération de session |
| 4 - Transport | SYN flood, port scan | Firewall stateful, rate limiting, IDS |
| 3 - Réseau | IP spoofing, route hijacking | ACL, uRPF, RPKI, IDS |
| 2 - Liaison | ARP spoofing, VLAN hopping, MAC flood | DAI, port security, 802.1X |
| 1 - Physique | Wiretapping, jamming, accès physique | Sécurité physique, fibre optique, NAC |

---

## Ressources

### Documentation

- Cisco : OSI Model Explained
- RFC 1122 : Requirements for Internet Hosts
- NIST SP 800-123 : Guide to General Server Security

### Outils essentiels

| Outil | Usage | Couches |
|-------|-------|---------|
| Wireshark | Analyse de paquets | 2-7 |
| nmap | Scan de ports et services | 3-4-7 |
| Burp Suite | Test d'applications web | 7 |
| tcpdump | Capture de paquets CLI | 2-4 |
| Scapy | Création de paquets personnalisés | 2-4 |
| testssl.sh | Audit TLS | 6 |
| Yersinia | Attaques Layer 2 | 2 |

### Certifications associées

- CompTIA Network+
- CompTIA Security+
- Cisco CCNA
- CEH (Certified Ethical Hacker)
- OSCP

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Introduction aux concepts fondamentaux du réseau | https://tryhackme.com/room/introtonetworking |
| **OSI Model** | Comprendre les 7 couches du modèle OSI | https://tryhackme.com/room/osimodelzi |
| **Packets & Frames** | Analyse des paquets et trames réseau | https://tryhackme.com/room/packetsframes |
| **What is Networking?** | Concepts de base du réseau | https://tryhackme.com/room/whatisnetworking |
