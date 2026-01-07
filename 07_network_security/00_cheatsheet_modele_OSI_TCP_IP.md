# Cheatsheet modèle OSI et TCP/IP

## Les deux modèles côte à côte

```
    OSI (7 couches)              TCP/IP (4 couches)
┌─────────────────────┐      ┌─────────────────────┐
│   7. Application    │      │                     │
├─────────────────────┤      │     Application     │
│   6. Présentation   │      │                     │
├─────────────────────┤      │                     │
│   5. Session        │      │                     │
├─────────────────────┼──────┼─────────────────────┤
│   4. Transport      │      │     Transport       │
├─────────────────────┼──────┼─────────────────────┤
│   3. Réseau         │      │     Internet        │
├─────────────────────┼──────┼─────────────────────┤
│   2. Liaison        │      │                     │
├─────────────────────┤      │   Accès réseau      │
│   1. Physique       │      │                     │
└─────────────────────┘      └─────────────────────┘
```

**OSI** = modèle théorique (référence pour comprendre)
**TCP/IP** = modèle pratique (ce qui tourne vraiment)

---

## Modèle OSI détaillé

### Couche 1 : Physique

```
Rôle : Transmission des bits bruts sur le média
─────────────────────────────────────────────────
Unité de données   │ Bit
Équipements        │ Hub, répéteur, câbles, connecteurs
Protocoles         │ Ethernet (partie physique), DSL, Wi-Fi (802.11)
Exemples concrets  │ RJ45, fibre optique, ondes radio
```

**Attaques associées :**
- Sniffing physique (tap sur câble)
- Brouillage (jamming Wi-Fi)
- Keylogger hardware

---

### Couche 2 : Liaison de données

```
Rôle : Communication fiable entre nœuds adjacents
─────────────────────────────────────────────────
Unité de données   │ Trame (frame)
Adressage          │ MAC (48 bits, ex: AA:BB:CC:DD:EE:FF)
Équipements        │ Switch, bridge, carte réseau (NIC)
Protocoles         │ Ethernet, Wi-Fi (802.11), ARP, PPP
Sous-couches       │ LLC (Logical Link Control)
                   │ MAC (Media Access Control)
```

**Fonctions clés :**
- Encapsulation des paquets en trames
- Adressage physique (MAC)
- Détection d'erreurs (CRC/FCS)
- Contrôle d'accès au média (CSMA/CD, CSMA/CA)

**Attaques associées :**
- ARP spoofing / ARP poisoning
- MAC flooding
- VLAN hopping
- STP manipulation

---

### Couche 3 : Réseau

```
Rôle : Routage et adressage logique entre réseaux
─────────────────────────────────────────────────
Unité de données   │ Paquet
Adressage          │ IP (IPv4: 32 bits, IPv6: 128 bits)
Équipements        │ Routeur, firewall L3
Protocoles         │ IP, ICMP, IGMP, IPsec
Routage            │ OSPF, BGP, EIGRP, RIP
```

**Fonctions clés :**
- Adressage logique (IP)
- Routage (choix du chemin)
- Fragmentation des paquets
- Gestion du TTL

**Attaques associées :**
- IP spoofing
- ICMP flood (ping of death, smurf)
- Route hijacking
- Fragmentation attacks

---

### Couche 4 : Transport

```
Rôle : Communication de bout en bout
─────────────────────────────────────────────────
Unité de données   │ Segment (TCP) / Datagramme (UDP)
Adressage          │ Ports (0-65535)
Protocoles         │ TCP, UDP, SCTP
```

**TCP vs UDP :**

```
        TCP                          UDP
┌──────────────────────┐    ┌──────────────────────┐
│ Connexion établie    │    │ Sans connexion       │
│ Fiable (ACK)         │    │ Non fiable           │
│ Contrôle de flux     │    │ Pas de contrôle      │
│ Ordre garanti        │    │ Ordre non garanti    │
│ Plus lent            │    │ Plus rapide          │
├──────────────────────┤    ├──────────────────────┤
│ HTTP, SSH, FTP       │    │ DNS, DHCP, VoIP      │
│ SMTP, SQL            │    │ Streaming, Gaming    │
└──────────────────────┘    └──────────────────────┘
```

**Ports courants :**

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
| 3389 | RDP | TCP |

**Attaques associées :**
- SYN flood
- Port scanning
- Session hijacking
- UDP flood

---

### Couche 5 : Session

```
Rôle : Gestion des sessions de communication
─────────────────────────────────────────────────
Fonctions          │ Établissement, maintien, terminaison
Protocoles         │ NetBIOS, RPC, PPTP, SIP (partiellement)
```

**Fonctions clés :**
- Synchronisation des échanges
- Points de reprise (checkpointing)
- Gestion du dialogue (half/full duplex)

**Note :** Souvent fusionnée avec les couches 6 et 7 en pratique.

---

### Couche 6 : Présentation

```
Rôle : Format et représentation des données
─────────────────────────────────────────────────
Fonctions          │ Encodage, compression, chiffrement
Formats            │ ASCII, JPEG, MPEG, SSL/TLS
```

**Fonctions clés :**
- Traduction des formats de données
- Compression / décompression
- Chiffrement / déchiffrement

**Attaques associées :**
- SSL stripping
- Downgrade attacks
- Format string attacks

---

### Couche 7 : Application

```
Rôle : Interface avec l'utilisateur et les applications
─────────────────────────────────────────────────
Protocoles         │ HTTP, HTTPS, FTP, SMTP, DNS, SNMP
                   │ SSH, Telnet, LDAP, SMB, NFS
```

**Attaques associées :**
- Injection SQL, XSS, CSRF
- Phishing
- DNS poisoning
- Brute force
- Man-in-the-middle applicatif

---

## Modèle TCP/IP détaillé

### Couche 1 : Accès réseau (Network Access)

```
Équivalent OSI     │ Couches 1 + 2 (Physique + Liaison)
Rôle               │ Transmission sur le réseau local
Protocoles         │ Ethernet, Wi-Fi, ARP, PPP
Adressage          │ MAC
```

---

### Couche 2 : Internet

```
Équivalent OSI     │ Couche 3 (Réseau)
Rôle               │ Routage entre réseaux
Protocoles         │ IP, ICMP, IGMP, IPsec
Adressage          │ IP
```

---

### Couche 3 : Transport

```
Équivalent OSI     │ Couche 4 (Transport)
Rôle               │ Communication bout en bout
Protocoles         │ TCP, UDP
Adressage          │ Ports
```

---

### Couche 4 : Application

```
Équivalent OSI     │ Couches 5 + 6 + 7 (Session + Présentation + Application)
Rôle               │ Services réseau pour les applications
Protocoles         │ HTTP, FTP, SMTP, DNS, SSH, SNMP, etc.
```

---

## Encapsulation des données

```
┌─────────────────────────────────────────────────────────────┐
│                        DONNÉES                              │  Application
└─────────────────────────────────────────────────────────────┘
                            ↓
┌──────────┬─────────────────────────────────────────────────┐
│ En-tête  │                    DONNÉES                      │  Transport
│ TCP/UDP  │                                                 │  (Segment)
└──────────┴─────────────────────────────────────────────────┘
                            ↓
┌──────────┬──────────┬──────────────────────────────────────┐
│ En-tête  │ En-tête  │              DONNÉES                 │  Réseau
│   IP     │ TCP/UDP  │                                      │  (Paquet)
└──────────┴──────────┴──────────────────────────────────────┘
                            ↓
┌──────────┬──────────┬──────────┬───────────────────┬───────┐
│ En-tête  │ En-tête  │ En-tête  │      DONNÉES      │  FCS  │  Liaison
│ Ethernet │   IP     │ TCP/UDP  │                   │       │  (Trame)
└──────────┴──────────┴──────────┴───────────────────┴───────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              01101001 01001010 11010010 ...                 │  Physique
└─────────────────────────────────────────────────────────────┘                                                              (Bits)
```

**Mnémotechnique pour les unités :**

| Couche | Unité | Mnémotechnique |
|--------|-------|----------------|
| Application | Données | **D**onnées |
| Transport | Segment | **S**egment |
| Réseau | Paquet | **P**aquet |
| Liaison | Trame | **T**rame (Frame) |
| Physique | Bit | **B**it |

"**D**es **S**aumons **P**êchés **T**rès **B**ien" (de haut en bas)

---

## Équipements par couche

```
Couche OSI │ Équipement         │ Fonction
───────────┼────────────────────┼─────────────────────────────
    7      │ Proxy applicatif   │ Filtre au niveau application
    6      │ (intégré)          │ -
    5      │ (intégré)          │ -
    4      │ Firewall L4        │ Filtre par port
    3      │ Routeur            │ Routage entre réseaux
           │ Firewall L3        │ Filtre par IP
    2      │ Switch             │ Commutation par MAC
           │ Bridge             │ Segmente les domaines collision
    1      │ Hub                │ Répète le signal (broadcast)
           │ Répéteur           │ Amplifie le signal
```

---

## Protocoles par couche (récap visuel)

```
┌─────────────────────────────────────────────────────────────┐
│  7  │ HTTP  HTTPS  FTP  SMTP  DNS  SSH  SNMP  LDAP  SMB     │
├─────────────────────────────────────────────────────────────┤
│  6  │ SSL/TLS  JPEG  MPEG  ASCII  Chiffrement               │
├─────────────────────────────────────────────────────────────┤
│  5  │ NetBIOS  RPC  PPTP  SIP                               │
├─────────────────────────────────────────────────────────────┤
│  4  │ TCP  UDP  SCTP                                        │
├─────────────────────────────────────────────────────────────┤
│  3  │ IP  ICMP  IGMP  IPsec  OSPF  BGP  RIP                 │
├─────────────────────────────────────────────────────────────┤
│  2  │ Ethernet  Wi-Fi (802.11)  ARP  PPP  STP  VLAN         │
├─────────────────────────────────────────────────────────────┤
│  1  │ Câbles  Connecteurs  Signaux  Hub  Répéteur           │
└─────────────────────────────────────────────────────────────┘
```

---

## Tableau récap attaques par couche

| Couche | Attaque | Outil/Technique |
|--------|---------|-----------------|
| 1 | Sniffing physique | Tap réseau, keylogger HW |
| 1 | Jamming | Brouilleur Wi-Fi |
| 2 | ARP spoofing | Bettercap, arpspoof |
| 2 | MAC flooding | macof |
| 2 | VLAN hopping | Double tagging |
| 3 | IP spoofing | Scapy, hping3 |
| 3 | ICMP flood | ping -f, hping3 |
| 4 | SYN flood | hping3, Scapy |
| 4 | Port scan | Nmap |
| 7 | SQL injection | SQLmap |
| 7 | XSS | Burp Suite |
| 7 | DNS poisoning | DNSspoof |

---

## Checklist analyse de trafic

```
□ Quelle couche est impliquée ?
□ Quel protocole ?
□ Quels sont les adresses/ports source et destination ?
□ Le trafic est-il chiffré ?
□ Y a-t-il des anomalies (taille, fréquence, flags) ?
```

---
