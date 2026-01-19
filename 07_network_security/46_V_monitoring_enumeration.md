# Monitoring et Énumération (Red Team) - Version Simplifiée

## L'idée en une phrase

L'énumération, c'est l'art de collecter des informations sur un réseau : SNMP révèle la carte du réseau, le fingerprinting identifie les versions, et tout cela prépare l'attaque.

---

## SNMP : la mine d'or des attaquants

### Ce que SNMP révèle

```
Attaquant                           Équipement SNMP
─────────                           ───────────────

"Community = public ?" ────────────> Port 161
                                         │
      <─────────────────────────── "Oui !"
                                         │
snmpwalk ───────────────────────────────>│
                                         │
      <──────────────────────────────────│

Résultat : TOUT sur l'équipement !
• Nom, version OS
• Interfaces réseau
• Table de routage
• Voisins (ARP)
• Processus en cours
```

### Pourquoi c'est dangereux

Un seul équipement mal configuré = carte complète du réseau pour l'attaquant.

---

## snmp-check : L'Outil d'Énumération

### Installation et Usage

```bash
# Installer
sudo apt install snmpcheck

# Utiliser
snmp-check -t 192.168.1.1

# Avec autre community string
snmp-check -t 192.168.1.1 -c secret
```

### Ce que ça retourne

| Catégorie | Information |
|-----------|-------------|
| System Info | Nom, version, uptime |
| Interfaces | IPs, MACs, VLANs |
| Routes | Chemins vers autres réseaux |
| ARP | Voisins actifs |
| Ports | Services en écoute |
| Processus | Applications en cours |

### Usage défensif

Lancer `snmp-check` contre les équipements. Si des infos apparaissent, les attaquants peuvent aussi les voir !

---

## Fingerprinting : Identifier les Services

### Le Workflow

```
1. DÉCOUVERTE
   nmap -sS -p- target
   → Ports ouverts : 22, 80, 443

2. IDENTIFICATION
   nmap -sV -p 22,80,443 target
   → SSH, Apache, HTTPS

3. FINGERPRINTING
   Bannières, headers, TLS
   → Apache 2.4.29, OpenSSH 7.4

4. VULNÉRABILITÉS
   CVE Database
   → CVE-2019-0211 (Apache)
```

### Techniques de Fingerprinting

| Technique | Ce que ça fait |
|-----------|----------------|
| Banner Grabbing | Lire les bannières de service |
| HTTP Headers | Analyser Server, X-Powered-By |
| TLS Analysis | Certificats, ciphers |
| Error Messages | Provoquer des erreurs révélatrices |

---

## Mapping réseau via SNMP

### Ce qu'on peut construire

```
SNMP Query sur routeur
         │
         ▼
┌─────────────────────────────────┐
│  Interfaces:                    │
│    eth0: 192.168.1.1/24 (LAN)  │
│    eth1: 10.0.0.1/24 (Serveurs)│
│                                 │
│  ARP Cache:                     │
│    192.168.1.10 → actif        │
│    192.168.1.20 → actif        │
│                                 │
│  Routes:                        │
│    172.16.0.0/24 via 10.0.0.254│
└─────────────────────────────────┘
         │
         ▼
CARTE RÉSEAU COMPLÈTE !
• LAN avec 2 hôtes actifs
• Segment serveurs découvert
• Autre subnet via routage
```

---

## Mouvement latéral avec SNMP

### Comment SNMP aide

| Info SNMP | Usage pour l'attaquant |
|-----------|------------------------|
| Table ARP | Liste d'IPs à cibler |
| Interfaces | VLANs accessibles |
| Routes | Subnets atteignables |
| sysName | Identifier le DC, serveur fichiers |
| sysContact | Noms d'utilisateurs potentiels |

### Exemple

```
Accès initial:              Info SNMP:               Mouvement:
─────────────               ──────────               ──────────

Switch compromis    →    ARP révèle:           →    Pivot vers
                         192.168.1.50 (DC)          serveur fichiers
                         192.168.1.60 (Files)
```

---

## Requêtes ciblées

### Pourquoi cibler ?

| Large (snmpwalk) | Ciblé (snmpget) |
|------------------|-----------------|
| Beaucoup de trafic | Peu de trafic |
| Détectable | Furtif |
| Long | Rapide |

### OIDs utiles

```bash
# Nom du système
snmpget -v2c -c public target 1.3.6.1.2.1.1.5.0

# Description
snmpget -v2c -c public target 1.3.6.1.2.1.1.1.0

# Table de routage seulement
snmpwalk -v2c -c public target 1.3.6.1.2.1.4.21
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Énumération** | Lister les ressources d'un réseau |
| **Fingerprinting** | Identifier versions et configurations |
| **MIB** | Structure de données SNMP |
| **OID** | Adresse d'une donnée SNMP |
| **Community String** | Mot de passe SNMP (v1/v2c) |
| **Mouvement Latéral** | Progresser dans le réseau après accès initial |
| **Pivot** | Utiliser une machine pour en atteindre d'autres |
| **Banner Grabbing** | Récupérer les infos de version d'un service |

---

## Résumé en 30 secondes

```
SNMP MAL CONFIGURÉ = Carte du réseau offerte aux attaquants

snmp-check       = Outil pour énumérer via SNMP
Fingerprinting   = Identifier services et versions
Mapping          = Construire la topologie via ARP/routes
Mouvement        = Utiliser les infos pour pivoter

DÉFENSE : SNMPv3 + ACLs + Monitoring
```

---

## Schéma récapitulatif

```
WORKFLOW RED TEAM :

    RECONNAISSANCE         ÉNUMÉRATION          EXPLOITATION
    ──────────────         ───────────          ────────────

    Scan ports ─────> SNMP Check ────────> CVE Lookup
         │                 │                     │
         │           Fingerprinting              │
         │                 │                     │
         ▼                 ▼                     ▼
    Hôtes actifs     Services/Versions     Accès initial
                                                │
                                                ▼
                                        Mouvement latéral


CE QUE SNMP RÉVÈLE :

    ┌─────────────────────────────────────┐
    │         ÉQUIPEMENT SNMP             │
    ├─────────────────────────────────────┤
    │                                     │
    │  sysDescr ──────> Type et OS        │
    │  sysName ───────> Nom/Rôle          │
    │  ifTable ───────> Interfaces        │
    │  ipRouteTable ──> Routes            │
    │  arpTable ──────> Voisins           │
    │  hrSWRunTable ──> Processus         │
    │                                     │
    └─────────────────────────────────────┘
              │
              ▼
    CARTE RÉSEAU COMPLÈTE !


DÉFENSE :

    ✗ Vulnérable              ✓ Sécurisé
    ────────────              ──────────

    SNMPv1/v2c                SNMPv3
    "public"                  Auth + Chiffrement
    Port ouvert               ACL restrictives
    Pas de logs               Monitoring
```
