# ARP et fondamentaux de la commutation

## Objectifs du cours

Ce cours explore le protocole ARP (Address Resolution Protocol) et le fonctionnement des switches. Comprendre ARP est essentiel car c'est le mécanisme qui permet la communication entre les adresses IP (couche 3) et les adresses MAC (couche 2).

Compétences visées :
- Comprendre le fonctionnement d'ARP et son rôle dans le réseau
- Maîtriser le processus de requête/réponse ARP
- Comprendre comment les switches utilisent les tables MAC
- Utiliser les commandes CLI pour inspecter les tables ARP
- Diagnostiquer les problèmes liés à ARP et à la commutation

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **ARP** | Address Resolution Protocol - Résolution IP → MAC |
| **MAC** | Media Access Control - Adresse physique unique (48 bits) |
| **Table ARP** | Cache associant adresses IP et adresses MAC |
| **Table MAC** | Table du switch associant adresses MAC et ports |
| **Broadcast** | Trame envoyée à tous les équipements du réseau |
| **Unicast** | Trame envoyée à un seul destinataire |
| **TTL** | Time To Live - Durée de vie d'une entrée dans le cache |

---

## Comment fonctionne ARP

### Le problème

Les applications utilisent des **adresses IP** pour communiquer, mais au niveau physique (Ethernet), les équipements utilisent des **adresses MAC**. ARP fait le lien entre les deux.

```
Application : "Je veux joindre 192.168.1.10"
                    ↓
              Mais quelle est son adresse MAC ?
                    ↓
              → ARP résout le problème
                    ↓
Réseau : "Envoyer la trame à AA:BB:CC:DD:EE:FF"
```

### Le processus ARP étape par étape

**Situation :** PC-A (192.168.1.1) veut communiquer avec PC-B (192.168.1.10)

```
Étape 1 : PC-A vérifie son cache ARP
┌─────────────────────────────────────────┐
│ Cache ARP de PC-A                       │
│ (vide ou pas d'entrée pour 192.168.1.10)│
└─────────────────────────────────────────┘

Étape 2 : PC-A envoie une requête ARP (broadcast)
┌───────┐                           ┌───────┐
│ PC-A  │  "Qui a 192.168.1.10 ?"   │ PC-B  │
│       │ ════════════════════════> │       │
│       │    (broadcast FF:FF:FF:FF:FF:FF)  │
└───────┘                           └───────┘
    ↓ Le broadcast atteint TOUS les équipements du réseau

Étape 3 : PC-B répond (unicast)
┌───────┐                           ┌───────┐
│ PC-A  │  "192.168.1.10 est à      │ PC-B  │
│       │ <═══════════════════════  │       │
│       │   AA:BB:CC:DD:EE:FF"      │       │
└───────┘      (unicast)            └───────┘

Étape 4 : PC-A met à jour son cache ARP
┌─────────────────────────────────────────┐
│ Cache ARP de PC-A                       │
│ 192.168.1.10 → AA:BB:CC:DD:EE:FF        │
└─────────────────────────────────────────┘
```

### Format des messages ARP

**Requête ARP (ARP Request) :**
```
Source MAC      : 00:11:22:33:44:55 (PC-A)
Destination MAC : FF:FF:FF:FF:FF:FF (broadcast)
Message         : "Qui a 192.168.1.10 ? Répondre à 192.168.1.1"
```

**Réponse ARP (ARP Reply) :**
```
Source MAC      : AA:BB:CC:DD:EE:FF (PC-B)
Destination MAC : 00:11:22:33:44:55 (PC-A)
Message         : "192.168.1.10 est à AA:BB:CC:DD:EE:FF"
```

---

## Table MAC des switches

### Rôle de la table MAC

Un switch opère en **couche 2** et utilise les adresses MAC pour acheminer les trames. La **table MAC** (aussi appelée CAM table) associe chaque adresse MAC au port physique correspondant.

### Apprentissage des adresses MAC

```
Étape 1 : Trame reçue sur le port Fa0/1
┌──────────────────────────────────────────────────────┐
│ Source MAC: 00:11:22:33:44:55                        │
│ Destination MAC: AA:BB:CC:DD:EE:FF                   │
└──────────────────────────────────────────────────────┘

Étape 2 : Le switch apprend l'adresse source
┌─────────────────────────────────────────┐
│ Table MAC                               │
│ 00:11:22:33:44:55 → Fa0/1 (DYNAMIC)     │
└─────────────────────────────────────────┘

Étape 3 : Le switch cherche la destination
- Si connue → Forward vers le bon port
- Si inconnue → Flood (envoyer sur tous les ports sauf source)
```

### Décisions de transfert

| Situation | Action du switch |
|-----------|------------------|
| MAC destination connue | Forward vers le port correspondant |
| MAC destination inconnue | Flood sur tous les ports (sauf source) |
| Broadcast (FF:FF:FF:FF:FF:FF) | Flood sur tous les ports (sauf source) |
| Multicast | Flood ou forward selon configuration |

---

## Commandes CLI essentielles

### Sur équipements Cisco

**Afficher la table ARP :**
```cisco
Switch# show ip arp

Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1             4   0011.2233.4455  ARPA   Vlan1
Internet  192.168.1.10            2   00AA.BBCC.DDEE  ARPA   Vlan1
Internet  192.168.1.20            -   A1B2.C3D4.E5F6  ARPA   Vlan1
```

**Vider le cache ARP :**
```cisco
Switch# clear ip arp
```

**Afficher la table MAC :**
```cisco
Switch# show mac address-table

          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Fa0/1
   1    00AA.BBCC.DDEE    DYNAMIC     Fa0/3
  10    00FF.1122.3344    DYNAMIC     Gi0/1
 100    0C1D.2E3F.4A5B    STATIC      Fa0/5
```

**Vider la table MAC :**
```cisco
Switch# clear mac address-table dynamic
```

### Sur Linux

**Afficher le cache ARP :**
```bash
# Méthode moderne
ip neigh show

192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.10 dev eth0 lladdr 00:aa:bb:cc:dd:ee STALE

# Méthode classique
arp -a

? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
```

**Vider le cache ARP :**
```bash
sudo ip neigh flush all
```

### Sur Windows

**Afficher le cache ARP :**
```cmd
arp -a

Interface: 192.168.1.100 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.10          00-aa-bb-cc-dd-ee     dynamic
```

**Vider le cache ARP :**
```cmd
netsh interface ip delete arpcache
```

---

## Dépannage ARP et commutation

### Problèmes ARP courants

#### 1. Entrée ARP obsolète (Stale)

**Symptôme :** Communication échoue malgré une entrée dans le cache

**Cause :** L'adresse MAC a changé (remplacement de carte réseau, VM déplacée...)

**Solution :**
```bash
# Linux
sudo ip neigh flush all

# Windows
netsh interface ip delete arpcache

# Cisco
clear ip arp
```

#### 2. ARP Spoofing (attaque)

**Symptôme :** Trafic intercepté, problèmes de connectivité intermittents

**Cause :** Un attaquant envoie de fausses réponses ARP pour se faire passer pour un autre équipement

**Détection :**
```bash
# Vérifier les doublons d'adresses IP avec des MAC différentes
arp -a | sort
```

**Protection :**
- Dynamic ARP Inspection (DAI) sur les switches
- ARP statique pour les équipements critiques
- Surveillance du réseau

#### 3. Broadcast Storm

**Symptôme :** Réseau saturé, switches surchargés

**Cause :** Boucle réseau provoquant une multiplication infinie des broadcasts (dont ARP)

**Solution :** Vérifier Spanning Tree (voir cours 18)

### Problèmes de commutation courants

#### 1. MAC Table Overflow

**Symptôme :** Le switch flood toutes les trames (comportement de hub)

**Cause :** Table MAC pleine (attaque ou réseau trop grand)

**Diagnostic :**
```cisco
Switch# show mac address-table count
```

**Solution :** Port-security pour limiter les MAC par port

#### 2. Port en err-disabled

**Symptôme :** Port désactivé automatiquement

**Cause :** Violation de sécurité (port-security, BPDU guard...)

**Diagnostic :**
```cisco
Switch# show interfaces status

Port      Name               Status       Vlan
Fa0/1                        err-disabled 10
```

**Solution :**
```cisco
Switch(config)# interface FastEthernet0/1
Switch(config-if)# shutdown
Switch(config-if)# no shutdown
```

---

## Analyse avec Wireshark

### Filtres utiles pour ARP

```
# Tout le trafic ARP
arp

# Requêtes ARP uniquement
arp.opcode == 1

# Réponses ARP uniquement
arp.opcode == 2

# ARP pour une IP spécifique
arp.dst.proto_ipv4 == 192.168.1.10

# Détecter ARP gratuit (potentielle attaque)
arp.isgratuitous == 1
```

### Exemple de capture ARP

```
Frame 1: ARP Request
  Sender MAC: 00:11:22:33:44:55
  Sender IP: 192.168.1.1
  Target MAC: 00:00:00:00:00:00
  Target IP: 192.168.1.10

Frame 2: ARP Reply
  Sender MAC: aa:bb:cc:dd:ee:ff
  Sender IP: 192.168.1.10
  Target MAC: 00:11:22:33:44:55
  Target IP: 192.168.1.1
```

---

## Debug ARP sur Cisco

Pour un dépannage avancé :

```cisco
Switch# debug arp

*Mar  1 00:03:22.069: ARP: received request from 192.168.1.10 for 192.168.1.1
*Mar  1 00:03:22.069: ARP: sent reply 192.168.1.1 is-at 00:11:22:33:44:55

! Désactiver le debug quand terminé
Switch# no debug arp
```

**Attention :** Le debug consomme des ressources. Ne pas laisser actif en production.

---

## Résumé

### ARP

| Concept | Point clé |
|---------|-----------|
| **Rôle** | Résoudre IP → MAC |
| **Requête** | Broadcast (qui a cette IP ?) |
| **Réponse** | Unicast (c'est moi, voici ma MAC) |
| **Cache** | Stockage temporaire des associations IP/MAC |

### Commutation

| Concept | Point clé |
|---------|-----------|
| **Table MAC** | Association MAC → Port physique |
| **Apprentissage** | Le switch apprend les MAC sources |
| **Forward** | Si MAC connue → envoyer au bon port |
| **Flood** | Si MAC inconnue → envoyer partout |

### Commandes essentielles

| Plateforme | Voir ARP | Voir MAC | Vider cache |
|------------|----------|----------|-------------|
| **Cisco** | `show ip arp` | `show mac address-table` | `clear ip arp` |
| **Linux** | `ip neigh show` | N/A | `ip neigh flush all` |
| **Windows** | `arp -a` | N/A | `netsh interface ip delete arpcache` |

---

## Ressources

| Ressource | Lien |
|-----------|------|
| Cisco ARP Configuration Guide | https://www.cisco.com/c/en/us/support/docs/ip/address-resolution-protocol-arp/ |
| How ARP Works | https://www.practicalnetworking.net/series/arp/arp/ |
| Cisco MAC Address Table | https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/71079-arp-cam-tableissues.html |
