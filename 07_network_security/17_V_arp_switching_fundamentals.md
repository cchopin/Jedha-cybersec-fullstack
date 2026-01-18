# ARP et Commutation - Version Simplifiée

## L'idée en une phrase

ARP est le protocole qui traduit les adresses IP en adresses MAC, parce que les ordinateurs connaissent l'IP de destination mais le réseau physique a besoin de l'adresse MAC pour livrer la trame.

---

## Pourquoi ARP existe-t-il ?

### Le problème

Les applications utilisent des **adresses IP** (couche 3), mais le réseau Ethernet utilise des **adresses MAC** (couche 2).

```
Application : "Envoi d'un message à 192.168.1.10"
                       ↓
              Mais quelle est son adresse MAC ?
                       ↓
              ARP trouve la réponse : AA:BB:CC:DD:EE:FF
                       ↓
Réseau : Envoi de la trame à AA:BB:CC:DD:EE:FF
```

**Analogie** : le nom de quelqu'un (IP) est connu, mais pour lui envoyer un colis, son adresse postale (MAC) est nécessaire.

---

## Comment fonctionne ARP ?

### Le processus en 4 étapes

**Situation** : PC-A veut parler à PC-B, mais ne connaît pas sa MAC.

```
Étape 1 : PC-A crie à tout le monde (broadcast)
┌───────┐                              ┌───────┐
│ PC-A  │  "QUI A 192.168.1.10 ???"   │ PC-B  │
│       │ ═══════════════════════════>│       │
│       │    (tout le monde entend)   │       │
└───────┘                              └───────┘

Étape 2 : PC-B répond directement (unicast)
┌───────┐                              ┌───────┐
│ PC-A  │  "C'est moi ! Ma MAC est    │ PC-B  │
│       │<═══════════════════════════ │       │
│       │   AA:BB:CC:DD:EE:FF"        │       │
└───────┘                              └───────┘

Étape 3 : PC-A enregistre la réponse
┌─────────────────────────────────┐
│ Cache ARP de PC-A               │
│ 192.168.1.10 → AA:BB:CC:DD:EE:FF│
└─────────────────────────────────┘

Étape 4 : PC-A peut maintenant communiquer
```

**Analogie** : crier dans une pièce "Qui s'appelle Pierre ?", et Pierre répond "C'est moi, je suis près de la fenêtre".

---

## Le cache ARP

### Pourquoi un cache ?

Pour éviter de crier "Qui a cette IP ?" à chaque paquet, les réponses sont gardées en mémoire.

### Durée de vie (TTL)

Les entrées expirent après un certain temps (quelques minutes), au cas où l'adresse MAC changerait.

### Voir le cache ARP

| Système | Commande |
|---------|----------|
| **Windows** | `arp -a` |
| **Linux** | `ip neigh show` ou `arp -a` |
| **Mac** | `arp -a` |
| **Cisco** | `show ip arp` |

### Vider le cache

| Système | Commande |
|---------|----------|
| **Windows** | `netsh interface ip delete arpcache` |
| **Linux** | `sudo ip neigh flush all` |
| **Cisco** | `clear ip arp` |

---

## Comment fonctionne un switch ?

### La table MAC

Le switch garde une table qui associe chaque adresse MAC à un port physique :

```
┌─────────────────────────────────────────┐
│ Table MAC du Switch                     │
│                                         │
│ MAC               │ Port                │
│ 00:11:22:33:44:55 │ Fa0/1              │
│ AA:BB:CC:DD:EE:FF │ Fa0/3              │
│ 00:FF:11:22:33:44 │ Gi0/1              │
└─────────────────────────────────────────┘
```

### Comment le switch apprend-il ?

```
1. Trame arrive sur port Fa0/1
   Source MAC : 00:11:22:33:44:55
                ↓
2. Switch apprend :
   "00:11:22:33:44:55 est sur Fa0/1"
                ↓
3. Pour les prochaines trames vers cette MAC :
   "Je sais, c'est sur Fa0/1 !"
```

### Décisions du switch

| Situation | Action |
|-----------|--------|
| MAC destination connue | Envoie au bon port |
| MAC destination inconnue | Flood (envoie partout sauf source) |
| Broadcast (FF:FF:FF:FF:FF:FF) | Flood partout |

**Analogie** : le switch est comme un facteur qui apprend où habitent les gens. La première fois, il doit demander. Ensuite, il sait.

---

## Voir les tables

### Table ARP sur un switch Cisco

```cisco
Switch# show ip arp

Protocol  Address        Age   Hardware Addr   Interface
Internet  192.168.1.1     4    0011.2233.4455  Vlan1
Internet  192.168.1.10    2    00AA.BBCC.DDEE  Vlan1
```

### Table MAC sur un switch Cisco

```cisco
Switch# show mac address-table

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Fa0/1
   1    00AA.BBCC.DDEE    DYNAMIC     Fa0/3
```

---

## Problèmes courants

### 1. Entrée ARP obsolète

**Symptôme** : la communication ne fonctionne plus

**Cause** : l'adresse MAC a changé (nouvelle carte réseau, VM déplacée)

**Solution** : vider le cache ARP

### 2. Table MAC saturée

**Symptôme** : le switch envoie tout partout (comme un hub)

**Cause** : trop d'adresses MAC (ou attaque MAC flooding)

**Solution** : vérifier avec `show mac address-table count`

### 3. Port err-disabled

**Symptôme** : un port est désactivé automatiquement

**Cause** : violation de sécurité (port-security, BPDU guard)

**Solution** :
```cisco
Switch(config-if)# shutdown
Switch(config-if)# no shutdown
```

---

## Analyser avec Wireshark

### Filtres utiles

| Filtre | Affichage |
|--------|-----------------|
| `arp` | Tout le trafic ARP |
| `arp.opcode == 1` | Requêtes ARP (who has?) |
| `arp.opcode == 2` | Réponses ARP |

### Exemple de capture

```
Frame 1: ARP Request
  "Qui a 192.168.1.10 ?"
  De : 00:11:22:33:44:55

Frame 2: ARP Reply
  "C'est moi, AA:BB:CC:DD:EE:FF"
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **ARP** | Traduit IP en MAC |
| **Cache ARP** | Mémoire des associations IP/MAC |
| **MAC** | Adresse physique unique (48 bits) |
| **Table MAC** | Table du switch : MAC → port |
| **Broadcast** | Message envoyé à tout le monde |
| **Unicast** | Message envoyé à un seul destinataire |
| **Flood** | Le switch envoie partout (MAC inconnue) |
| **TTL** | Durée de vie d'une entrée en cache (Time To Live) |

---

## Résumé en 30 secondes

1. **ARP** = traduction IP → MAC (comme un annuaire)
2. **Requête ARP** = broadcast "Qui a cette IP ?"
3. **Réponse ARP** = unicast "C'est moi !"
4. Le **cache ARP** garde les réponses en mémoire
5. Le **switch** apprend les MAC en observant les trames
6. Si MAC inconnue → **flood** (envoie partout)

---

## Schéma récapitulatif

```
   PC-A                   SWITCH                   PC-B
   192.168.1.1                                    192.168.1.10
   MAC: 00:11:22:...                              MAC: AA:BB:CC:...
       │                                               │
       │  1. ARP Request (broadcast)                   │
       │  "Qui a 192.168.1.10 ?"                       │
       │────────────────────────────────────────────────>
       │                                               │
       │               2. Switch apprend               │
       │             00:11:22 → Port 1                 │
       │                                               │
       │  3. ARP Reply (unicast)                       │
       │  "C'est moi, AA:BB:CC:..."                    │
       │<────────────────────────────────────────────────
       │                                               │
       │               4. Switch apprend               │
       │             AA:BB:CC → Port 3                 │
       │                                               │
       │  5. Communication normale                     │
       │<══════════════════════════════════════════════>
```
