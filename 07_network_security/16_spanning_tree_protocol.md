# Spanning Tree Protocol (STP)

## Objectifs du cours

Ce cours présente le Spanning Tree Protocol (STP), le mécanisme qui empêche les boucles réseau dans les topologies redondantes. Les boucles sont l'un des problèmes les plus destructeurs dans un réseau commuté.

Compétences visées :
- Comprendre pourquoi les boucles réseau sont dangereuses
- Maîtriser le processus d'élection du Root Bridge
- Connaître les différents états des ports STP
- Comprendre les améliorations apportées par RSTP
- Optimiser STP pour un failover plus rapide

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **STP** | Spanning Tree Protocol - Protocole anti-boucle (IEEE 802.1D) |
| **RSTP** | Rapid Spanning Tree Protocol - Version rapide (IEEE 802.1w) |
| **Root Bridge** | Switch central de référence dans la topologie STP |
| **BPDU** | Bridge Protocol Data Unit - Messages échangés par STP |
| **BID** | Bridge ID - Identifiant unique du switch (priorité + MAC) |
| **Root Port** | Port avec le meilleur chemin vers le Root Bridge |
| **Designated Port** | Port qui forward le trafic vers un segment |
| **Blocked Port** | Port désactivé pour éviter les boucles |
| **Convergence** | Temps nécessaire pour recalculer la topologie |

---

## Pourquoi les boucles sont dangereuses

### Le problème des boucles

Dans un réseau redondant sans STP, les trames peuvent circuler indéfiniment :

```
Sans STP - CATASTROPHE :

     Switch A ←─────────────→ Switch B
         ↑                        ↑
         │                        │
         └────────────────────────┘

1. PC envoie un broadcast
2. Switch A forward vers B et vers le lien du bas
3. Switch B forward vers A et vers le lien du bas
4. Les trames tournent EN BOUCLE INFINIE
5. Chaque tour MULTIPLIE le nombre de trames
6. → BROADCAST STORM → Réseau DOWN
```

### Conséquences d'une boucle

| Effet | Description |
|-------|-------------|
| **Broadcast Storm** | Multiplication exponentielle des broadcasts |
| **Saturation CPU** | Switches surchargés à 100% |
| **Table MAC instable** | Adresses qui "sautent" entre ports |
| **Réseau inutilisable** | Latence extrême ou perte totale |

### La solution : STP

STP crée une **topologie sans boucle** en bloquant certains liens redondants :

```
Avec STP - STABLE :

     Switch A ←─────────────→ Switch B
     (Root)       actif           ↑
         ↑                        │
         │         BLOQUÉ         │
         └────────────╳───────────┘

- Un seul chemin actif entre chaque paire de switches
- Les liens redondants sont en "standby"
- En cas de panne, STP réactive un lien bloqué
```

---

## Élection du Root Bridge

### Qu'est-ce que le Root Bridge ?

Le **Root Bridge** est le switch de référence dans la topologie STP. Tous les autres switches calculent leur meilleur chemin vers lui.

### Le Bridge ID (BID)

Chaque switch a un identifiant unique composé de :

```
┌────────────────────────────────────────────────┐
│                   Bridge ID                     │
├──────────────────┬─────────────────────────────┤
│  Priority (16 bits) │    MAC Address (48 bits)    │
│  Par défaut: 32768  │    Unique à chaque switch   │
└──────────────────┴─────────────────────────────┘

Exemple :
  Switch A : 32768 + 00:11:22:33:44:55 → BID = 32768.001122334455
  Switch B : 32768 + 00:AA:BB:CC:DD:EE → BID = 32768.00AABBCCDDEE
```

### Processus d'élection

1. Au démarrage, chaque switch se considère Root Bridge
2. Les switches échangent des **BPDU** contenant leur BID
3. Le switch avec le **BID le plus bas** devient Root Bridge
4. En cas d'égalité de priorité → la MAC la plus basse gagne

```
Élection :

Switch A (Priority 32768, MAC ...44:55)
Switch B (Priority 32768, MAC ...CC:DD)
Switch C (Priority 32768, MAC ...11:22)  ← Plus petite MAC = ROOT

Pour forcer un switch comme Root :
Switch C(config)# spanning-tree vlan 1 priority 4096
```

### Vérification

```cisco
Switch# show spanning-tree

VLAN0001
  Spanning tree enabled protocol ieee
  Root ID    Priority    4096
             Address     0011.2233.1122
             This bridge is the root

  Bridge ID  Priority    4096
             Address     0011.2233.1122
```

---

## États des ports STP

### Les 5 états

| État | Durée | Apprend MAC | Forward | Description |
|------|-------|-------------|---------|-------------|
| **Disabled** | - | Non | Non | Port administrativement désactivé |
| **Blocking** | - | Non | Non | Bloqué pour éviter les boucles |
| **Listening** | 15s | Non | Non | Écoute les BPDU, calcule la topologie |
| **Learning** | 15s | Oui | Non | Apprend les MAC, prépare le forwarding |
| **Forwarding** | - | Oui | Oui | Opérationnel, transmet les trames |

### Transitions normales

```
Port activé
    ↓
Blocking (20s) ──→ Listening (15s) ──→ Learning (15s) ──→ Forwarding
                                                              │
                         Temps total : ~50 secondes           │
                                                              ↓
                                                         Port actif
```

**Problème :** 50 secondes de convergence = trop lent pour les réseaux modernes !

### Rôles des ports

| Rôle | Description |
|------|-------------|
| **Root Port** | Meilleur chemin vers le Root Bridge (1 par switch non-root) |
| **Designated Port** | Port qui forward vers un segment (1 par segment) |
| **Blocked Port** | Port désactivé pour casser les boucles |

```
Exemple de topologie :

        [Root Bridge]
        Switch A
       /          \
    DP/            \DP     (DP = Designated Port)
     /              \
Switch B ────────── Switch C
   RP \     BP      / RP   (RP = Root Port)
       \          /        (BP = Blocked Port)
        └────────┘
```

---

## Rapid Spanning Tree Protocol (RSTP)

### Pourquoi RSTP ?

STP classique met **30 à 50 secondes** pour converger. C'est inacceptable pour les applications modernes. **RSTP** réduit ce temps à **quelques secondes**.

### Améliorations de RSTP

| Aspect | STP (802.1D) | RSTP (802.1w) |
|--------|--------------|---------------|
| **Convergence** | 30-50 secondes | 1-5 secondes |
| **États des ports** | 5 états | 3 états |
| **Détection de panne** | Lente (timers) | Rapide (hello manqués) |
| **Compatibilité** | - | Compatible avec STP |

### États des ports RSTP

RSTP simplifie à **3 états** :

| État RSTP | Équivalent STP | Description |
|-----------|----------------|-------------|
| **Discarding** | Disabled, Blocking, Listening | Ne transmet pas |
| **Learning** | Learning | Apprend les MAC |
| **Forwarding** | Forwarding | Opérationnel |

### Nouveaux rôles RSTP

| Rôle | Description |
|------|-------------|
| **Root Port** | Identique à STP |
| **Designated Port** | Identique à STP |
| **Alternate Port** | Backup du Root Port (prêt à prendre le relais) |
| **Backup Port** | Backup d'un Designated Port |

```
Avec RSTP :

        [Root Bridge]
              │
         RP   │
    Switch B ─┼─────────── Switch C
              │    AP          │
              │                │
              └────────────────┘

AP (Alternate Port) : Prêt à devenir RP instantanément si le RP tombe
```

### Activation de RSTP (Cisco)

```cisco
! Activer RSTP (mode Rapid PVST+)
Switch(config)# spanning-tree mode rapid-pvst

! Vérifier
Switch# show spanning-tree summary
Switch is in rapid-pvst mode
```

---

## Optimisation de STP

### Forcer le Root Bridge

Ne jamais laisser l'élection au hasard. Définir explicitement le Root Bridge :

```cisco
! Méthode 1 : Définir une priorité basse
Switch(config)# spanning-tree vlan 1 priority 4096

! Méthode 2 : Utiliser la macro root primary
Switch(config)# spanning-tree vlan 1 root primary

! Pour un backup
Switch(config)# spanning-tree vlan 1 root secondary
```

### Ajuster le coût des chemins

Par défaut, le coût dépend de la bande passante :

| Bande passante | Coût STP |
|----------------|----------|
| 10 Gbps | 2 |
| 1 Gbps | 4 |
| 100 Mbps | 19 |
| 10 Mbps | 100 |

Pour forcer un chemin préféré :

```cisco
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# spanning-tree cost 10
```

### PortFast (ports access)

**PortFast** permet aux ports access de passer directement en Forwarding, évitant 30 secondes d'attente pour les PC :

```cisco
! Sur un port spécifique
Switch(config)# interface FastEthernet0/1
Switch(config-if)# spanning-tree portfast

! Globalement pour tous les ports access
Switch(config)# spanning-tree portfast default
```

**Attention :** Ne JAMAIS activer PortFast sur un port connecté à un autre switch !

### BPDU Guard

Protège les ports PortFast contre les switches non autorisés :

```cisco
! Si un BPDU est reçu, le port passe en err-disabled
Switch(config)# interface FastEthernet0/1
Switch(config-if)# spanning-tree bpduguard enable

! Ou globalement
Switch(config)# spanning-tree portfast bpduguard default
```

---

## Dépannage STP

### Commandes de diagnostic

```cisco
! Vue d'ensemble
Switch# show spanning-tree

! Résumé par VLAN
Switch# show spanning-tree summary

! Détails d'une interface
Switch# show spanning-tree interface GigabitEthernet0/1

! Voir le Root Bridge
Switch# show spanning-tree root
```

### Exemple de sortie

```cisco
Switch# show spanning-tree vlan 1

VLAN0001
  Spanning tree enabled protocol rstp
  Root ID    Priority    4096
             Address     0011.2233.4455
             Cost        4
             Port        1 (GigabitEthernet0/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32769  (priority 32768 sys-id-ext 1)
             Address     00AA.BBCC.DDEE
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec
             Aging Time  300

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----------------
Gi0/1            Root FWD 4         128.1    P2p
Gi0/2            Desg FWD 4         128.2    P2p
Fa0/1            Desg FWD 19        128.3    P2p Edge
```

### Problèmes courants

| Problème | Symptôme | Solution |
|----------|----------|----------|
| Root Bridge mal placé | Trafic sous-optimal | Définir la priorité manuellement |
| Convergence lente | Perte de connectivité prolongée | Passer à RSTP |
| Port en Blocking | Pas de trafic | Vérifier la topologie |
| Port en err-disabled | Port down | `shutdown` puis `no shutdown` |

---

## Résumé

### STP vs RSTP

| Aspect | STP | RSTP |
|--------|-----|------|
| **Standard** | 802.1D | 802.1w |
| **Convergence** | 30-50s | 1-5s |
| **États** | 5 | 3 |
| **À utiliser** | Legacy uniquement | Toujours préféré |

### Points clés

```
✓ STP empêche les boucles en bloquant des liens redondants
✓ Le Root Bridge est le centre de la topologie (BID le plus bas)
✓ Toujours définir le Root Bridge explicitement
✓ Utiliser RSTP pour une convergence rapide
✓ PortFast pour les ports access (jamais vers un switch !)
✓ BPDU Guard pour protéger les ports PortFast
```

### Commandes essentielles

| Commande | Usage |
|----------|-------|
| `show spanning-tree` | Vue d'ensemble STP |
| `spanning-tree mode rapid-pvst` | Activer RSTP |
| `spanning-tree vlan X priority Y` | Définir la priorité |
| `spanning-tree portfast` | Activer PortFast |
| `spanning-tree bpduguard enable` | Activer BPDU Guard |

---

## Ressources

| Ressource | Lien |
|-----------|------|
| Cisco STP Documentation | https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/ |
| Understanding STP | https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/5234-5.html |
| RSTP Configuration Guide | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/12-2_55_se/configuration/guide/scg3750/swstp.html |
