# Lab Spanning Tree Protocol - Automatisation Ansible

Lab pratique pour apprendre le Spanning Tree Protocol (STP) avec une topologie GNS3 automatisée.

## Table des matières

1. [Objectifs pédagogiques](#objectifs-pédagogiques)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Exercices détaillés](#exercices-détaillés)
6. [Commandes STP essentielles](#commandes-stp-essentielles)
7. [Concepts clés](#concepts-clés)

---

## Objectifs pédagogiques

- Comprendre pourquoi STP est nécessaire (éviter les boucles)
- Identifier le Root Bridge et comprendre son élection
- Reconnaître les rôles des ports (Root, Designated, Alternate)
- Comprendre les états des ports (Blocking, Forwarding, etc.)
- Configurer manuellement le Root Bridge
- Différencier STP classique et RSTP

---

## Prérequis

- Ansible installé (`brew install ansible`)
- Python 3
- GNS3 connecté au serveur distant (192.168.139.14)

---

## Architecture

```
ansible/
├── ansible.cfg              # Configuration Ansible locale
├── inventory.yml            # Connexion au serveur GNS3
├── group_vars/
│   └── all.yml              # Variables (switches, liens, config STP)
├── playbooks/
│   ├── 01_create_topology.yml   # Créer 3 switches en triangle
│   ├── 02_configure_stp.yml     # Configuration STP de base
│   ├── 03_root_election.yml     # Manipulation du Root Bridge
│   ├── 04_port_states.yml       # Observation des états des ports
│   └── 05_rstp.yml              # Passage en RSTP
├── scripts/
│   └── cisco_cli.py         # Script pour envoyer des commandes Cisco
└── switch_info.yml          # Généré automatiquement (ports console)
```

### Topologie créée

```
          SW1 (Root Bridge)
         /   \
      e0/0   e0/1
       /       \
     SW2 ----- SW3
         e0/1

     STP bloque un port pour éviter la boucle
```

---

## Démarrage rapide

```bash
cd ansible

# 1. Créer la topologie (3 switches en triangle)
ansible-playbook playbooks/01_create_topology.yml

# 2. Observer et configurer STP
ansible-playbook playbooks/02_configure_stp.yml
```

---

## Exercices détaillés

### Exercice 1 : Création de la topologie

**Objectif** : Créer une topologie avec boucle et observer STP en action.

```bash
ansible-playbook playbooks/01_create_topology.yml
```

#### Comment vérifier

**1. Ouvrir GNS3** et observer la topologie créée (3 switches en triangle).

**2. Se connecter à un switch** :
```bash
telnet 192.168.139.14 5000   # SW1
```

**3. Vérifier que STP est actif** :
```
SW1# show spanning-tree

VLAN0001
  Spanning tree enabled protocol ieee    ← STP activé
  Root ID    Priority    32769
             Address     aabb.cc00.0100
             This bridge is the root     ← Ce switch est Root Bridge
```

**4. Identifier le port bloqué** (sur SW3) :
```bash
telnet 192.168.139.14 5002   # SW3
```
```
SW3# show spanning-tree vlan 1

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- ----
Et0/0               Root FWD 100       128.1    Shr    ← Port vers Root
Et0/1               Altn BLK 100       128.2    Shr    ← PORT BLOQUÉ
```

Le port `Et0/1` est en état `BLK` (Blocking) - STP a cassé la boucle.

---

### Exercice 2 : Configuration du Root Bridge

**Objectif** : Configurer explicitement SW1 comme Root Bridge.

```bash
ansible-playbook playbooks/02_configure_stp.yml
```

#### Comment vérifier

**1. Vérifier la priorité AVANT** :
```
SW1# show spanning-tree vlan 1 | include Priority
  Root ID    Priority    32769        ← Priorité par défaut
  Bridge ID  Priority    32769
```

**2. Après le playbook, vérifier la nouvelle priorité** :
```
SW1# show spanning-tree vlan 1 | include Priority
  Root ID    Priority    4097         ← Nouvelle priorité (4096 + VLAN 1)
  Bridge ID  Priority    4097
```

**3. Confirmer sur les autres switches** :
```
SW2# show spanning-tree root

                                        Root    Hello Max Fwd
Vlan           Root ID         Cost    Port    Time  Age Dly
------------   ----------------  ----  -------  ---- ---- ----
VLAN0001       4097 aabb.cc00.0100  100  Et0/0    2   20   15
               ↑                         ↑
               Priorité du Root          Port vers le Root
```

---

### Exercice 3 : Changement du Root Bridge

**Objectif** : Observer ce qui se passe quand le Root Bridge change.

```bash
ansible-playbook playbooks/03_root_election.yml
```

#### Comment vérifier

**1. AVANT - Noter quel port est bloqué** :
```
SW3# show spanning-tree vlan 1 | include BLK
Et0/1               Altn BLK 100       128.2    Shr
```

**2. Exécuter le playbook** (SW2 devient Root)

**3. APRÈS - Observer les changements** :
```
SW2# show spanning-tree vlan 1 | include root
             This bridge is the root    ← SW2 est maintenant Root
```

**4. Vérifier le nouveau port bloqué** :
```
SW1# show spanning-tree vlan 1 | include BLK
# ou
SW3# show spanning-tree vlan 1 | include BLK
```

Le port bloqué peut avoir changé car le chemin optimal a été recalculé.

---

### Exercice 4 : États des ports

**Objectif** : Comprendre les rôles et états des ports.

```bash
ansible-playbook playbooks/04_port_states.yml
```

#### Comment vérifier

**1. Afficher tous les ports STP** :
```
SW1# show spanning-tree vlan 1

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- ----
Et0/0               Desg FWD 100       128.1    Shr
Et0/1               Desg FWD 100       128.2    Shr
```

**Lecture du tableau** :

| Colonne | Signification |
|---------|---------------|
| Role | `Root` = vers Root, `Desg` = Designated, `Altn` = Alternate |
| Sts | `FWD` = Forwarding, `BLK` = Blocking, `LRN` = Learning |
| Cost | Coût du chemin (100 = Fast Ethernet) |

**2. Détails d'un port spécifique** :
```
SW1# show spanning-tree interface ethernet 0/0 detail

Port 1 (Ethernet0/0) of VLAN0001 is designated forwarding
   Port path cost 100, Port priority 128, Port Identifier 128.1
   Designated root has priority 4097, address aabb.cc00.0100
   Designated bridge has priority 4097, address aabb.cc00.0100
```

**3. Observer une transition d'état** (débrancher/rebrancher un câble dans GNS3) :
```
SW1# show spanning-tree vlan 1

# Observer les états transitoires :
# BLK → LIS → LRN → FWD (prend environ 30 secondes en STP classique)
```

---

### Exercice 5 : Passage en RSTP

**Objectif** : Activer RSTP pour une convergence plus rapide.

```bash
ansible-playbook playbooks/05_rstp.yml
```

#### Comment vérifier

**1. AVANT - Vérifier le mode actuel** :
```
SW1# show spanning-tree summary | include mode
Switch is in pvst mode              ← STP classique
```

**2. APRÈS - Vérifier le nouveau mode** :
```
SW1# show spanning-tree summary | include mode
Switch is in rapid-pvst mode        ← RSTP activé
```

**3. Confirmer dans le détail** :
```
SW1# show spanning-tree vlan 1

VLAN0001
  Spanning tree enabled protocol rstp    ← "rstp" au lieu de "ieee"
```

**4. Tester la convergence rapide** :
- Dans GNS3, clic droit sur un lien → Suspend
- Observer le temps de convergence (quelques secondes au lieu de 30-50)
- Clic droit → Resume pour rétablir

---

## Commandes STP essentielles

### Vérification

| Commande | Utilité |
|----------|---------|
| `show spanning-tree` | État STP complet |
| `show spanning-tree vlan 1` | STP pour VLAN 1 |
| `show spanning-tree root` | Info sur le Root Bridge |
| `show spanning-tree summary` | Mode STP actif |
| `show spanning-tree interface e0/0 detail` | Détails d'un port |
| `show spanning-tree vlan 1 | include BLK` | Trouver les ports bloqués |
| `show spanning-tree vlan 1 | include root` | Identifier le Root |

### Configuration

| Commande | Utilité |
|----------|---------|
| `spanning-tree vlan 1 priority 4096` | Définir la priorité |
| `spanning-tree mode rapid-pvst` | Activer RSTP |
| `spanning-tree cost 100` | Modifier le coût d'un port |
| `spanning-tree portfast` | Activer PortFast (ports edge) |
| `spanning-tree bpduguard enable` | Protection BPDU Guard |

### Accès console

```bash
telnet 192.168.139.14 5000   # SW1
telnet 192.168.139.14 5001   # SW2
telnet 192.168.139.14 5002   # SW3
```

---

## Concepts clés

### Pourquoi STP est nécessaire

Sans STP, une boucle dans le réseau cause :
- **Broadcast storms** : Les frames circulent indéfiniment
- **Table MAC instable** : Les switches voient les MAC sur plusieurs ports
- **Saturation CPU** : Les switches sont submergés

### Élection du Root Bridge

1. Comparer les **priorités** (plus basse gagne)
2. Si égalité, comparer les **MAC addresses** (plus basse gagne)
3. Le gagnant devient **Root Bridge**

### Rôles des ports

| Rôle | Description | État |
|------|-------------|------|
| Root (RP) | Meilleur chemin vers le Root Bridge | Forwarding |
| Designated (DP) | Port qui forward vers un segment | Forwarding |
| Alternate (AP) | Backup du Root Port | Blocking |
| Backup (BP) | Backup du Designated Port | Blocking |

### États des ports

| État | Durée | Description |
|------|-------|-------------|
| Blocking | - | Ne transmet pas (port redondant) |
| Listening | 15 sec | Écoute les BPDU |
| Learning | 15 sec | Apprend les MAC addresses |
| Forwarding | - | Transmet normalement |

### STP vs RSTP

| Critère | STP (802.1D) | RSTP (802.1w) |
|---------|--------------|---------------|
| Convergence | 30-50 secondes | < 10 secondes |
| États | 5 | 3 (Discarding, Learning, Forwarding) |
| Commande Cisco | `spanning-tree mode pvst` | `spanning-tree mode rapid-pvst` |

---

## Troubleshooting

### Le port reste en Blocking

C'est normal si c'est un Alternate Port (redondance). Vérifier :
```
show spanning-tree vlan 1
```
Un port Alternate en BLK est le comportement attendu.

### Convergence lente

1. Vérifier le mode : `show spanning-tree summary`
2. Passer en RSTP : `spanning-tree mode rapid-pvst`
3. Activer PortFast sur les ports edge

### Identifier le Root Bridge

```
show spanning-tree root
```
ou chercher "This bridge is the root" dans :
```
show spanning-tree vlan 1
```

---

## Documentation officielle

- [Cisco STP Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/layer2/b_1612_layer2_9300_cg.html)
- [RSTP (802.1w) Overview](https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/24062-146.html)
- [GNS3 API Documentation](https://gns3-server.readthedocs.io/en/stable/api.html)
