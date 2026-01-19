# Cheatsheet Cisco STP - Spanning Tree Protocol

## C'est quoi STP ?

STP (Spanning Tree Protocol) empêche les **boucles** dans un réseau avec plusieurs switches interconnectés.

```
Sans STP :                    Avec STP :
   SW1 ←→ SW2                    SW1 ←→ SW2
    ↑  ✗  ↑                       ↑      ↑
    └──→──┘                       └──X───┘
   BOUCLE !                    Port bloqué
   (broadcast storm)           (pas de boucle)
```

---

## Nomenclature des interfaces Cisco

### Format : Type + Slot/Port

Les interfaces Cisco suivent le format : **Type** + **Slot/Port** (ou **Slot/Subslot/Port**)

```
Ethernet0/0
   │     │ │
   │     │ └── Port number (0, 1, 2, 3...)
   │     └──── Slot number (0, 1, 2...)
   └────────── Type d'interface
```

### Types d'interfaces courants

| Type | Abréviation | Vitesse | Description |
|------|-------------|---------|-------------|
| Ethernet | Et, E | 10 Mbps | Interface Ethernet legacy |
| FastEthernet | Fa, F | 100 Mbps | Fast Ethernet |
| GigabitEthernet | Gi, G | 1 Gbps | Gigabit Ethernet |
| TenGigabitEthernet | Te | 10 Gbps | 10 Gigabit Ethernet |
| Serial | Se, S | Variable | Liaison série (WAN) |
| Loopback | Lo | - | Interface virtuelle |
| Vlan | Vlan | - | Interface virtuelle de VLAN (SVI) |

### Exemples concrets

```
Ethernet0/0      → Slot 0, Port 0 (10 Mbps)
Ethernet0/2      → Slot 0, Port 2
FastEthernet0/1  → Slot 0, Port 1 (100 Mbps)
GigabitEthernet1/0/1  → Module 1, Slot 0, Port 1 (1 Gbps)
```

### Abréviations acceptées dans les commandes

Cisco accepte les abréviations tant qu'elles sont non-ambiguës :

```cisco
! Ces commandes sont équivalentes :
interface Ethernet0/0
interface ethernet0/0
interface Et0/0
interface e0/0

! Pour GigabitEthernet :
interface GigabitEthernet1/0/1
interface Gi1/0/1
interface g1/0/1
```

### Slots sur les switches IOU (GNS3)

Sur les switches Cisco IOU utilisés dans GNS3, la numérotation typique est :

```
Slot 0 : Ethernet0/0 à Ethernet0/3   (4 ports)
Slot 1 : Ethernet1/0 à Ethernet1/3   (4 ports)
Slot 2 : Ethernet2/0 à Ethernet2/3   (4 ports)
Slot 3 : Ethernet3/0 à Ethernet3/3   (4 ports)
         ─────────────────────────
         Total : 16 ports Ethernet
```

### Documentation officielle Cisco

**Interfaces :**
- [Interface and Hardware Components Configuration Guide - Catalyst 9300](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-16/configuration_guide/int_hw/b_1716_int_and_hw_9300_cg.html) - Configuration des interfaces Ethernet

**VLANs :**
- [VLAN Configuration Guide - Catalyst 9200](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-16/configuration_guide/vxlan/b_1716_vlan_9200_cg.html) - Configuration des VLANs (IOS XE 17.16.x)
- [VLAN Configuration Guide - Catalyst 2960-X](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/vlan/configuration_guide/b_vlan_1522e_2960x_cg/b_vlan_152ex_2960-x_cg_chapter_011.html) - Configuration des VLANs (IOS 15.2)

**Spanning Tree Protocol :**
- [Spanning Tree Protocol - Cisco Tech Portal](https://www.cisco.com/c/en/us/tech/lan-switching/spanning-tree-protocol/index.html) - Page centrale STP avec ressources
- [Configuring STP - Catalyst 9600 (IOS XE 17.12.x)](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9600_cg/configuring_spanning_tree_protocol.html) - Guide complet STP/RSTP
- [Configuring STP - Catalyst 9200 (IOS XE 16.12.x)](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/16-12/configuration_guide/lyr2/b_1612_lyr2_9200_cg/configuring_spanning_tree_protocol.html) - Guide STP pour Catalyst 9200

**Général :**
- [Cisco IOS XE 17 - All Configuration Guides](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-installation-and-configuration-guides-list.html) - Portail de tous les guides IOS XE 17
- [Cisco IOS Command Reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref.html) - Référence complète des commandes

---

## Les rôles STP

### Rôles des switches

| Rôle | Description |
|------|-------------|
| **Root Bridge** | Le "chef" du réseau STP. Tous les autres switches calculent leur chemin vers lui |

**Comment est élu le Root Bridge ?**
```
1. Priorité la plus BASSE gagne (défaut = 32768)
2. Si égalité : MAC address la plus BASSE gagne
```

### Rôles des ports

| Rôle | Abréviation | Description |
|------|-------------|-------------|
| **Root Port** | Root | Port avec le meilleur chemin vers le Root Bridge |
| **Designated Port** | Desg | Port qui forward le trafic sur un segment |
| **Alternate/Blocked** | Altn/BLK | Port bloqué pour éviter les boucles |

```
        Root Bridge (SW1)
        Desg ┌───┐ Desg
        ────►│SW1│◄────
             └───┘
            /     \
      Root /       \ Root
          ▼         ▼
      ┌───┐         ┌───┐
      │SW2│◄───────►│SW3│
      └───┘  Desg   └───┘
             BLK
         (bloqué pour
         éviter la boucle)
```

---

## Les états des ports

Un port passe par plusieurs états avant de forwarder :

```
État        │ Durée    │ Ce qui se passe
────────────┼──────────┼─────────────────────────────────
Blocking    │ 20 sec   │ Reçoit les BPDU, ne forward rien
Listening   │ 15 sec   │ Envoie/reçoit BPDU, apprend la topologie
Learning    │ 15 sec   │ Apprend les MAC, ne forward pas encore
Forwarding  │ -        │ Forward le trafic normalement
Disabled    │ -        │ Port désactivé
```

**Temps total pour passer en Forwarding = ~50 secondes !**

---

## Commandes show (visualisation)

### Voir l'état STP global

```cisco
show spanning-tree
```
Affiche l'état STP pour tous les VLANs.

### Voir STP pour un VLAN spécifique

```cisco
show spanning-tree vlan 10
```

**Exemple de sortie :**
```
VLAN0010
  Spanning tree enabled protocol ieee
  Root ID    Priority    32778
             Address     aabb.cc00.0100
             This bridge is the root    ◄── Ce switch est le Root Bridge

  Bridge ID  Priority    32778  (priority 32768 sys-id-ext 10)
             Address     aabb.cc00.0100

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----
Et0/0            Desg FWD 100       128.1    Shr
Et0/1            Desg FWD 100       128.2    Shr
```

### Voir qui est le root bridge

```cisco
show spanning-tree root
```

### Voir les infos du bridge local

```cisco
show spanning-tree bridge
```

### Voir STP sur une interface

```cisco
show spanning-tree interface Ethernet0/0
show spanning-tree interface e0/0 detail
```

### Voir un résumé rapide

```cisco
show spanning-tree summary
```

---

## Commandes de CONFIGURATION

### Forcer un switch comme root bridge

**Méthode 1 : Définir la priorité manuellement**
```cisco
configure terminal
spanning-tree vlan 10 priority 4096
end
```

**Priorités valides :** 0, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768 (défaut)

Plus la priorité est **basse**, plus le switch a de chances d'être Root.

**Méthode 2 : Utiliser la macro root primary**
```cisco
configure terminal
spanning-tree vlan 10 root primary
end
```
Cette commande calcule automatiquement une priorité plus basse que le Root actuel.

**Méthode 3 : Root secondary (backup)**
```cisco
configure terminal
spanning-tree vlan 10 root secondary
end
```
Configure le switch comme Root de secours (priorité 28672).

---

### Modifier le coût d'un port

Le coût influence le choix du chemin vers le Root Bridge.

```cisco
configure terminal
interface Ethernet0/0
spanning-tree cost 50
end
```

**Coûts par défaut (IEEE) :**

| Vitesse | Coût |
|---------|------|
| 10 Mbps | 100 |
| 100 Mbps | 19 |
| 1 Gbps | 4 |
| 10 Gbps | 2 |

**Plus le coût est bas = meilleur chemin**

---

### Modifier la priorité d'un port

```cisco
configure terminal
interface Ethernet0/0
spanning-tree port-priority 64
end
```

Priorités valides : 0, 16, 32, 48, 64, 80, 96, 112, 128 (défaut), ...

Utilisé pour choisir quel port devient Root Port quand plusieurs liens existent.

---

### PortFast (pour les ports utilisateurs)

PortFast permet à un port de passer directement en Forwarding (skip les 50 sec).

**ATTENTION : Uniquement sur les ports vers des PC/serveurs, JAMAIS vers un autre switch !**

```cisco
configure terminal
interface Ethernet0/2
spanning-tree portfast
end
```

**Activer PortFast globalement (ports access seulement) :**
```cisco
configure terminal
spanning-tree portfast default
end
```

---

### BPDU Guard (protection)

Désactive le port si un BPDU est reçu (protège contre les switches non autorisés).

```cisco
configure terminal
interface Ethernet0/2
spanning-tree bpduguard enable
end
```

**Activer globalement sur tous les ports PortFast :**
```cisco
configure terminal
spanning-tree portfast bpduguard default
end
```

---

### Root Guard (protection du root bridge)

Empêche un port de devenir Root Port (protège la topologie).

```cisco
configure terminal
interface Ethernet0/0
spanning-tree guard root
end
```

---

## Modes STP

### PVST+ (Per-VLAN Spanning Tree Plus)

Mode par défaut Cisco. Un arbre STP par VLAN.

```cisco
configure terminal
spanning-tree mode pvst
end
```

### Rapid PVST+ (RSTP)

Version plus rapide (~2-3 sec au lieu de 50 sec).

```cisco
configure terminal
spanning-tree mode rapid-pvst
end
```

### MST (Multiple Spanning Tree)

Regroupe plusieurs VLANs dans une instance STP.

```cisco
configure terminal
spanning-tree mode mst
end
```

---

## Les timers STP

| Timer | Défaut | Description |
|-------|--------|-------------|
| Hello | 2 sec | Fréquence d'envoi des BPDU |
| Forward Delay | 15 sec | Temps dans Listening et Learning |
| Max Age | 20 sec | Temps avant qu'un BPDU soit considéré périmé |

### Modifier les timers (sur le root bridge uniquement !)

```cisco
configure terminal
spanning-tree vlan 10 hello-time 1
spanning-tree vlan 10 forward-time 10
spanning-tree vlan 10 max-age 15
end
```

---

## Bridge ID et priority

Le Bridge ID est composé de :

```
┌────────────────┬──────────────────┐
│   Priority     │   MAC Address    │
│   (2 bytes)    │   (6 bytes)      │
└────────────────┴──────────────────┘

Priority = Bridge Priority (32768 par défaut) + VLAN ID

Exemple VLAN 10 :
Priority = 32768 + 10 = 32778
```

---

## Calcul du meilleur chemin

STP utilise ces critères (dans l'ordre) pour élire le Root Port :

```
1. Root Path Cost le plus BAS
   (somme des coûts pour atteindre le Root)

2. Bridge ID de l'émetteur le plus BAS
   (en cas d'égalité de coût)

3. Port Priority le plus BAS
   (si même switch voisin)

4. Port ID le plus BAS
   (dernier recours)
```

---

## Exemple complet de configuration (noeud par noeud)

### Topologie cible

```
                    PC1
                     │
                   e0/2
                     │
                 ┌───────┐
                 │Switch1│ ◄── ROOT BRIDGE (Priority 4096)
                 │ (Root)│
                 └───────┘
                /         \
           e0/0             e0/1
              /               \
         e0/0                 e0/1
        ┌───────┐           ┌───────┐
        │Switch2│───e0/1────│Switch3│
        └───────┘   e0/0    └───────┘
             │      (BLK)        │
           e0/2                e0/2
             │                   │
            PC2                 PC3

Tous les PCs sont dans le VLAN 10 (192.168.10.0/24)
```

### Liens et ports

| Lien | Switch A | Port A | Switch B | Port B |
|------|----------|--------|----------|--------|
| Trunk 1 | Switch1 | e0/0 | Switch2 | e0/0 |
| Trunk 2 | Switch1 | e0/1 | Switch3 | e0/1 |
| Trunk 3 | Switch2 | e0/1 | Switch3 | e0/0 |
| Access | Switch1 | e0/2 | PC1 | - |
| Access | Switch2 | e0/2 | PC2 | - |
| Access | Switch3 | e0/2 | PC3 | - |

---

### SWITCH 1 - configuration complète (root bridge)

```cisco
! ============================================
! SWITCH 1 - ROOT BRIDGE
! ============================================

! Passer en mode privilégié
enable

! Entrer en configuration
configure terminal

! --------------------------------------------
! 1. Configurer le hostname
! --------------------------------------------
hostname Switch1

! --------------------------------------------
! 2. Créer le VLAN 10
! --------------------------------------------
vlan 10
name USERS
exit

! --------------------------------------------
! 3. Configurer le trunk vers Switch2 (e0/0)
! --------------------------------------------
interface Ethernet0/0
description Trunk vers Switch2
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 4. Configurer le trunk vers Switch3 (e0/1)
! --------------------------------------------
interface Ethernet0/1
description Trunk vers Switch3
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 5. Configurer le port access vers PC1 (e0/2)
! --------------------------------------------
interface Ethernet0/2
description Vers PC1
switchport mode access
switchport access vlan 10
spanning-tree portfast
spanning-tree bpduguard enable
no shutdown
exit

! --------------------------------------------
! 6. Forcer ce switch comme ROOT BRIDGE
! --------------------------------------------
spanning-tree vlan 10 priority 4096

! --------------------------------------------
! 7. Sauvegarder la configuration
! --------------------------------------------
end
write memory
```

---

### SWITCH 2 - Configuration complète

```cisco
! ============================================
! SWITCH 2
! ============================================

enable
configure terminal

! --------------------------------------------
! 1. Configurer le hostname
! --------------------------------------------
hostname Switch2

! --------------------------------------------
! 2. Créer le VLAN 10
! --------------------------------------------
vlan 10
name USERS
exit

! --------------------------------------------
! 3. Configurer le trunk vers Switch1 (e0/0)
! --------------------------------------------
interface Ethernet0/0
description Trunk vers Switch1 (ROOT)
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 4. Configurer le trunk vers Switch3 (e0/1)
! --------------------------------------------
interface Ethernet0/1
description Trunk vers Switch3
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 5. Configurer le port access vers PC2 (e0/2)
! --------------------------------------------
interface Ethernet0/2
description Vers PC2
switchport mode access
switchport access vlan 10
spanning-tree portfast
spanning-tree bpduguard enable
no shutdown
exit

! --------------------------------------------
! 6. Sauvegarder la configuration
! --------------------------------------------
end
write memory
```

---

### SWITCH 3 - Configuration complète

```cisco
! ============================================
! SWITCH 3
! ============================================

enable
configure terminal

! --------------------------------------------
! 1. Configurer le hostname
! --------------------------------------------
hostname Switch3

! --------------------------------------------
! 2. Créer le VLAN 10
! --------------------------------------------
vlan 10
name USERS
exit

! --------------------------------------------
! 3. Configurer le trunk vers Switch2 (e0/0)
!    Ce port sera probablement BLOQUÉ par STP
! --------------------------------------------
interface Ethernet0/0
description Trunk vers Switch2 (sera bloque par STP)
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 4. Configurer le trunk vers Switch1 (e0/1)
! --------------------------------------------
interface Ethernet0/1
description Trunk vers Switch1 (ROOT)
switchport trunk encapsulation dot1q
switchport mode trunk
switchport trunk allowed vlan 1,10
no shutdown
exit

! --------------------------------------------
! 5. Configurer le port access vers PC3 (e0/2)
! --------------------------------------------
interface Ethernet0/2
description Vers PC3
switchport mode access
switchport access vlan 10
spanning-tree portfast
spanning-tree bpduguard enable
no shutdown
exit

! --------------------------------------------
! 6. Sauvegarder la configuration
! --------------------------------------------
end
write memory
```

---

### PC1 - Configuration IP (VPCS)

```
! ============================================
! PC1 - Connecté à Switch1
! ============================================

ip 192.168.10.1 255.255.255.0
save
```

---

### PC2 - Configuration IP (VPCS)

```
! ============================================
! PC2 - Connecté à Switch2
! ============================================

ip 192.168.10.2 255.255.255.0
save
```

---

### PC3 - Configuration IP (VPCS)

```
! ============================================
! PC3 - Connecté à Switch3
! ============================================

ip 192.168.10.3 255.255.255.0
save
```

---

### Vérification après configuration

#### Sur chaque switch : vérifier les VLANs

```cisco
show vlan brief
```

**Résultat attendu :**
```
VLAN Name                             Status    Ports
---- -------------------------------- --------- ----------
1    default                          active
10   USERS                            active    Et0/2
```

#### Sur chaque switch : vérifier les trunks

```cisco
show interfaces trunk
```

**Résultat attendu :**
```
Port        Mode         Encapsulation  Status        Native vlan
Et0/0       on           802.1q         trunking      1
Et0/1       on           802.1q         trunking      1

Port        Vlans allowed on trunk
Et0/0       1,10
Et0/1       1,10
```

#### Vérifier STP sur Switch1 (root bridge)

```cisco
Switch1# show spanning-tree vlan 10
```

**Résultat attendu :**
```
VLAN0010
  Spanning tree enabled protocol ieee
  Root ID    Priority    4106
             Address     aabb.cc00.0100
             This bridge is the root      ◄── CONFIRME ROOT BRIDGE
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    4106  (priority 4096 sys-id-ext 10)
             Address     aabb.cc00.0100

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----
Et0/0            Desg FWD 100       128.1    Shr    ◄── Designated
Et0/1            Desg FWD 100       128.2    Shr    ◄── Designated
Et0/2            Desg FWD 100       128.3    Shr    ◄── Designated (vers PC)
```

#### Vérifier STP sur Switch2

```cisco
Switch2# show spanning-tree vlan 10
```

**Résultat attendu :**
```
VLAN0010
  Root ID    Priority    4106
             Address     aabb.cc00.0100
             Cost        100
             Port        1 (Ethernet0/0)      ◄── Chemin vers Root

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----
Et0/0            Root FWD 100       128.1    Shr    ◄── ROOT PORT (vers Switch1)
Et0/1            Desg FWD 100       128.2    Shr    ◄── Designated (vers Switch3)
Et0/2            Desg FWD 100       128.3    Shr    ◄── Designated (vers PC)
```

#### Vérifier STP sur Switch3 (port bloqué)

```cisco
Switch3# show spanning-tree vlan 10
```

**Résultat attendu :**
```
VLAN0010
  Root ID    Priority    4106
             Address     aabb.cc00.0100
             Cost        100
             Port        2 (Ethernet0/1)      ◄── Chemin vers Root

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----
Et0/0            Altn BLK 100       128.1    Shr    ◄── BLOQUÉ ! (évite la boucle)
Et0/1            Root FWD 100       128.2    Shr    ◄── ROOT PORT (vers Switch1)
Et0/2            Desg FWD 100       128.3    Shr    ◄── Designated (vers PC)
```

#### Vérifier la connectivité (depuis PC1)

```
PC1> ping 192.168.10.2
PC1> ping 192.168.10.3
```

**Les pings doivent fonctionner même avec le port bloqué** (le trafic passe par Switch1).

---

### Résumé des rôles STP après configuration

```
┌─────────────────────────────────────────────────────────────┐
│                     TOPOLOGIE STP FINALE                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                         PC1                                 │
│                          │                                  │
│                    [Desg FWD]                               │
│                          │                                  │
│                    ┌──────────┐                             │
│                    │ SWITCH1  │                             │
│                    │  ROOT    │ Priority: 4096              │
│                    │ BRIDGE   │                             │
│                    └──────────┘                             │
│                   /            \                            │
│            [Desg FWD]      [Desg FWD]                       │
│                 /                \                          │
│           [Root FWD]          [Root FWD]                    │
│               /                    \                        │
│        ┌──────────┐            ┌──────────┐                 │
│        │ SWITCH2  │            │ SWITCH3  │                 │
│        └──────────┘            └──────────┘                 │
│              │      \        /      │                       │
│        [Desg FWD]   [Desg FWD]──[Altn BLK]  [Desg FWD]      │
│              │              ▲               │               │
│             PC2         PORT BLOQUÉ        PC3              │
│                     (évite la boucle)                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting STP

### Le réseau est lent / broadcast storm

```cisco
show spanning-tree
show spanning-tree blockedports
show spanning-tree inconsistentports
```

### Un port reste en Blocking trop longtemps

```cisco
show spanning-tree interface e0/0 detail
```

Vérifier :
- Le coût du port
- La priorité du port
- Les BPDU reçus

### Debug STP (attention en prod !)

```cisco
debug spanning-tree events
debug spanning-tree bpdu
```

Pour arrêter :
```cisco
undebug all
```

---

## Récap des commandes essentielles

### Show

| Commande | Description |
|----------|-------------|
| `show spanning-tree` | Vue globale |
| `show spanning-tree vlan X` | STP pour VLAN X |
| `show spanning-tree root` | Infos Root Bridge |
| `show spanning-tree summary` | Résumé |
| `show spanning-tree interface e0/0` | STP sur un port |

### Configuration

| Commande | Description |
|----------|-------------|
| `spanning-tree vlan X priority Y` | Définir priorité |
| `spanning-tree vlan X root primary` | Forcer Root Bridge |
| `spanning-tree cost X` | Modifier coût (sur interface) |
| `spanning-tree portfast` | Activer PortFast (sur interface) |
| `spanning-tree bpduguard enable` | Activer BPDU Guard (sur interface) |
| `spanning-tree mode rapid-pvst` | Passer en RSTP |

---

## Checklist dépannage STP

```
□ Quel switch est le Root Bridge ? (show spanning-tree root)
□ Les priorités sont-elles correctes ? (vérifier les priority)
□ Y a-t-il des ports bloqués ? (show spanning-tree blockedports)
□ Les ports PortFast sont-ils correctement configurés ?
□ Y a-t-il des inconsistances ? (show spanning-tree inconsistentports)
□ Les timers sont-ils standards ? (hello 2, forward 15, max-age 20)
```

---

## Exercices pratiques

### 1. Identifier les rôles

Avec cette topologie, identifiez les rôles de chaque port :

```
SW1 (Priority 32768, MAC 0001.0001.0001)
  └── e0/0 ─── e0/0 ── SW2 (Priority 32768, MAC 0002.0002.0002)
  └── e0/1 ─── e0/0 ── SW3 (Priority 32768, MAC 0003.0003.0003)
                         └── e0/1 ─── e0/1 ── SW2
```

### 2. Forcer le root bridge

Comment faire de SW3 le root bridge pour VLAN 10 ?

### 3. Optimiser la convergence

Comment réduire le temps de convergence STP pour les ports vers les PC ?

---

## Réponses

### 1. Rôles

- **SW1** = Root Bridge (MAC la plus basse)
  - e0/0 : Designated (vers SW2)
  - e0/1 : Designated (vers SW3)

- **SW2**
  - e0/0 : Root Port (vers SW1)
  - e0/1 : Designated (vers SW3, car MAC < SW3)

- **SW3**
  - e0/0 : Root Port (vers SW1)
  - e0/1 : **Alternate/Blocked** (vers SW2)

### 2. Forcer root bridge

```cisco
SW3# configure terminal
SW3(config)# spanning-tree vlan 10 priority 4096
SW3(config)# end
```

Ou :
```cisco
SW3(config)# spanning-tree vlan 10 root primary
```

### 3. Optimiser convergence

Activer PortFast sur les ports vers les PC :
```cisco
interface range e0/2 - 3
spanning-tree portfast
spanning-tree bpduguard enable
```

Ou passer en Rapid PVST+ :
```cisco
spanning-tree mode rapid-pvst
```
