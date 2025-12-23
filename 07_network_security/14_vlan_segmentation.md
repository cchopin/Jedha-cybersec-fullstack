# VLANs et segmentation

## Objectifs du cours

Ce cours présente les VLANs (Virtual Local Area Networks), un concept fondamental pour segmenter le trafic réseau de manière logique plutôt que physique.

Compétences visées :
- Comprendre le fonctionnement des VLANs et leur utilité
- Maîtriser le standard 802.1Q et le tagging des trames
- Distinguer les ports access et trunk
- Identifier les vulnérabilités liées aux VLANs et les mesures de protection

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **VLAN** | Virtual Local Area Network - Réseau local virtuel |
| **802.1Q** | Standard IEEE pour le tagging VLAN |
| **TPID** | Tag Protocol Identifier - Identifiant de protocole de tag (0x8100) |
| **VID** | VLAN Identifier - Identifiant du VLAN (12 bits, valeurs 1-4094) |
| **PCP** | Priority Code Point - Code de priorité pour QoS (3 bits) |
| **DEI** | Drop Eligible Indicator - Indicateur d'éligibilité au drop (1 bit) |
| **Access Port** | Port appartenant à un seul VLAN |
| **Trunk Port** | Port transportant plusieurs VLANs |
| **Native VLAN** | VLAN dont les trames ne sont pas taguées sur un trunk |
| **DTP** | Dynamic Trunking Protocol - Protocole de négociation de trunk Cisco |

---

## Comprendre les VLANs

### Le problème

Dans un réseau traditionnel, tous les appareils connectés à un switch partagent le même domaine de broadcast. Cela signifie :
- Les broadcasts sont envoyés à tous les appareils
- Aucune séparation logique entre départements
- Risques de sécurité accrus
- Performance dégradée dans les grands réseaux

### La solution : VLANs

Les VLANs permettent de créer plusieurs réseaux logiques sur une infrastructure physique unique.

**Exemple de segmentation :**

```
Switch physique unique
├─ VLAN 10 : Département RH
├─ VLAN 20 : Département IT
└─ VLAN 30 : Département Finance
```

Avantages :
- Isolation du trafic broadcast par VLAN
- Sécurité renforcée (séparation logique)
- Flexibilité de configuration
- Réduction des coûts matériels

---

## VLAN Tagging et le standard 802.1Q

### Structure du tag 802.1Q

Le standard 802.1Q insère un tag de 4 octets dans la trame Ethernet :

```
┌──────────────┬─────────────┬──────┬─────┬──────────────┬─────┐
│ MAC Dest     │ MAC Source  │ TPID │ TCI │ EtherType    │ ... │
└──────────────┴─────────────┴──────┴─────┴──────────────┴─────┘
                             └──────┬─────┘
                                802.1Q Tag (4 octets)
```

### Composition du tag

**TPID (Tag Protocol Identifier) - 16 bits :**
- Valeur : 0x8100
- Identifie la trame comme une trame 802.1Q

**TCI (Tag Control Information) - 16 bits :**
```
┌──────┬─────┬──────────────┐
│ PCP  │ DEI │     VID      │
└──────┴─────┴──────────────┘
  3 bits 1 bit    12 bits
```

- **PCP (Priority Code Point)** : Priorité QoS (0-7)
- **DEI (Drop Eligible Indicator)** : Éligibilité au drop en cas de congestion
- **VID (VLAN Identifier)** : Identifiant du VLAN (1-4094)

### Processus de tagging

**Trame entrante (port access) :**
```
[MAC Dest][MAC Source][EtherType][Data]
```

**Trame sur trunk (802.1Q) :**
```
[MAC Dest][MAC Source][0x8100][TCI][EtherType][Data]
```

**Trame sortante (port access) :**
```
[MAC Dest][MAC Source][EtherType][Data]
```

---

## Access Ports vs Trunk Ports

### Access Ports

Un port access appartient à un seul VLAN.

**Caractéristiques :**
- Connecté à un appareil final (PC, téléphone, imprimante)
- Ne taggue pas les trames sortantes
- Assume que toutes les trames entrantes appartiennent à son VLAN
- Configuration simple

**Configuration Cisco :**
```
Switch(config)# interface gigabitEthernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
```

### Trunk Ports

Un port trunk transporte plusieurs VLANs.

**Caractéristiques :**
- Connecte deux switches ou un switch à un routeur
- Taggue les trames avec 802.1Q
- Permet le passage de plusieurs VLANs
- Nécessite une configuration explicite

**Configuration Cisco :**
```
Switch(config)# interface gigabitEthernet 0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk encapsulation dot1q
Switch(config-if)# switchport trunk allowed vlan 10,20,30
```

---

## Native VLAN et risques de sécurité

### Concept du Native VLAN

Le Native VLAN est le VLAN dont les trames ne sont pas taguées sur un trunk.

**Par défaut :**
- VLAN 1 est le Native VLAN
- Les trames du VLAN 1 circulent sans tag 802.1Q

**Pourquoi c'est important :**
- Compatibilité avec des équipements ne supportant pas 802.1Q
- Risque de sécurité si mal configuré

### VLAN Hopping Attacks

#### 1. Switch Spoofing

L'attaquant configure son appareil pour négocier un trunk avec le switch.

**Scénario :**
```
Attaquant  ──DTP──> Switch
           <──DTP──
              ↓
         Trunk formé
              ↓
    Accès à tous les VLANs
```

**Prévention :**
```
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate
```

#### 2. Double Tagging

L'attaquant envoie une trame avec deux tags VLAN.

**Mécanisme :**
```
1. Attaquant envoie : [MAC][0x8100][VLAN 1][0x8100][VLAN 20][Data]
2. Premier switch retire le premier tag (VLAN 1, native)
3. Trame devient : [MAC][0x8100][VLAN 20][Data]
4. Deuxième switch transmet au VLAN 20
```

**Prévention :**
```
Switch(config)# vlan 999
Switch(config-if)# switchport trunk native vlan 999
```

---

## Mitigation des risques VLAN

### 1. Désactiver DTP

Dynamic Trunking Protocol permet la négociation automatique de trunks.

```
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate
```

### 2. Changer le Native VLAN

Utiliser un VLAN inutilisé comme Native VLAN.

```
Switch(config-if)# switchport trunk native vlan 999
```

### 3. Limiter les VLANs autorisés

Ne permettre que les VLANs nécessaires sur chaque trunk.

```
Switch(config-if)# switchport trunk allowed vlan 10,20,30
```

### 4. Utiliser les VLAN ACLs (VACLs)

Contrôler le trafic inter-VLAN au niveau du switch.

```
Switch(config)# vlan access-map BLOCK_TRAFFIC 10
Switch(config-access-map)# match ip address 100
Switch(config-access-map)# action drop
Switch(config)# vlan filter BLOCK_TRAFFIC vlan-list 10
```

### 5. Private VLANs

Isoler les ports au sein d'un même VLAN.

**Types de ports :**
- **Promiscuous** : Communique avec tous
- **Isolated** : Communique seulement avec promiscuous
- **Community** : Communique avec community et promiscuous

---

## Configuration GNS3

Pour pratiquer ces concepts, utilisez GNS3 sur la plateforme Jedha.

**Topologie suggérée :**
```
┌────────┐         ┌────────┐
│   PC1  │         │   PC2  │
│ VLAN10 │         │ VLAN20 │
└───┬────┘         └───┬────┘
    │ access           │ access
    │                  │
    └────┬────────┬────┘
         │ Switch │
         └────┬───┘
              │ trunk
         ┌────┴───┐
         │ Router │
         └────────┘
```

**Commandes de vérification :**
```
Switch# show vlan brief
Switch# show interfaces trunk
Switch# show interfaces switchport
```

---

## Ressources

- Cisco VLAN Configuration Guide : [Cisco Documentation](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021q/)
- IEEE 802.1Q Standard : [IEEE Standards](https://standards.ieee.org/standard/802_1Q-2018.html)
- VLAN Hopping Attacks : [SANS Paper](https://www.sans.org/white-papers/37242/)
