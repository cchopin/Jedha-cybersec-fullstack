# VLANs et segmentation réseau

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
| **Tag** | Identifiant ajouté à une trame Ethernet pour indiquer son VLAN |
| **Port Access** | Port appartenant à un seul VLAN (pour les machines finales) |
| **Port Trunk** | Port transportant plusieurs VLANs (entre switches) |
| **Native VLAN** | VLAN dont les trames ne sont pas taguées sur un trunk |
| **VID** | VLAN Identifier - Numéro du VLAN (1 à 4094) |
| **Broadcast domain** | Zone où un broadcast est propagé |

---

## Comprendre les VLANs

### Le problème sans VLANs

Sans VLANs, toutes les machines connectées au même switch appartiennent au même réseau. Cela pose plusieurs problèmes :

```
                    ┌─────────────────────────────────┐
                    │           SWITCH                │
        ┌───────────┼─────┬─────┬─────┬─────┬───────┼───────────┐
        │           │     │     │     │     │       │           │
     ┌──┴──┐     ┌──┴──┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐  ┌──┴──┐    ┌──┴──┐
     │ RH  │     │ IT  │ │ $ │ │ $ │ │Dev│ │Dir│  │Serv │    │Invit│
     └─────┘     └─────┘ └───┘ └───┘ └───┘ └───┘  └─────┘    └─────┘

Problèmes :
- Un broadcast atteint TOUTES les machines
- L'invité peut potentiellement voir les serveurs
- Aucune isolation entre les départements
- Trafic inutile sur tout le réseau
```

### La solution : les VLANs

Les VLANs permettent de créer des **réseaux virtuels séparés** sur le même équipement physique :

```
                    ┌─────────────────────────────────┐
                    │           SWITCH                │
                    │  ┌──────┐ ┌──────┐ ┌──────────┐ │
                    │  │VLAN10│ │VLAN20│ │  VLAN30  │ │
        ┌───────────┼──┼──────┼─┼──────┼─┼──────────┼─┼───────────┐
        │           │  │      │ │      │ │          │ │           │
     ┌──┴──┐     ┌──┴──┴─┐   ┌┴─┴┐   ┌─┴─┴┐      ┌──┴─┴──┐    ┌──┴──┐
     │ RH  │     │  IT   │   │Dev│   │Serv│      │  Dir  │    │Invit│
     └─────┘     └───────┘   └───┘   └────┘      └───────┘    └─────┘
       ↑             ↑         ↑        ↑            ↑           ↑
       └─VLAN 10─────┘         └─VLAN 20┘            └─VLAN 30───┘

Résultat :
- Chaque VLAN = réseau isolé
- Un broadcast dans VLAN 10 reste dans VLAN 10
- L'invité (VLAN 30) ne peut pas atteindre les serveurs (VLAN 20)
```

### Caractéristiques clés

| Caractéristique | Description |
|-----------------|-------------|
| **Isolation L2** | Les machines de VLANs différents ne communiquent pas directement |
| **Broadcast** | Chaque VLAN forme son propre domaine de broadcast |
| **Adressage** | Chaque VLAN a généralement son propre sous-réseau IP |
| **Routage** | Pour communiquer entre VLANs, un routeur (L3) est nécessaire |
| **Flexibilité** | Plusieurs VLANs coexistent sur un même switch physique |

**Rappel L2/L3 :**
```
L2 (Couche 2 - Liaison) : Communication par adresse MAC, gérée par les switches
L3 (Couche 3 - Réseau)  : Communication par adresse IP, gérée par les routeurs

→ Les VLANs isolent au niveau L2 : pas de communication MAC directe
→ Pour traverser les VLANs, il faut remonter en L3 (routeur)
```

### Convention : VLAN = Sous-réseau

En pratique, chaque VLAN correspond à un sous-réseau IP distinct :

```
VLAN 10 (RH)       → 192.168.10.0/24  → Passerelle : 192.168.10.1
VLAN 20 (IT)       → 192.168.20.0/24  → Passerelle : 192.168.20.1
VLAN 30 (Invités)  → 192.168.30.0/24  → Passerelle : 192.168.30.1
```

Cette convention facilite l'administration :
- VLAN 10 → réseau 10.X ou 192.168.10.X
- VLAN 100 → réseau 100.X ou 192.168.100.X

---

## Le standard 802.1Q : tagging des trames

### Principe du tagging

Lorsqu'une trame doit traverser un lien transportant plusieurs VLANs (trunk), le switch **ajoute un tag 802.1Q** pour identifier le VLAN d'origine :

```
AVANT (trame Ethernet standard) :
┌──────────────┬──────────────┬──────────┬─────────────────┬─────┐
│ Dest MAC (6) │ Src MAC (6)  │ Type (2) │   Payload       │ FCS │
└──────────────┴──────────────┴──────────┴─────────────────┴─────┘

APRÈS (trame 802.1Q) :
┌──────────────┬──────────────┬─────────────────┬──────────┬─────────────────┬─────┐
│ Dest MAC (6) │ Src MAC (6)  │  Tag 802.1Q (4) │ Type (2) │   Payload       │ FCS │
└──────────────┴──────────────┴─────────────────┴──────────┴─────────────────┴─────┘
                               │                │
                               └──── Inséré ────┘
```

### Structure du tag 802.1Q (4 octets)

```
┌────────────────────────── 4 octets (32 bits) ──────────────────────────┐
│                                                                        │
│  ┌──────────────────┬────────┬──────┬───────────────────┐              │
│  │   TPID (16 bits) │PCP (3) │DEI(1)│    VID (12 bits)  │              │
│  │     0x8100       │ 0-7    │ 0/1  │      1-4094       │              │
│  └──────────────────┴────────┴──────┴───────────────────┘              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

| Champ | Taille | Description |
|-------|--------|-------------|
| **TPID** | 16 bits | Tag Protocol Identifier - Toujours 0x8100 pour 802.1Q |
| **PCP** | 3 bits | Priority Code Point - Priorité QoS (0=basse, 7=haute) |
| **DEI** | 1 bit | Drop Eligible Indicator - Trame supprimable en cas de congestion |
| **VID** | 12 bits | VLAN Identifier - Numéro du VLAN (1 à 4094) |

### VLANs réservés

| VID | Usage |
|-----|-------|
| 0 | Priorité seulement (pas de VLAN) |
| 1 | VLAN par défaut (à éviter en production) |
| 2-1001 | VLANs normaux |
| 1002-1005 | Réservés (Token Ring, FDDI - obsolètes) |
| 1006-4094 | VLANs étendus |
| 4095 | Réservé |

---

## Ports Access vs Trunk

### Port Access

Un port **access** appartient à **un seul VLAN** et connecte les machines finales (PC, serveurs, imprimantes...).

**Caractéristiques :**
- 1 seul VLAN assigné
- Pas de tag sur les trames sortantes
- Les trames entrantes sont automatiquement assignées au VLAN du port

```
Fonctionnement :

     PC (pas de tag)        SWITCH                    Trunk (taggé)
          │             ┌──────────────────┐              │
          │  ──────────>│  Port Access     │─────────────>│ Tag VLAN 10 ajouté
          │  Trame      │  (VLAN 10)       │   Trame      │
          │  standard   │                  │   802.1Q     │
                        └──────────────────┘
```

### Port Trunk

Un port **trunk** transporte **plusieurs VLANs** en utilisant le tagging 802.1Q.

**Caractéristiques :**
- Plusieurs VLANs autorisés
- Trames taguées avec leur VID
- Utilisé entre switches, vers routeurs, vers serveurs multi-VLAN

```
Fonctionnement :

     SWITCH A                              SWITCH B
┌────────────────┐                    ┌────────────────┐
│   VLAN 10      │     Trunk 802.1Q   │   VLAN 10      │
│   VLAN 20 ─────┼────────────────────┼───VLAN 20      │
│   VLAN 30      │   (Tags: 10,20,30) │   VLAN 30      │
└────────────────┘                    └────────────────┘

Toutes les trames sur ce lien sont taguées,
sauf celles du Native VLAN.
```

### Comparaison

| Aspect | Port Access | Port Trunk |
|--------|-------------|------------|
| VLANs | 1 seul | Plusieurs |
| Tagging | Jamais | Toujours (sauf native VLAN) |
| Usage | Machines finales | Inter-switch, routeurs |
| Configuration | Plus simple | Plus complexe |

---

## Native VLAN et risques de sécurité

### Qu'est-ce que le Native VLAN ?

Le **Native VLAN** est le VLAN dont les trames **ne sont pas taguées** sur un trunk.

```
Par défaut : Native VLAN = VLAN 1

Sur un trunk :
- Trame VLAN 10 → taguée avec VID 10
- Trame VLAN 20 → taguée avec VID 20
- Trame VLAN 1 (native) → PAS de tag !
```

**Pourquoi ?** Pour la compatibilité avec les équipements anciens qui ne comprennent pas 802.1Q.

### Risques de sécurité

Laisser le VLAN 1 comme Native VLAN est **dangereux** :

1. **VLAN 1 est le VLAN par défaut** de tous les ports → cible facile
2. **Protocoles de contrôle** circulent sur VLAN 1 (CDP, VTP, DTP...)
3. **Attaques VLAN Hopping** possibles

### Attaque 1 : Switch Spoofing

L'attaquant fait croire au switch qu'il est un autre switch pour établir un trunk :

```
ATTAQUANT                              SWITCH
    │                                    │
    │  "Je suis un switch,               │
    │   négocions un trunk !"            │
    │ ─────────────────────────────────> │
    │        (paquets DTP)               │
    │                                    │
    │  "OK, trunk établi !"              │
    │ <───────────────────────────────── │
    │                                    │
    │  L'attaquant a maintenant          │
    │  accès à TOUS les VLANs !          │
```

### Attaque 2 : Double Tagging

L'attaquant envoie une trame avec **deux tags VLAN** :

```
ATTAQUANT        SWITCH A           SWITCH B         VICTIME
(VLAN 10)                                            (VLAN 20)

    │              │                   │                │
    │  ┌────────┐  │                   │                │
    │  │Tag: 1  │  │                   │                │
    │  │Tag: 20 │──┼──────────────────>│                │
    │  │Payload │  │     Trunk         │                │
    │  └────────┘  │   Native=1        │                │
    │              │                   │                │
    │              │  ┌────────┐       │                │
    │              │  │Tag: 20 │───────┼───────────────>│
    │              │  │Payload │       │   La trame     │
    │              │  └────────┘       │   arrive !     │
    │              │  (1er tag enlevé) │                │
```

**Explication :**
1. L'attaquant crée une trame avec 2 tags : Native VLAN (1) + VLAN cible (20)
2. Switch A enlève le premier tag (c'est le native VLAN) et forward
3. Switch B voit le tag 20 et envoie vers VLAN 20
4. L'attaquant a atteint un VLAN non autorisé !

---

## Mesures de protection

### Checklist de sécurisation

```
□ 1. Changer le Native VLAN (ne JAMAIS utiliser VLAN 1)
□ 2. Désactiver DTP sur tous les ports
□ 3. Configurer explicitement chaque port en access ou trunk
□ 4. Limiter les VLANs autorisés sur les trunks
□ 5. Désactiver les ports non utilisés
□ 6. Placer les ports inutilisés dans un VLAN "poubelle"
□ 7. Activer le port-security si possible
□ 8. Implémenter des VACLs (VLAN ACLs) pour le filtrage
```

### Configuration sécurisée (Cisco)

**Port Access sécurisé :**
```
interface FastEthernet0/1
 description PC-Utilisateur
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
```

**Port Trunk sécurisé :**
```
interface GigabitEthernet0/1
 description TRUNK-VERS-SWITCH-B
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30
 switchport nonegotiate
```

**Port non utilisé :**
```
interface FastEthernet0/24
 description UNUSED
 switchport mode access
 switchport access vlan 666
 shutdown
```

---

## Résumé

| Concept | Point clé |
|---------|-----------|
| **VLAN** | Segmentation logique du réseau L2 |
| **802.1Q** | Standard de tagging (4 octets, VID sur 12 bits) |
| **Access** | 1 VLAN, pas de tag, pour les machines |
| **Trunk** | Plusieurs VLANs, avec tags, entre switches |
| **Native VLAN** | VLAN non taggé sur trunk (dangereux si = 1) |
| **VLAN Hopping** | Attaques pour accéder à des VLANs non autorisés |

### Règles de sécurité essentielles

```
✓ Ne JAMAIS utiliser VLAN 1 en production
✓ Désactiver DTP partout
✓ Limiter les VLANs sur les trunks
✓ Changer le Native VLAN
✓ Désactiver/isoler les ports inutilisés
```

---

## Ressources

| Ressource | Lien |
|-----------|------|
| Cisco VLAN Configuration Guide | https://www.cisco.com/c/en/us/support/docs/lan-switching/8021q/ |
| IEEE 802.1Q Standard | https://standards.ieee.org/standard/802_1Q-2018.html |
| VLAN Hopping Attacks (SANS) | https://www.sans.org/white-papers/37242/ |
