# VLANs et segmentation réseau

## Objectifs du cours

Les VLANs (Virtual Local Area Networks) sont un outil fondamental pour :
- Segmenter le réseau sans multiplier le matériel physique
- Améliorer la sécurité en isolant les zones sensibles
- Réduire les domaines de broadcast
- Faciliter la gestion du réseau

Compétences visées :
- Comprendre le fonctionnement des VLANs et leur utilité
- Maîtriser le standard 802.1Q et le tagging des trames
- Distinguer les ports access et trunk
- Identifier les vulnérabilités liées aux VLANs et les protections
- Configurer des VLANs dans GNS3

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **VLAN** | Virtual Local Area Network - Réseau local virtuel |
| **802.1Q** | Standard IEEE pour le tagging VLAN |
| **Tag** | Identifiant ajouté à une trame Ethernet pour indiquer son VLAN |
| **Port Access** | Port appartenant à un seul VLAN (pour les machines) |
| **Port Trunk** | Port transportant plusieurs VLANs (entre switches) |
| **Native VLAN** | VLAN dont les trames ne sont pas taguées sur un trunk |
| **DTP** | Dynamic Trunking Protocol - Négociation automatique de trunk |
| **VID** | VLAN Identifier - Numéro du VLAN (1 à 4094) |
| **Broadcast domain** | Zone où un broadcast est propagé |
| **Inter-VLAN routing** | Routage entre différents VLANs |

---

## Comprendre les VLANs : les bases

### Le problème : un switch = un domaine de broadcast

Sans VLANs, **toutes les machines connectées au même switch peuvent communiquer** directement entre elles :

```
                    ┌─────────────────────────────────┐
                    │           SWITCH                │
                    │                                 │
        ┌───────────┼─────┬─────┬─────┬─────┬───────┼───────────┐
        │           │     │     │     │     │       │           │
     ┌──┴──┐     ┌──┴──┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐ ┌─┴─┐  ┌──┴──┐    ┌──┴──┐
     │ RH  │     │ IT  │ │ $ │ │ $ │ │Dev│ │Dir│  │Serv │    │Invit│
     └─────┘     └─────┘ └───┘ └───┘ └───┘ └───┘  └─────┘    └─────┘
       ↑           ↑       ↑     ↑     ↑     ↑        ↑          ↑
       └───────────┴───────┴─────┴─────┴─────┴────────┴──────────┘
                   TOUS dans le même réseau L2 !

Problèmes :
- Un broadcast touche TOUT LE MONDE
- L'invité peut potentiellement atteindre les serveurs
- Pas d'isolation entre départements
```

### La solution : les VLANs

Avec les VLANs, **on crée des réseaux virtuels séparés** sur le même équipement physique :

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

### Caractéristiques clés des VLANs

| Caractéristique | Description |
|-----------------|-------------|
| **Isolation** | Les machines de VLANs différents ne se voient pas en L2 (couche 2) |
| **Broadcast** | Chaque VLAN est son propre domaine de broadcast |
| **Adressage** | Chaque VLAN a généralement son propre sous-réseau IP |
| **Routage** | Pour communiquer entre VLANs, il faut un routeur (L3) |
| **Physique** | Plusieurs VLANs peuvent coexister sur un même switch |

**Rappel L2/L3 :**
```
L2 (Couche 2 - Liaison) : Communication par adresse MAC, gérée par les switches
L3 (Couche 3 - Réseau)  : Communication par adresse IP, gérée par les routeurs

→ Les VLANs isolent au niveau L2 : pas de communication MAC directe
→ Pour traverser les VLANs, il faut remonter en L3 (routeur)
```

### VLANs et sous-réseaux : le lien

**Convention :** Un VLAN = Un sous-réseau IP

```
VLAN 10 (RH)     → 192.168.10.0/24  → Passerelle : 192.168.10.1
VLAN 20 (IT)     → 192.168.20.0/24  → Passerelle : 192.168.20.1
VLAN 30 (Serveurs) → 192.168.30.0/24  → Passerelle : 192.168.30.1
```

Cette convention n'est pas obligatoire mais **facilite grandement l'administration** :
- VLAN 10 → réseau 10.X ou 192.168.10.X
- VLAN 100 → réseau 100.X ou 192.168.100.X

**Validation avec NetProbe :**
```bash
./NetProbe info 192.168.10.0/24
```
Exemple de sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║ Adresse réseau   : 192.168.10.0                                              ║
║ Masque           : 255.255.255.0                                             ║
║ Broadcast        : 192.168.10.255                                            ║
║ Plage hôtes      : 192.168.10.1 - 192.168.10.254                             ║
║ Nb hôtes         : 254                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Le standard 802.1Q : tagging des trames

### Comment fonctionne le tagging ?

Quand une trame doit traverser un lien transportant plusieurs VLANs (trunk), le switch **ajoute un tag 802.1Q** à la trame Ethernet :

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
      ┌───────────────────── 4 octets (32 bits) ─────────────────────┐
      │                                                              │
      │  ┌──────────────────┬────────┬──────┬───────────────────┐    │
      │  │   TPID (16 bits) │PCP (3) │DEI(1)│    VID (12 bits)  │    │
      │  │     0x8100       │ 0-7    │ 0/1  │      1-4094       │    │
      │  └──────────────────┴────────┴──────┴───────────────────┘    │
      │                                                              │
      └──────────────────────────────────────────────────────────────┘
```

| Champ | Taille | Description |
|-------|--------|-------------|
| **TPID** | 16 bits | Tag Protocol Identifier - Toujours 0x8100 pour 802.1Q |
| **PCP** | 3 bits | Priority Code Point - Priorité QoS (0=basse, 7=haute) |
| **DEI** | 1 bit | Drop Eligible Indicator - Peut être supprimée si congestion |
| **VID** | 12 bits | VLAN Identifier - Numéro du VLAN (1 à 4094) |

### VLANs réservés

| VID | Usage |
|-----|-------|
| 0 | Priorité seulement (pas de VLAN) |
| 1 | VLAN par défaut (dangereux à utiliser) |
| 2-1001 | VLANs normaux |
| 1002-1005 | Réservés (Token Ring, FDDI) |
| 1006-4094 | VLANs étendus |
| 4095 | Réservé |

---

## Ports Access vs Trunk

### Port Access

Un port **access** appartient à **un seul VLAN** et est destiné aux machines finales (PC, serveurs, téléphones IP...).

```
Caractéristiques :
- 1 seul VLAN
- Pas de tag sur les trames sortantes
- Les trames entrantes sont "assignées" au VLAN du port
```

**Fonctionnement :**

```
                            SWITCH
     PC (pas de tag)    ┌──────────────────┐     Trunk (taggé)
          │             │                  │           │
          │  ──────────>│  Port Access     │──────────>│ Tag VLAN 10 ajouté
          │  Trame      │  (VLAN 10)       │   Trame   │
          │  standard   │                  │   802.1Q  │
                        └──────────────────┘
```

### Port Trunk

Un port **trunk** transporte **plusieurs VLANs** et utilise le tagging 802.1Q.

```
Caractéristiques :
- Plusieurs VLANs
- Trames taguées avec leur VID
- Utilisé entre switches, vers routeurs, vers serveurs multi-VLAN
```

**Fonctionnement :**

```
     SWITCH A                              SWITCH B
┌────────────────┐                    ┌────────────────┐
│   VLAN 10      │     Trunk 802.1Q  │   VLAN 10      │
│   VLAN 20 ─────┼────────────────── │───VLAN 20      │
│   VLAN 30      │   (Tags: 10,20,30)│   VLAN 30      │
└────────────────┘                    └────────────────┘

Toutes les trames sur ce lien sont taguées,
sauf celles du Native VLAN (voir ci-dessous).
```

### Comparaison Access vs Trunk

| Aspect | Port Access | Port Trunk |
|--------|-------------|------------|
| VLANs | 1 seul | Plusieurs |
| Tagging | Jamais | Toujours (sauf native VLAN) |
| Usage | Machines finales | Inter-switch, routeurs |
| Sécurité | Plus simple | Plus complexe |

---

## Le Native VLAN : fonctionnement et risques

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

### Le danger du Native VLAN par défaut

Laisser le VLAN 1 comme Native VLAN est **dangereux** pour plusieurs raisons :

1. **VLAN 1 est le VLAN par défaut** de tous les ports → attaque plus facile
2. **Protocoles de contrôle** circulent sur VLAN 1 (CDP, VTP, DTP...)
3. **VLAN Hopping** : attaques pour sauter entre VLANs

---

## Attaques VLAN Hopping

### Attaque 1 : Switch Spoofing

**Principe :** L'attaquant fait croire au switch qu'il est un autre switch pour établir un trunk.

```
ATTAQUANT                              SWITCH
    │                                    │
    │  "Je suis un switch,              │
    │   négocions un trunk !"            │
    │ ─────────────────────────────────> │
    │        (paquets DTP)               │
    │                                    │
    │  "OK, trunk établi !"             │
    │ <───────────────────────────────── │
    │                                    │
    │  Maintenant l'attaquant           │
    │  a accès à TOUS les VLANs !        │
```

**Protection :**
```
# Désactiver DTP sur tous les ports non-trunk
switchport mode access
switchport nonegotiate
```

### Attaque 2 : Double Tagging

**Principe :** L'attaquant envoie une trame avec **deux tags VLAN**. Le premier switch enlève le premier tag (native VLAN), le second switch lit le deuxième tag et envoie vers un VLAN non autorisé.

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
    │              │  │Payload │       │                │
    │              │  └────────┘       │                │
    │              │  (1er tag enlevé) │   La trame     │
    │              │                   │  arrive !       │
```

**Explication :**
1. L'attaquant crée une trame avec 2 tags : le Native VLAN (1) à l'extérieur, VLAN cible (20) à l'intérieur
2. Switch A voit le tag externe (VLAN 1 = Native), l'enlève car c'est le native VLAN, et forward sur le trunk
3. Switch B reçoit la trame avec un seul tag (VLAN 20) et la forward vers le VLAN 20
4. L'attaquant a réussi à atteindre un VLAN où il ne devrait pas être !

**Protection :**
```
# Ne jamais utiliser VLAN 1 comme Native VLAN
# Utiliser un VLAN inutilisé comme Native VLAN
switchport trunk native vlan 999

# Ou taguer aussi le Native VLAN (Cisco)
vlan dot1q tag native
```

---

## Bonnes pratiques de sécurité VLAN

### Checklist de sécurisation

```
□ 1. Changer le Native VLAN (ne JAMAIS utiliser VLAN 1)
□ 2. Désactiver DTP sur tous les ports
□ 3. Configurer explicitement chaque port en access ou trunk
□ 4. Limiter les VLANs autorisés sur les trunks
□ 5. Désactiver les ports non utilisés
□ 6. Placer les ports non utilisés dans un VLAN "poubelle"
□ 7. Activer le port-security si possible
□ 8. Implémenter des VACLs (VLAN ACLs) pour le filtrage
```

### Configuration sécurisée type

**Port Access sécurisé :**
```
interface FastEthernet0/1
 description PC-RH
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
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

## Configuration des VLANs dans GNS3

### Exercice pratique : créer une topologie VLAN

**Objectif :** Créer 2 VLANs et tester l'isolation

**Topologie :**

```
      VLAN 10 (RH)                    VLAN 20 (IT)
    192.168.10.0/24                 192.168.20.0/24

     ┌─────┐                           ┌─────┐
     │ PC1 │                           │ PC3 │
     │.10  │                           │.10  │
     └──┬──┘                           └──┬──┘
        │                                 │
        │ Fa0/1 (access VLAN 10)          │ Fa0/3 (access VLAN 20)
        │                                 │
     ┌──┴─────────────────────────────────┴──┐
     │              SWITCH                   │
     │                                       │
     │  VLAN 10: Fa0/1, Fa0/2               │
     │  VLAN 20: Fa0/3, Fa0/4               │
     └──┬─────────────────────────────────┬──┘
        │                                 │
        │ Fa0/2 (access VLAN 10)          │ Fa0/4 (access VLAN 20)
        │                                 │
     ┌──┴──┐                           ┌──┴──┐
     │ PC2 │                           │ PC4 │
     │.20  │                           │.20  │
     └─────┘                           └─────┘
```

### Étape 1 : Créer les VLANs sur le switch

```
Switch> enable
Switch# configure terminal

! Créer VLAN 10
Switch(config)# vlan 10
Switch(config-vlan)# name RH
Switch(config-vlan)# exit

! Créer VLAN 20
Switch(config)# vlan 20
Switch(config-vlan)# name IT
Switch(config-vlan)# exit

! Vérifier
Switch# show vlan brief
```

### Étape 2 : Assigner les ports aux VLANs

```
Switch(config)# interface range FastEthernet0/1-2
Switch(config-if-range)# switchport mode access
Switch(config-if-range)# switchport access vlan 10
Switch(config-if-range)# exit

Switch(config)# interface range FastEthernet0/3-4
Switch(config-if-range)# switchport mode access
Switch(config-if-range)# switchport access vlan 20
Switch(config-if-range)# exit
```

### Étape 3 : Configurer les PCs

```
# PC1 (VLAN 10)
ip 192.168.10.10/24 192.168.10.1

# PC2 (VLAN 10)
ip 192.168.10.20/24 192.168.10.1

# PC3 (VLAN 20)
ip 192.168.20.10/24 192.168.20.1

# PC4 (VLAN 20)
ip 192.168.20.20/24 192.168.20.1
```

### Étape 4 : Tester l'isolation

```
# Depuis PC1 (VLAN 10)
ping 192.168.10.20   # Vers PC2 → devrait fonctionner ✓
ping 192.168.20.10   # Vers PC3 → ne devrait PAS fonctionner ✗

# Depuis PC3 (VLAN 20)
ping 192.168.20.20   # Vers PC4 → devrait fonctionner ✓
ping 192.168.10.10   # Vers PC1 → ne devrait PAS fonctionner ✗
```

**Résultat attendu :**
- Les PCs du même VLAN peuvent communiquer
- Les PCs de VLANs différents ne peuvent PAS communiquer (pas de routeur)

---

## Inter-VLAN Routing

Pour que les VLANs puissent communiquer entre eux, il faut un **routeur** ou un **switch L3**.

### Méthode 1 : Router-on-a-Stick

Un seul lien trunk entre le switch et le routeur, avec des sous-interfaces.

```
                    ROUTEUR
             Fa0/0.10 : 192.168.10.1
             Fa0/0.20 : 192.168.20.1
                  │ trunk
                  │
     ┌────────────┴────────────┐
     │         SWITCH          │
     │                         │
     │  VLAN 10       VLAN 20  │
     └─────┬──────────────┬────┘
           │              │
        ┌──┴──┐        ┌──┴──┐
        │ PC1 │        │ PC3 │
        └─────┘        └─────┘
```

**Configuration du routeur :**
```
Router> enable
Router# configure terminal

! Activer l'interface principale
Router(config)# interface FastEthernet0/0
Router(config-if)# no shutdown

! Sous-interface VLAN 10
Router(config)# interface FastEthernet0/0.10
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

! Sous-interface VLAN 20
Router(config)# interface FastEthernet0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0
```

**Configuration du trunk sur le switch :**
```
Switch(config)# interface FastEthernet0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20
```

---

## Cas d'usage en cybersécurité

### Segmentation pour la défense

| Zone | VLAN | Réseau | Description |
|------|------|--------|-------------|
| Users | 10 | 10.10.10.0/24 | Postes utilisateurs standard |
| Admin | 20 | 10.10.20.0/24 | Postes administrateurs |
| Servers | 30 | 10.10.30.0/24 | Serveurs internes |
| DMZ | 40 | 10.10.40.0/24 | Serveurs exposés |
| Management | 50 | 10.10.50.0/24 | Interfaces de gestion |
| IoT | 100 | 10.10.100.0/24 | Caméras, capteurs... |
| Guest | 200 | 10.10.200.0/24 | Réseau invités |

### Reconnaissance lors d'un pentest

**Indices pour identifier les VLANs :**

| Technique | Information obtenue |
|-----------|---------------------|
| Analyse ARP | Plages IP utilisées |
| Capture 802.1Q | VIDs si trunk mal configuré |
| CDP sniffing | Info VLAN sur équipements Cisco |
| DHCP | Sous-réseaux assignés |
| Traceroute | Passerelles inter-VLAN |

**Commandes utiles :**
```bash
# Capturer le trafic 802.1Q (Linux)
tcpdump -i eth0 -e | grep 802.1Q

# Wireshark : filtre VLAN
vlan.id == 10

# Tshark : afficher les tags VLAN
tshark -i eth0 -Y "vlan" -T fields -e vlan.id
```

---

## Résumé

### Les points clés

| Concept | À retenir |
|---------|-----------|
| **VLAN** | Segmentation logique du réseau L2 |
| **802.1Q** | Standard de tagging (4 octets, VID sur 12 bits) |
| **Access** | 1 VLAN, pas de tag, pour les machines |
| **Trunk** | Plusieurs VLANs, avec tags, entre switches |
| **Native VLAN** | VLAN non taggé sur trunk (dangereux si = 1) |
| **VLAN Hopping** | Attaques pour sauter entre VLANs |

### Règles de sécurité

```
✓ Ne JAMAIS utiliser VLAN 1
✓ Désactiver DTP partout
✓ Limiter les VLANs sur les trunks
✓ Changer le Native VLAN
✓ Désactiver les ports inutilisés
✓ Mettre les ports inutilisés dans un VLAN mort
```

---

## Ressources

| Ressource | Lien |
|-----------|------|
| IEEE 802.1Q | https://standards.ieee.org/standard/802_1Q-2018.html |
| Cisco VLAN Guide | https://www.cisco.com/c/en/us/support/docs/lan-switching/vlan/10023-3.html |
| VLAN Hopping (SANS) | https://www.sans.org/white-papers/37242/ |
| GNS3 VLAN Lab | https://docs.gns3.com/docs/using-gns3/beginners/the-gns3-gui |

---

## Exercice récapitulatif

### Objectif

Créer cette architecture dans GNS3 :

```
                          INTERNET
                              │
                         ┌────┴────┐
                         │  FW/R   │ (Routeur avec ACLs)
                         └────┬────┘
                              │ Trunk (VLAN 10,20,30,40)
                              │
     ┌────────────────────────┴───────────────────────────┐
     │                    SWITCH CORE                     │
     └────┬─────────────┬─────────────┬─────────────┬────┘
          │             │             │             │
       VLAN 10       VLAN 20       VLAN 30       VLAN 40
       Users         Servers        DMZ          Admin
     ┌───┴───┐     ┌───┴───┐     ┌───┴───┐     ┌───┴───┐
     │ PC1   │     │ SRV1  │     │ WEB   │     │ ADM1  │
     │ PC2   │     │ SRV2  │     │       │     │       │
     └───────┘     └───────┘     └───────┘     └───────┘
  10.0.10.0/24   10.0.20.0/24   10.0.30.0/24  10.0.40.0/24
```

### Étapes

1. Créer la topologie dans GNS3
2. Configurer les 4 VLANs sur le switch
3. Assigner les ports access
4. Configurer le trunk vers le routeur
5. Configurer le router-on-a-stick
6. Configurer les IP des machines
7. Tester la connectivité intra-VLAN
8. Tester le routage inter-VLAN
9. Appliquer les bonnes pratiques de sécurité
10. Exporter le projet !
