# Link Aggregation et Load Balancing

## Objectifs du cours

Ce cours presente les techniques de haute disponibilite essentielles pour les reseaux modernes : l'agregation de liens (Link Aggregation) et la repartition de charge (Load Balancing). Ces competences sont critiques pour les ingenieurs reseau, administrateurs systeme et architectes de data centers qui doivent garantir des reseaux resilients, redondants et performants.

Competences visees :
- Comprendre les principes et le fonctionnement de LACP et EtherChannel
- Maitriser les differentes strategies de load balancing et leurs cas d'usage
- Appliquer l'agregation de liens dans les topologies redondantes et les data centers
- Identifier les bonnes pratiques et considerations de conception
- Reconnaitre les vulnerabilites et les mesures de securisation

---

## Glossaire

### Concepts fondamentaux

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **LAG** | Link Aggregation Group | Groupe de liens physiques agreges en un lien logique |
| **LACP** | Link Aggregation Control Protocol | Protocole standard IEEE 802.3ad pour l'agregation dynamique |
| **PAgP** | Port Aggregation Protocol | Protocole Cisco proprietaire pour l'agregation |
| **EtherChannel** | - | Implementation Cisco de l'agregation de liens |
| **Port-Channel** | - | Interface logique representant un groupe de liens agreges |
| **Bonding** | - | Terme Linux pour l'agregation de liens |
| **Teaming** | - | Terme Windows/VMware pour l'agregation de liens |

### Modes LACP

| Mode | Description |
|------|-------------|
| **Active** | Envoie des LACPDUs et initie la negociation |
| **Passive** | Repond aux LACPDUs mais n'initie pas |
| **On** | Mode statique sans negociation (risque) |

### Modes EtherChannel

| Mode | Protocole | Description |
|------|-----------|-------------|
| **Active** | LACP | Initie la negociation LACP |
| **Passive** | LACP | Repond a la negociation LACP |
| **Desirable** | PAgP | Initie la negociation PAgP |
| **Auto** | PAgP | Repond a la negociation PAgP |
| **On** | Aucun | Configuration statique |

### Load Balancing

| Terme | Description |
|-------|-------------|
| **Per-Packet** | Distribution paquet par paquet |
| **Per-Flow** | Distribution par flux (session) |
| **Per-Destination** | Distribution par destination |
| **Hash** | Algorithme de repartition base sur un calcul |
| **Round-Robin** | Distribution alternee sur chaque lien |

### Haute disponibilite

| Terme | Description |
|-------|-------------|
| **Failover** | Basculement automatique vers un lien de secours |
| **Redundancy** | Duplication des ressources pour la tolerance aux pannes |
| **MLAG/MC-LAG** | Multi-Chassis LAG - Agregation sur plusieurs switches |
| **vPC** | Virtual Port-Channel - Implementation Cisco Nexus de MC-LAG |
| **VSS** | Virtual Switching System - Virtualisation de deux switches Cisco |

### Termes de securite

| Terme | Description |
|-------|-------------|
| **LAG Manipulation** | Attaque visant a perturber l'agregation |
| **LACP Flooding** | Saturation de messages LACP |
| **Link Flapping** | Oscillation rapide de l'etat d'un lien |

---

## Comprendre le besoin de haute disponibilite

La haute disponibilite n'est pas qu'un buzzword, c'est le fondement des infrastructures modernes. Les reseaux sont la colonne vertebrale de toute communication numerique, mais comme tout systeme, ils peuvent tomber en panne.

### Problemes resolus par l'agregation de liens

| Probleme | Solution |
|----------|----------|
| Point de defaillance unique | Redondance des liens physiques |
| Goulots d'etranglement de bande passante | Agregation de la capacite |
| Manque de redondance | Failover automatique |
| Distribution inefficace du trafic | Load balancing |

---

## Fondamentaux de l'agregation de liens

![Link Aggregation](assets/Link_Aggregation.jpg)

L'agregation de liens est la methode de combinaison de plusieurs interfaces reseau physiques en une seule interface logique. Ce groupe logique agit comme un lien unique offrant un debit plus eleve et une tolerance aux pannes.

### Exemple concret

```
Sans agregation :
Switch A ──── 1 Gbps ──── Switch B
             (lien unique)

Avec agregation :
Switch A ═══╤═══ 1 Gbps ═══╤═══ Switch B
            │   1 Gbps     │
            │   1 Gbps     │
            └── 1 Gbps ────┘
            (4 Gbps logiques, redondance)
```

### Types d'agregation

| Type | Description | Risque |
|------|-------------|--------|
| **Statique (On)** | Configuration manuelle identique des deux cotes | Boucles si mal configure |
| **Dynamique (LACP)** | Negociation automatique avec LACPDUs | Faible |
| **Dynamique (PAgP)** | Negociation Cisco proprietaire | Faible, mais limite a Cisco |

---

## LACP (IEEE 802.3ad)

LACP (Link Aggregation Control Protocol) est le protocole standard defini dans IEEE 802.3ad pour agreger dynamiquement plusieurs ports physiques en un canal logique.

### Fonctionnement de LACP

1. Deux appareils supportant LACP se detectent mutuellement
2. Ils echangent des LACP Data Units (LACPDUs)
3. Ils negocient quelles interfaces inclure dans le groupe
4. L'agregation est formee selon la compatibilite (vitesse, duplex, config)
5. LACP surveille continuellement la sante de chaque lien

### Avantages de LACP

| Avantage | Description |
|----------|-------------|
| **Detection automatique** | Pas besoin de configuration manuelle |
| **Interoperabilite** | Standard IEEE, multi-vendeur |
| **Surveillance continue** | Detection et exclusion des liens defaillants |
| **Hot standby** | Support de liens de secours (jusqu'a 8 actifs + 8 standby) |

### Parametres LACP

| Parametre | Description |
|-----------|-------------|
| **System Priority** | Priorite du systeme (plus bas = prefere) |
| **Port Priority** | Priorite du port (plus bas = prefere) |
| **LACP Rate** | Fast (1s) ou Slow (30s) pour les LACPDUs |
| **LACP Key** | Identifiant du groupe d'agregation |

---

## EtherChannel Cisco

EtherChannel est l'implementation Cisco de l'agregation de liens. Il peut fonctionner en trois modes principaux.

### Modes de negociation

| Cote A | Cote B | Resultat |
|--------|--------|----------|
| Active | Active | EtherChannel LACP |
| Active | Passive | EtherChannel LACP |
| Passive | Passive | Pas d'EtherChannel |
| Desirable | Desirable | EtherChannel PAgP |
| Desirable | Auto | EtherChannel PAgP |
| Auto | Auto | Pas d'EtherChannel |
| On | On | EtherChannel statique |

### Regles essentielles

- Tous les liens doivent avoir la **meme vitesse et duplex**
- Jusqu'a **8 liens actifs** par EtherChannel
- Les configurations d'interface (trunking, STP) doivent **correspondre**
- Meme **type de media** (tous cuivre ou tous fibre)

### Configuration EtherChannel LACP (sans VLANs)

```cisco
! Configuration des interfaces physiques
interface range FastEthernet0/1 - 2
 no shutdown
 channel-group 1 mode active
 exit

! Configuration de l'interface Port-Channel logique
interface Port-channel1
 no shutdown
```

**Explication :**
- `channel-group 1 mode active` : Active LACP et assigne les interfaces au Port-Channel 1
- Au moins un cote doit etre en **active**, l'autre peut etre **active** ou **passive**

### Configuration EtherChannel avec Trunk

```cisco
! SW1 et SW2 - Configuration identique
configure terminal
hostname SW1

! Interface Port-Channel
interface Port-channel 1
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 exit

! Interfaces physiques
interface range ethernet 0/0-3
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 1 mode active
 exit

copy running-config startup-config
```

### Commandes de verification

```cisco
! Voir l'etat de l'EtherChannel
show etherchannel summary

! Detail du Port-Channel
show etherchannel port-channel

! Voir les interfaces membres
show etherchannel detail

! Verifier LACP
show lacp neighbor
show lacp internal

! Statistiques
show interfaces port-channel 1
```

### Exemple de sortie show etherchannel summary

```
Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

Number of channel-groups in use: 1
Number of aggregators:           1

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP      Fa0/1(P)    Fa0/2(P)
```

---

## Strategies de Load Balancing

Une fois les liens agreges, il faut distribuer efficacement le trafic. C'est le role du load balancing.

### Per-Packet Load Balancing

Chaque paquet est envoye sur un lien different en alternance.

| Avantages | Inconvenients |
|-----------|---------------|
| Utilisation maximale des liens | Paquets arrivent dans le desordre |
| Algorithme simple | Performance TCP degradee |

**Usage :** Environnements UDP ou stateless uniquement.

### Per-Flow / Per-Destination Load Balancing

Le trafic est hashe selon source/destination IP, MAC ou ports, et envoye de maniere coherente sur le meme lien.

| Avantages | Inconvenients |
|-----------|---------------|
| Preserve l'ordre des paquets | Peut ne pas utiliser tous les liens |
| Bon pour TCP | Depend de la diversite du trafic |

**Usage :** Cas general, recommande pour la plupart des environnements.

### Algorithmes de hachage

| Methode | Hache sur | Utilisation |
|---------|-----------|-------------|
| **src-mac** | MAC source | Trafic depuis plusieurs sources |
| **dst-mac** | MAC destination | Trafic vers plusieurs destinations |
| **src-dst-mac** | MAC source + destination | Cas general L2 |
| **src-ip** | IP source | Trafic depuis plusieurs sources |
| **dst-ip** | IP destination | Trafic vers plusieurs destinations |
| **src-dst-ip** | IP source + destination | Cas general L3 |
| **src-dst-ip-port** | IP + ports L4 | Meilleure distribution |

### Configuration du load balancing Cisco

```cisco
! Voir la methode actuelle
show etherchannel load-balance

! Configurer la methode
port-channel load-balance src-dst-ip
```

### Adaptive Load Balancing

Certains systemes avances utilisent des retours pour adapter dynamiquement la repartition. Si un lien est congestionne, ils deplacent les flux vers des liens moins utilises.

---

## Cas d'usage dans les topologies redondantes

### Data Center - Couche Access

```
        Serveur
       /       \
   NIC1         NIC2
     \           /
      \         /
    ┌──────────────┐
    │   ToR Switch │
    └──────────────┘
         LACP
```

Les serveurs sont connectes aux switches ToR (Top of Rack) avec plusieurs liens agreges via LACP. Cela fournit :
- **Redondance** : Si un lien tombe, les autres continuent
- **Bande passante** : Plus de capacite pour le trafic

### Multi-Chassis LAG (MC-LAG / MLAG)

```
        Serveur
       /       \
   NIC1         NIC2
     │           │
     │    LAG    │
     ▼           ▼
┌─────────┐ ┌─────────┐
│ Switch1 │─│ Switch2 │
└─────────┘ └─────────┘
   (MLAG peer-link)
```

Le serveur se connecte a **deux switches differents** avec des liens agreges. Si un switch tombe, l'autre maintient la connectivite.

**Implementations :**
- **Cisco vPC** (Nexus)
- **Cisco VSS** (Catalyst)
- **Arista MLAG**
- **Juniper MC-LAG**

### Core Network Redundancy

```
┌──────────┐         ┌──────────┐
│  Core 1  │═════════│  Core 2  │
└────┬─────┘  LAG    └────┬─────┘
     │                    │
     │    LAG             │    LAG
     │                    │
┌────┴─────┐         ┌────┴─────┐
│ Distrib1 │         │ Distrib2 │
└──────────┘         └──────────┘
```

Les liens multiples entre switches core sont agreges pour :
- Eviter que STP bloque certains liens
- Utiliser toute la bande passante disponible
- Proteger contre les defaillances de liens individuels

### Environnements virtualises

Dans VMware ESXi, Microsoft Hyper-V ou KVM, les NICs des hotes sont bondes :

```
      VMware ESXi Host
    ┌─────────────────────┐
    │   VM1  VM2  VM3     │
    │        │            │
    │   vSwitch (LACP)    │
    │   /    │    \       │
    │ vmnic0 vmnic1 vmnic2│
    └───┬─────┬─────┬─────┘
        │     │     │
        └─────┼─────┘
              │ LAG
        ┌─────┴─────┐
        │  Switch   │
        └───────────┘
```

---

## Lab pratique : EtherChannel LACP dans GNS3

### Objectif

Configurer un EtherChannel LACP entre deux switches Cisco, connecter deux VPCs, tester la connectivite et observer la redondance des liens.

### Topologie

```
    VPC1                          VPC2
     │                              │
     │ e1/0                    e1/0 │
┌────┴────┐                   ┌────┴────┐
│   SW1   │═══════════════════│   SW2   │
│         │  e0/0-e0/3 (LAG)  │         │
└─────────┘                   └─────────┘
```

### Configuration SW1

```cisco
configure terminal
hostname SW1

! Interface Port-Channel
interface Port-channel 1
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 exit

! Interfaces physiques pour le LAG
interface range ethernet 0/0-3
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 1 mode active
 exit

! Interface vers VPC1
interface ethernet 1/0
 switchport mode access
 switchport access vlan 1
 no shutdown
 exit

copy running-config startup-config
```

### Configuration SW2

```cisco
configure terminal
hostname SW2

! Interface Port-Channel
interface Port-channel 1
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 exit

! Interfaces physiques pour le LAG
interface range ethernet 0/0-3
 no shutdown
 switchport trunk encapsulation dot1q
 switchport mode trunk
 channel-group 1 mode active
 exit

! Interface vers VPC2
interface ethernet 1/0
 switchport mode access
 switchport access vlan 1
 no shutdown
 exit

copy running-config startup-config
```

### Configuration des VPCs

**VPC1 :**
```
ip 192.168.1.1/24
save
```

**VPC2 :**
```
ip 192.168.1.2/24
save
```

### Tests

1. **Test de connectivite initial :**
```
VPC1> ping 192.168.1.2
```

2. **Test de redondance - Couper un lien :**
```cisco
! Sur SW1 ou SW2
interface Ethernet0/0
 shutdown
```

3. **Verifier que la connectivite persiste :**
```
VPC1> ping 192.168.1.2
```

### Resultat attendu

![Resultat du lab LACP](assets/LACP_DEMO_Result.png)

- L'EtherChannel est forme avec LACP
- Les VPCs peuvent communiquer via le Port-Channel logique
- La deconnexion d'un lien physique n'affecte pas la connectivite globale

---

## Bonnes pratiques et defis

### Bonnes pratiques

| Pratique | Raison |
|----------|--------|
| Ne pas melanger les vitesses | 1 Gbps + 10 Gbps = problemes |
| Coherence des configurations | Les deux cotes doivent correspondre |
| Monitorer le trafic | Verifier que le load balancing fonctionne |
| Diversite physique | Cables dans des chemins differents |
| Comprendre le trafic | Adapter l'algorithme de hachage |
| Tester le failover | Simuler des pannes regulierement |

### Points d'attention

| Probleme | Solution |
|----------|----------|
| STP bloque un lien du LAG | Configurer PortFast ou Rapid PVST+ |
| Trafic inegalement reparti | Changer l'algorithme de hachage |
| Failover lent | Utiliser LACP fast rate |
| Boucles reseau | Verifier la coherence des configurations |

### Differences entre vendeurs

| Vendeur | Particularites |
|---------|----------------|
| **Cisco** | EtherChannel, load balance src-dst-ip par defaut |
| **Juniper** | Interface `ae0` pour aggregated Ethernet |
| **Arista** | Support natif MLAG, ideal pour leaf-spine |
| **HP/Aruba** | Utilise la terminologie "Trunk" en CLI |
| **Linux** | Driver bonding avec modes multiples |

### Modes de bonding Linux

| Mode | Nom | Description |
|------|-----|-------------|
| 0 | balance-rr | Round-robin |
| 1 | active-backup | Un seul actif, failover |
| 2 | balance-xor | Hash XOR |
| 3 | broadcast | Envoie sur tous les liens |
| 4 | 802.3ad | LACP dynamique |
| 5 | balance-tlb | Transmit Load Balancing adaptatif |
| 6 | balance-alb | Adaptive Load Balancing |

---

## Securite et implications cyber

### Vulnerabilites liees a l'agregation de liens

| Attaque | Description | Impact |
|---------|-------------|--------|
| **LACP Manipulation** | Envoi de LACPDUs malveillants | Disruption de l'agregation |
| **LAG Hijacking** | Tentative de rejoindre un LAG existant | Interception de trafic |
| **Link Flapping** | Oscillation rapide d'un lien | Instabilite, CPU spike |
| **LACP Flooding** | Saturation de messages LACP | DoS |

### Scenario d'attaque : LACP Manipulation

```
1. RECONNAISSANCE
   - Attaquant capture le trafic LACP (multicast 01:80:C2:00:00:02)
   - Identification des parametres (System ID, Key, Priority)

2. INJECTION
   - Envoi de LACPDUs avec des parametres manipules
   - Tentative de perturber l'agregation existante

3. IMPACT
   - Perte de liens du LAG
   - Reduction de bande passante
   - Potential MitM si l'attaquant devient membre du LAG
```

### Contre-mesures

#### 1. Port Security

```cisco
interface range ethernet 0/0-3
 switchport port-security
 switchport port-security maximum 1
 switchport port-security violation shutdown
```

#### 2. LACP Rate et Timeout

```cisco
interface range ethernet 0/0-3
 lacp rate fast
 lacp port-priority 32768
```

#### 3. Filtrage des LACPDUs

Sur les ports access ou non-LAG :
```cisco
interface ethernet 1/0
 no lacp port-channel
 spanning-tree bpduguard enable
```

#### 4. LACP System Priority

```cisco
lacp system-priority 4096  ! Plus bas = prefere
```

#### 5. Monitoring

```cisco
! Alertes sur les changements d'etat
logging trap notifications
snmp-server enable traps etherchannel
```

### Checklist securite LAG

```
[ ] Port security sur les interfaces LAG
[ ] LACP rate fast pour detection rapide
[ ] System priority configure explicitement
[ ] Monitoring des evenements EtherChannel
[ ] BPDUGuard sur les ports non-LAG
[ ] Documentation des LAGs autorises
[ ] Tests de failover reguliers
[ ] Revue des logs pour link flapping
[ ] Separation physique des cables (diversite)
[ ] Configuration coherente et verifiee
```

### Mapping MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Network Denial of Service | T1498 | Perturbation via LACP manipulation |
| Adversary-in-the-Middle | T1557 | Interception si LAG compromis |
| Network Sniffing | T1040 | Capture sur un membre du LAG |

---

## Depannage

### Problemes courants

| Probleme | Cause probable | Solution |
|----------|----------------|----------|
| LAG ne se forme pas | Modes incompatibles | Verifier active/passive |
| Liens en "s" (suspended) | Vitesse/duplex differents | Harmoniser les configs |
| Un seul lien actif | Configuration incorrecte | Verifier channel-group |
| Trafic inegal | Hash inadapte | Changer load-balance method |
| Flapping | Probleme physique | Verifier cables/SFPs |

### Commandes de diagnostic

```cisco
! Etat general
show etherchannel summary
show etherchannel detail

! Verifier LACP
show lacp neighbor
show lacp sys-id
show lacp counters

! Interface Port-Channel
show interfaces port-channel 1

! Voir le load balancing
show etherchannel load-balance

! Debug (attention en production)
debug etherchannel events
debug lacp events
```

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [IEEE 802.3ad](https://standards.ieee.org/standard/802_3ad-2000.html) | Standard LACP |
| [Cisco - EtherChannel Configuration](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/15-0_2_se/configuration/guide/scg3750/swethchl.html) | Guide officiel Cisco |
| [Juniper - Link Aggregation](https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet/topics/concept/interfaces-link-aggregation-overview.html) | Documentation Juniper |
| [Linux Bonding](https://www.kernel.org/doc/Documentation/networking/bonding.txt) | Documentation kernel Linux |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Fondamentaux reseau | https://tryhackme.com/room/introtonetworking |
| **Network Services** | Services et protocoles reseau | https://tryhackme.com/room/networkservices |
| **Network Services 2** | Services reseau avances | https://tryhackme.com/room/networkservices2 |
| **Wireshark: The Basics** | Analyse de paquets | https://tryhackme.com/room/wiresharkthebasics |

> **Note** : L'agregation de liens est principalement pratiquee sur des environnements de lab comme GNS3, EVE-NG ou Packet Tracer. Le lab decrit dans ce cours peut etre realise avec des images Cisco IOU L2 dans GNS3. Pour les tests de securite LAG, un environnement isole est recommande.
