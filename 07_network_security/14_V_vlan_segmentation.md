# VLANs et segmentation - version simplifiée

## L'idée en une phrase

Un VLAN permet de créer plusieurs réseaux virtuels sur un seul switch physique, comme si plusieurs switches séparés existaient.

---

## Le problème sans VLANs

Un open space avec 3 départements :
- RH (ressources humaines)
- IT (informatique)
- Finance

Sans VLAN, tout le monde est sur le même réseau :

```
       ┌────────────────────────────────┐
       │          SWITCH                │
       │                                │
       │  RH     IT      Finance        │
       │  ○──────○───────○              │
       │  Tout le monde se voit !       │
       └────────────────────────────────┘
```

**Problèmes** :
- Pas de séparation entre départements
- Les données RH visibles par tous
- Un virus se propage à tout le monde
- Les broadcasts surchargent le réseau

---

## La solution : les VLANs

Avec les VLANs, des réseaux virtuels séparés sont créés :

```
       ┌────────────────────────────────┐
       │          SWITCH                │
       │                                │
       │  ┌─────┐ ┌─────┐ ┌─────────┐  │
       │  │VLAN │ │VLAN │ │  VLAN   │  │
       │  │ 10  │ │ 20  │ │   30    │  │
       │  │ RH  │ │ IT  │ │ Finance │  │
       │  └─────┘ └─────┘ └─────────┘  │
       │                                │
       │  Isolés les uns des autres !   │
       └────────────────────────────────┘
```

Même switch physique, mais 3 réseaux logiques séparés.

---

## Comment cela fonctionne-t-il ?

### Port Access

Un port "access" appartient à un seul VLAN.

```
PC du RH ─────┐
              │ Port 1 = VLAN 10
              │
         [SWITCH]
              │
              │ Port 5 = VLAN 20
PC de l'IT ───┘
```

Les deux PCs ne peuvent pas communiquer (sauf si explicitement permis via un routeur).

### Port Trunk

Un port "trunk" transporte plusieurs VLANs (entre switches ou vers un routeur).

```
Switch A                          Switch B
┌────────┐                        ┌────────┐
│ VLAN10 │         TRUNK          │ VLAN10 │
│ VLAN20 │ ═══════════════════════│ VLAN20 │
│ VLAN30 │   (tous les VLANs)     │ VLAN30 │
└────────┘                        └────────┘
```

Sur le trunk, chaque trame est "étiquetée" (taggée) avec son numéro de VLAN.

---

## Le tagging 802.1Q

Quand une trame circule sur un trunk, une étiquette lui est ajoutée :

```
Trame normale :
[MAC Dest][MAC Source][Données]

Trame taguée (sur trunk) :
[MAC Dest][MAC Source][VLAN 10][Données]
                         ↑
                    Étiquette VLAN
```

À l'arrivée, le switch retire l'étiquette et envoie au bon port.

**Analogie** : un colis avec une étiquette "Département RH" - le facteur sait où le livrer.

---

## Les risques de sécurité

### 1. VLAN Hopping (saut entre VLANs)

**Le problème** : un attaquant peut essayer de passer d'un VLAN à un autre.

**Technique "Switch Spoofing"** :
L'attaquant fait croire au switch qu'il est un autre switch et négocie un trunk.

```
Attaquant : "Je suis un switch !"
Switch : "OK, voilà un trunk avec tous les VLANs !"
Attaquant : "Parfait, accès à tout !"
```

**Solution** : désactiver la négociation automatique (DTP)

### 2. Double tagging

**Le problème** : l'attaquant envoie une trame avec 2 étiquettes VLAN.

```
1. Attaquant envoie : [VLAN 1][VLAN 20][Données]
2. Premier switch retire VLAN 1 (natif)
3. Deuxième switch voit VLAN 20
4. La trame arrive au VLAN 20 !
```

**Solution** : ne pas utiliser le VLAN 1 comme Native VLAN

---

## Bonnes pratiques de sécurité

| Pratique | Pourquoi |
|----------|----------|
| Désactiver DTP | Empêche la négociation automatique de trunks |
| Changer le Native VLAN | Évite les attaques double-tagging |
| Ne pas utiliser VLAN 1 | VLAN par défaut, souvent ciblé |
| Limiter les VLANs sur trunks | N'autoriser que ceux nécessaires |
| Éteindre les ports inutilisés | Moins de points d'entrée |

---

## Configuration basique (Cisco)

### Créer un VLAN

```
Switch(config)# vlan 10
Switch(config-vlan)# name RH
```

### Configurer un port access

```
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
```

### Configurer un trunk

```
Switch(config)# interface GigabitEthernet0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30
Switch(config-if)# switchport nonegotiate
```

---

## Analogie complète

Un immeuble de bureaux :

| Concept | Analogie |
|---------|----------|
| **VLAN** | Un étage de l'immeuble |
| **Port access** | Une porte qui mène à un seul étage |
| **Port trunk** | L'ascenseur qui dessert tous les étages |
| **Tag 802.1Q** | Le badge qui indique à quel étage aller |
| **Native VLAN** | L'étage par défaut si pas de badge |

Les personnes d'un étage ne peuvent pas aller dans un autre sans passer par un point de contrôle (routeur).

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **VLAN** | Réseau virtuel sur un switch physique |
| **802.1Q** | Standard pour étiqueter les trames avec leur VLAN |
| **Port Access** | Port qui appartient à un seul VLAN |
| **Port Trunk** | Port qui transporte plusieurs VLANs |
| **Native VLAN** | VLAN dont les trames ne sont pas étiquetées |
| **DTP** | Protocole de négociation automatique (dangereux) |
| **VLAN Hopping** | Attaque pour sauter d'un VLAN à l'autre |

---

## Résumé en 30 secondes

1. **VLAN** = réseaux virtuels séparés sur un même switch
2. **Avantages** : sécurité, organisation, performances
3. **Port access** = un VLAN, **port trunk** = plusieurs VLANs
4. Les trames sont étiquetées avec leur VLAN sur les trunks
5. **Risques** : VLAN hopping, double tagging
6. **Sécurité** : désactiver DTP, changer le Native VLAN
