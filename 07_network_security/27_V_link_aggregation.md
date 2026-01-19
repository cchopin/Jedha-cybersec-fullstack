# Link aggregation (LACP) - version simplifiée

## L'idée en une phrase

L'agrégation de liens permet de combiner plusieurs câbles réseau en un seul lien logique plus rapide et plus fiable.

---

## Pourquoi agréger des liens ?

### Les problèmes sans agrégation

| Problème | Conséquence |
|----------|-------------|
| Un seul câble | Si le câble casse = plus de connexion |
| Bande passante limitée | Goulot d'étranglement |
| STP bloque les liens redondants | Gaspillage de ressources |

### La solution

On combine plusieurs câbles en un seul "super lien" :

```
Sans agrégation :           Avec agrégation :

   SW1         SW2            SW1         SW2
    │           │              │           │
    │ 1 Gbps    │              ├───────────┤
    └───────────┘              ├─── 4x ────┤  = 4 Gbps logique
         │                     ├─── 1 Gbps ┤
    Si ça casse =              └───────────┘
    plus rien !                     │
                              Si 1 câble casse =
                              3 Gbps restants !
```

**Analogie** : au lieu d'avoir une seule voie sur l'autoroute, on en a 4. Si une voie est bloquée, les 3 autres continuent.

---

## LACP : le protocole standard

### Qu'est-ce que LACP ?

**LACP** (Link Aggregation Control Protocol) est le protocole standard (IEEE 802.3ad) pour agréger des liens de manière dynamique.

### Fonctionnement

1. Les deux switches s'envoient des messages LACP
2. Ils négocient les paramètres (vitesse, duplex)
3. Si tout est compatible, le LAG se forme
4. Si un câble tombe, il est retiré automatiquement

### Modes LACP

| Mode | Comportement |
|------|--------------|
| **Active** | Initie la négociation LACP |
| **Passive** | Attend une négociation |
| **On** | Pas de négociation (risque !) |

**Combinaisons qui fonctionnent** :
- Active + Active = OK
- Active + Passive = OK
- Passive + Passive = PAS DE LAG

---

## Configuration basique

### Sur un switch Cisco

```cisco
! Créer l'interface Port-Channel
interface Port-channel1
 switchport mode trunk

! Ajouter les interfaces physiques
interface range GigabitEthernet0/1-4
 switchport mode trunk
 channel-group 1 mode active
```

**Important** : la configuration doit être identique sur les deux switches !

---

## Load Balancing : répartir le trafic

### Le problème

Le LAG ne répartit pas le trafic paquet par paquet (cela causerait du désordre). Il répartit par **flux**.

### Méthodes de répartition

| Méthode | Basée sur | Usage |
|---------|-----------|-------|
| **src-mac** | MAC source | Peu de sources |
| **dst-mac** | MAC destination | Peu de destinations |
| **src-dst-ip** | IP source + destination | Cas général |
| **src-dst-port** | IP + ports | Maximum de granularité |

### Configuration

```cisco
port-channel load-balance src-dst-ip
```

**Exemple de répartition** :

```
PC1 → Serveur = toujours lien 1
PC2 → Serveur = toujours lien 2
PC3 → Serveur = toujours lien 3
...
```

---

## Vérification

### Commandes utiles

```cisco
! Voir l'état du LAG
show etherchannel summary

! Détail LACP
show lacp neighbor

! Méthode de load balancing
show etherchannel load-balance
```

### Exemple de sortie

```
Group  Port-channel  Protocol    Ports
------+-------------+-----------+----------------------------------
1      Po1(SU)       LACP       Gi0/1(P)  Gi0/2(P)  Gi0/3(P)  Gi0/4(P)

SU = Layer 2, en service
P  = Port actif dans le bundle
```

---

## MLAG : agrégation multi-chassis

### Le problème

Avec un LAG classique, si le switch tombe, tout tombe.

### La solution

**MLAG** (Multi-Chassis LAG) permet d'agréger vers deux switches différents :

```
              ┌─────────┐     ┌─────────┐
              │  SW1    │─────│  SW2    │  (Peer-link)
              └────┬────┘     └────┬────┘
                   │               │
                   └───────┬───────┘
                           │ MLAG
                    ┌──────┴──────┐
                    │   Serveur    │
                    └─────────────┘

Avantage : si SW1 tombe, SW2 continue !
```

### Implémentations MLAG

| Vendeur | Nom |
|---------|-----|
| Cisco Nexus | vPC (Virtual Port Channel) |
| Cisco Catalyst | VSS, StackWise |
| Arista | MLAG |

---

## Sécurité

### Risques

| Attaque | Description |
|---------|-------------|
| LACP Spoofing | Faux messages LACP pour rejoindre un LAG |
| Traffic Interception | S'ajouter au LAG pour intercepter |

### Protections

```cisco
! Utiliser LACP plutôt que mode statique
channel-group 1 mode active

! Détection rapide des pannes
interface range GigabitEthernet0/1-4
 lacp rate fast
```

---

## Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| LAG ne se forme pas | Configuration différente | Vérifier vitesse, duplex, VLANs |
| Ports en (s) suspended | Incompatibilité | `show etherchannel detail` |
| Trafic sur un seul lien | Peu de flux | Changer la méthode de hash |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **LAG** | Link Aggregation Group - ensemble de liens physiques combinés en un seul lien logique |
| **LACP** | Link Aggregation Control Protocol - protocole standard IEEE 802.3ad pour négocier l'agrégation |
| **Port-Channel** | Interface logique représentant le LAG |
| **EtherChannel** | Nom Cisco pour l'agrégation |
| **Load Balancing** | Répartition du trafic sur les liens |
| **MLAG** | Agrégation vers deux switches différents |
| **Bonding** | Terme Linux pour l'agrégation |

---

## Résumé en 30 secondes

1. **Link Aggregation** = combiner plusieurs câbles en un seul lien
2. **Avantages** : plus de bande passante + redondance
3. **LACP** = protocole standard pour négocier l'agrégation
4. Le trafic est réparti **par flux**, pas par paquet
5. **MLAG** = agrégation vers 2 switches (encore plus de redondance)
6. Toujours utiliser **mode active** pour LACP

---

## Schéma récapitulatif

```
AGRÉGATION DE LIENS :

   Sans LAG :                    Avec LAG :

   SW1       SW2                 SW1       SW2
    │         │                   ├─────────┤
    │ 1 Gbps  │                   ├─────────┤ Port-Channel
    └─────────┘                   ├─────────┤ 4 Gbps logique
                                  ├─────────┤
   1 lien = 1 Gbps                └─────────┘
   Si casse = 0 Gbps
                                 4 liens = 4 Gbps
                                 Si 1 casse = 3 Gbps


LOAD BALANCING (par flux) :

   PC1 ───────┐
              │   ┌──── Lien 1 ────┐
   PC2 ───────┼───│     Lien 2    │───── Serveur
              │   │     Lien 3    │
   PC3 ───────┘   └──── Lien 4 ────┘

   Chaque PC utilise un lien différent
   (selon le hash de son adresse)


MLAG (Multi-Chassis) :

        SW1 ←─ Peer-link ─→ SW2
         │                   │
         └─────────┬─────────┘
                   │ MLAG
              ┌────┴────┐
              │ Serveur │
              └─────────┘

   Si SW1 tombe → SW2 continue
   Zéro interruption !
```
