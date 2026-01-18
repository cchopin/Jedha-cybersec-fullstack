# Agrégation de Liens et Load Balancing - Version Simplifiée

## L'idée en une phrase

L'agrégation de liens permet de combiner plusieurs câbles réseau en un seul lien logique plus rapide et plus fiable, comme si on élargissait une autoroute.

---

## Pourquoi agréger des liens ?

### Les problèmes sans agrégation

```
Un seul câble :

    Switch A ════════ Switch B
              1 Gbps

    - Si le câble casse = PLUS DE CONNEXION !
    - Bande passante limitée à 1 Gbps
```

### La solution : agrégation

```
4 câbles agrégés = 1 super lien :

    Switch A ═══╤═══ Switch B
               ═╤═
               ═╤═    = 4 Gbps logique
               ═╧═    + redondance

    - Si 1 câble casse = 3 Gbps restants !
    - Plus de bande passante
```

**Analogie** : au lieu d'avoir une seule voie sur l'autoroute, on en a 4. Si une voie est bloquée, les 3 autres continuent.

---

## LACP : le protocole standard

### Qu'est-ce que LACP ?

**LACP** (Link Aggregation Control Protocol) est le protocole standard (IEEE 802.3ad) pour agréger des liens de manière dynamique.

### Comment cela fonctionne ?

```
1. Les deux switches s'envoient des messages LACP
2. Ils négocient : "On a les mêmes paramètres ?"
3. Si oui, le LAG se forme automatiquement
4. LACP surveille la santé de chaque lien
5. Si un câble tombe, il est retiré du groupe
```

### Modes LACP

| Mode | Comportement |
|------|--------------|
| **Active** | Initie la négociation |
| **Passive** | Attend qu'on lui parle |
| **On** | Pas de négociation (risque !) |

```
Combinaisons qui fonctionnent :
Active + Active  = OK
Active + Passive = OK
Passive + Passive = PAS DE LAG (personne ne parle !)
```

---

## Configuration basique

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

### Comment cela fonctionne ?

```
PC1 → Serveur = toujours lien 1
PC2 → Serveur = toujours lien 2
PC3 → Serveur = toujours lien 3
...

Chaque "conversation" reste sur le même lien
pour éviter que les paquets arrivent dans le désordre.
```

### Méthodes de répartition

| Méthode | Basé sur | Quand l'utiliser |
|---------|----------|------------------|
| **src-mac** | MAC source | Peu de sources, beaucoup de destinations |
| **dst-mac** | MAC destination | Beaucoup de sources, peu de destinations |
| **src-dst-ip** | IP source + destination | Cas général (recommandé) |

```cisco
port-channel load-balance src-dst-ip
```

---

## MLAG : agrégation multi-chassis

### Le problème avec un LAG classique

```
Si le switch tombe, tout tombe :

    Serveur
       │
       │ LAG
       │
    Switch ← MORT
       │
   Internet
```

### La solution : MLAG

Le serveur se connecte à **deux switches différents** :

```
          Serveur
         /       \
     NIC1         NIC2
       │           │
       │    LAG    │
       ▼           ▼
   ┌─────────┐ ┌─────────┐
   │ Switch1 │─│ Switch2 │  (peer-link entre eux)
   └─────────┘ └─────────┘

Si Switch1 tombe → Switch2 continue !
```

### Implémentations MLAG

| Vendeur | Nom |
|---------|-----|
| Cisco Nexus | vPC |
| Cisco Catalyst | VSS, StackWise |
| Arista | MLAG |
| Juniper | MC-LAG |

---

## Vérification

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
------+-------------+-----------+------------------------
1      Po1(SU)       LACP       Gi0/1(P)  Gi0/2(P)

SU = Layer 2, en service
P  = Port actif dans le bundle
```

---

## Sécurité

### Risques

| Attaque | Description |
|---------|-------------|
| LACP Spoofing | Faux messages LACP pour rejoindre un LAG |
| Traffic Interception | S'ajouter au LAG pour intercepter le trafic |

### Protections

```cisco
! Utiliser LACP (pas mode statique)
channel-group 1 mode active

! Détection rapide des pannes
interface range GigabitEthernet0/1-4
 lacp rate fast
```

---

## Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| LAG ne se forme pas | Config différente | Vérifier vitesse, duplex, VLANs |
| Ports en (s) suspended | Incompatibilité | `show etherchannel detail` |
| Trafic sur un seul lien | Peu de flux | Changer la méthode de hash |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **LAG** | Link Aggregation Group - groupe de liens agrégés |
| **LACP** | Protocole standard d'agrégation |
| **Port-Channel** | Interface logique représentant le LAG |
| **EtherChannel** | Nom Cisco pour l'agrégation |
| **Load Balancing** | Répartition du trafic sur les liens |
| **MLAG** | Agrégation vers deux switches différents |
| **Bonding** | Terme Linux pour l'agrégation (même concept, nom différent) |

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
