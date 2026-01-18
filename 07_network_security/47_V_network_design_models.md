# Modèles de Conception Réseau - Version Simplifiée

## L'idée en une phrase

Concevoir un réseau, c'est comme planifier une ville : le **Core-Distribution-Access** organise les réseaux campus en couches (autoroute → douane → rues), tandis que le **Leaf-Spine** aplatit tout pour les data centers modernes où tout le monde parle à tout le monde.

---

## Le Modèle Core-Distribution-Access : La Ville

### C'est quoi ?

C'est un modèle en 3 couches pour organiser un réseau d'entreprise :

```
                    ┌──────────┐
                    │   CORE   │ ← L'autoroute (rapide, pas de contrôle)
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
        ┌─────┴─────┐    │    ┌─────┴─────┐
        │DISTRIBUTION│   │    │DISTRIBUTION│ ← La douane (contrôle, routage)
        └─────┬─────┘    │    └─────┬─────┘
              │          │          │
        ┌─────┴────┐ ┌───┴───┐ ┌────┴─────┐
        │  ACCESS  │ │ ACCESS│ │  ACCESS  │ ← Les rues (utilisateurs)
        └────┬─────┘ └───┬───┘ └────┬─────┘
             │           │          │
          [PC]        [Phone]    [Printer]
```

### Les 3 couches expliquées simplement

```
┌─────────────────────────────────────────────────────────────┐
│                        CORE                                  │
├─────────────────────────────────────────────────────────────┤
│  • L'autoroute express                                       │
│  • Un seul job : TRANSPORTER VITE                            │
│  • Pas de contrôle, pas de filtrage                          │
│  • Redondance maximale (si un switch tombe, l'autre prend)   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     DISTRIBUTION                             │
├─────────────────────────────────────────────────────────────┤
│  • Le point de contrôle douanier                             │
│  • Applique les règles (ACL, QoS)                            │
│  • Route entre les VLANs                                     │
│  • VRRP pour la redondance gateway                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        ACCESS                                │
├─────────────────────────────────────────────────────────────┤
│  • Les rues du quartier                                      │
│  • Où les utilisateurs se connectent                         │
│  • Sécurité des ports (802.1X, port security)                │
│  • Attribution des VLANs                                     │
│  • PoE pour alimenter les téléphones                         │
└─────────────────────────────────────────────────────────────┘
```

### Qui fait quoi ?

| Couche | Rôle | Analogie |
|--------|------|----------|
| **Core** | Transport rapide | Autoroute |
| **Distribution** | Contrôle et routage | Douane |
| **Access** | Connexion utilisateurs | Rues |

---

## Le Modèle Leaf-Spine : Le Data Center

### Pourquoi un autre modèle ?

```
AVANT (applications classiques):        MAINTENANT (microservices):

    Internet                                Internet
       │                                       │
       ▼                                       ▼
   [Serveur]                             [Service A]
       │                                    │   │
       ▼                              ┌─────┘   └─────┐
   [Base de                           ▼               ▼
    données]                     [Service B]    [Service C]
                                      │               │
                                      └───────┬───────┘
                                              ▼
Trafic: Surtout vertical              [Base de données]
(utilisateur ↔ serveur)
                                 Trafic: Surtout horizontal
                                 (serveur ↔ serveur)
```

Le trafic **Nord-Sud** (vertical) est devenu minoritaire.
Le trafic **Est-Ouest** (horizontal) domine maintenant !

### Comment ça marche ?

```
                 SPINE 1         SPINE 2         SPINE 3
                    │               │               │
        ┌───────────┼───────────────┼───────────────┼───────────┐
        │           │               │               │           │
        ▼           ▼               ▼               ▼           ▼
    ┌──────┐    ┌──────┐        ┌──────┐        ┌──────┐    ┌──────┐
    │LEAF 1│    │LEAF 2│        │LEAF 3│        │LEAF 4│    │LEAF 5│
    └──┬───┘    └──┬───┘        └──┬───┘        └──┬───┘    └──┬───┘
       │           │               │               │           │
    [Srv]       [Srv]           [Srv]           [Srv]       [Srv]


Règles d'or :
✓ Chaque Leaf connecté à TOUS les Spines
✗ Les Leafs ne se parlent JAMAIS directement
✗ Les Spines ne se parlent JAMAIS directement
```

### Pourquoi c'est mieux pour les data centers ?

```
PROBLÈME avec le 3-tier :

Serveur A veut parler à Serveur B :

A → Access → Distrib → Core → Distrib → Access → B
      [1]      [2]     [3]     [4]       [5]

= 5 hops, latence variable


SOLUTION avec Leaf-Spine :

A → Leaf → Spine → Leaf → B
     [1]    [2]

= 2 hops MAXIMUM, toujours pareil !
```

---

## Comparaison Rapide

```
┌────────────────────┬─────────────────────┬─────────────────────┐
│                    │  CORE-DISTRIB-ACCESS│     LEAF-SPINE      │
├────────────────────┼─────────────────────┼─────────────────────┤
│ Forme              │    Pyramide         │    Plate            │
│ Trafic optimisé    │    Nord-Sud ↕       │    Est-Ouest ↔      │
│ Latence            │    Variable         │    Prévisible       │
│ Où l'utiliser ?    │    Campus, bureaux  │    Data centers     │
│ Hops max           │    5-6              │    2                 │
│ Scalabilité        │    Verticale        │    Horizontale      │
└────────────────────┴─────────────────────┴─────────────────────┘
```

---

## Quand utiliser quoi ?

### Choisir Core-Distribution-Access :

```
✓ Réseau de campus (université, hôpital)
✓ Bureaux d'entreprise
✓ Utilisateurs dispersés géographiquement
✓ Trafic principalement vers Internet/serveurs centraux
✓ Besoin de segmentation forte (VLANs, sécurité)
```

### Choisir Leaf-Spine :

```
✓ Data center moderne
✓ Applications en microservices / conteneurs
✓ Beaucoup de communication serveur-à-serveur
✓ Besoin de faible latence constante
✓ Automatisation importante
```

### Les deux ensemble ?

```
C'est souvent le cas !

┌─────────────────────────────────────────────────────────────┐
│                      ENTREPRISE                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   CAMPUS (CDA)                    DATA CENTER (Leaf-Spine)   │
│   ┌─────────┐                     ┌─────────────────────┐   │
│   │  Core   │                     │  Spine    Spine     │   │
│   │  Dist   │◄───────────────────►│  Leaf Leaf Leaf     │   │
│   │ Access  │                     │  [Srv] [Srv] [Srv]  │   │
│   │ [Users] │                     │                     │   │
│   └─────────┘                     └─────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Core** | Couche backbone, transport rapide sans filtrage |
| **Distribution** | Couche de contrôle, routage inter-VLAN, ACLs |
| **Access** | Couche utilisateur, ports, VLANs, PoE |
| **Leaf** | Switch connecté aux serveurs (bord) |
| **Spine** | Switch backbone interconnectant les Leafs |
| **Nord-Sud** | Trafic vertical (utilisateur ↔ serveur/Internet) |
| **Est-Ouest** | Trafic horizontal (serveur ↔ serveur) |
| **ECMP** | Répartition sur plusieurs chemins de coût égal |
| **VRRP** | Redondance de passerelle (backup automatique) |
| **Full mesh** | Chaque nœud connecté à tous les autres |

---

## Résumé en 30 secondes

```
CORE-DISTRIBUTION-ACCESS = La ville organisée
  • Core      = Autoroute (vite, pas de contrôle)
  • Distribution = Douane (contrôle, routage)
  • Access    = Rues (utilisateurs)
  → Pour : Campus, bureaux, trafic Nord-Sud

LEAF-SPINE = Le réseau plat
  • Spine = Backbone interconnectant tout
  • Leaf  = Bord connecté aux serveurs
  • 2 hops max entre n'importe quels serveurs
  → Pour : Data centers, microservices, trafic Est-Ouest
```

---

## Schéma récapitulatif

```
CORE-DISTRIBUTION-ACCESS (Campus)
══════════════════════════════════

         ┌────────┐
         │  CORE  │ ← Rapide, simple
         └───┬────┘
             │
      ┌──────┼──────┐
      │      │      │
   ┌──┴──┐┌──┴──┐┌──┴──┐
   │DIST ││DIST ││DIST │ ← Contrôle, routage
   └──┬──┘└──┬──┘└──┬──┘
      │      │      │
   ┌──┴──┐┌──┴──┐┌──┴──┐
   │ ACC ││ ACC ││ ACC │ ← Utilisateurs
   └─────┘└─────┘└─────┘

   Utiliser pour : Campus, hôpitaux, bureaux
   Trafic : Nord-Sud (↕)


LEAF-SPINE (Data Center)
════════════════════════

      [Spine 1]   [Spine 2]   [Spine 3]
           \    /  │  \    /
            \  /   │   \  /
             \/    │    \/
             /\    │    /\
            /  \   │   /  \
           /    \  │  /    \
      [Leaf 1] [Leaf 2] [Leaf 3]
         │         │        │
      [Srv]     [Srv]    [Srv]

   Utiliser pour : Data centers modernes
   Trafic : Est-Ouest (↔)


TRAFIC NORD-SUD vs EST-OUEST
════════════════════════════

   Nord-Sud (↕)           Est-Ouest (↔)
   ─────────────          ──────────────

      Internet               [Srv A]
         │                      │
         ▼                      │
      [Serveur]            ─────┼─────
         │                      │
         ▼                      ▼
      [User]               [Srv B]

   Utilisateur parle       Serveur parle
   au serveur              au serveur


QUAND UTILISER QUOI ?
═════════════════════

   ┌──────────────────────────────────────────────────────┐
   │                                                       │
   │   "Je construis un réseau de bureau/campus"           │
   │         → Core-Distribution-Access                    │
   │                                                       │
   │   "Je construis un data center moderne"               │
   │         → Leaf-Spine                                  │
   │                                                       │
   │   "J'ai les deux"                                     │
   │         → CDA pour les utilisateurs                   │
   │         → Leaf-Spine pour les serveurs                │
   │                                                       │
   └──────────────────────────────────────────────────────┘
```
