# OSPF - version simplifiée

## L'idée en une phrase

OSPF est un protocole de routage intelligent où chaque routeur connaît la carte complète du réseau et calcule lui-même le meilleur chemin vers chaque destination.

---

## Pourquoi OSPF ?

### Le problème avec RIP

RIP (ancien protocole) compte juste le nombre de sauts :

```
RIP : "3 sauts = 3, peu importe si c'est du 10 Mbps ou 10 Gbps"

    ┌─────────────────────────────────────┐
    │        3 sauts (10 Mbps chacun)     │
    │ A ──→ R1 ──→ R2 ──→ R3 ──→ B        │  ← RIP choisit ça
    └─────────────────────────────────────┘

    ┌─────────────────────────────────────┐
    │        4 sauts (10 Gbps chacun)     │
    │ A ──→ R4 ──→ R5 ──→ R6 ──→ R7 ──→ B │  ← Plus rapide !
    └─────────────────────────────────────┘
```

### La solution OSPF

OSPF prend en compte la **vitesse des liens** :

```
OSPF : "Le chemin le plus rapide, pas le plus court"
```

---

## Comment fonctionne OSPF ?

### 1. Découverte des voisins

Les routeurs s'envoient des messages "Hello" pour se connaître :

```
R1 : "Hello ! Je suis R1"
R2 : "Hello ! Je suis R2, R1 a été entendu"
R1 : "Parfait, la relation de voisinage est établie !"
```

### 2. Échange de la topologie

Chaque routeur partage sa liste de liens (LSA = Link State Advertisement) :

```
R1 indique : "Connexion à R2 (coût 10) et R3 (coût 5)"
R2 indique : "Connexion à R1 (coût 10) et R4 (coût 20)"
...
```

### 3. Construction de la carte

Tous les routeurs ont maintenant la **même carte** du réseau (LSDB).

### 4. Calcul du meilleur chemin

Chaque routeur utilise l'algorithme de **Dijkstra** pour calculer le chemin le moins coûteux vers chaque destination.

**Analogie** : c'est comme si chaque conducteur avait la même carte Google Maps et calculait son itinéraire.

---

## Le coût OSPF

### Formule

```
Coût = Reference Bandwidth / Interface Bandwidth

Par défaut : Reference = 100 Mbps

FastEthernet (100 Mbps) : 100/100 = 1
GigabitEthernet (1 Gbps) : 100/1000 = 0.1 → arrondi à 1 (problème !)
```

### Problème et solution

Tous les liens >= 100 Mbps ont le même coût !

**Solution** : augmenter la référence :

```cisco
router ospf 1
 auto-cost reference-bandwidth 10000  ! 10 Gbps
```

---

## Les aires OSPF

### Pourquoi des aires ?

Dans un grand réseau, si tous les routeurs échangent toutes leurs informations, cela devient énorme. Le réseau est donc découpé en **aires**.

```
          ┌─────────────────────┐
          │      Area 0         │
          │    (Backbone)       │
          └──────────┬──────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
    ┌────┴────┐ ┌────┴────┐ ┌────┴────┐
    │ Area 1  │ │ Area 2  │ │ Area 3  │
    └─────────┘ └─────────┘ └─────────┘
```

**Règle d'or** : Toutes les aires doivent se connecter à l'Area 0 (backbone).

### Types d'aires

| Type | Ce qui est bloqué | Usage |
|------|-----------------|-------|
| **Standard** | Rien | Normal |
| **Stub** | Routes externes | Simplifié |
| **Totally Stubby** | Routes externes + inter-aires | Très simplifié |

---

## DR et BDR : les responsables de segment

### Le problème

Sur un réseau Ethernet avec 5 routeurs, chacun devrait parler à tous les autres :

```
Sans DR : 5 routeurs = 10 connexions !
```

### La solution

Un **responsable** (DR) et un **adjoint** (BDR) sont élus :

```
Avec DR :
              ┌───────┐
    R1 ───────┤  DR   ├─────── R3
              │       │
    R2 ───────┤  BDR  ├─────── R4
              └───────┘
                  │
                 R5

Tous les routeurs communiquent avec le DR, le DR communique avec tous.
```

### Élection

Le routeur avec la **priorité la plus élevée** devient DR.

```cisco
interface GigabitEthernet0/0
 ip ospf priority 100    ! Plus élevé = plus de chances de devenir DR
```

**Priorité 0** = ne participe jamais à l'élection.

---

## États des voisins OSPF

| État | Ce qui se passe |
|------|-----------------|
| **Down** | Pas de réponse |
| **Init** | Hello reçu mais pas encore confirmé |
| **2-Way** | Communication établie |
| **Full** | Synchronisation complète |

Si deux routeurs sont en **FULL**, ils ont la même vision du réseau.

---

## Configuration basique

```cisco
! Activer OSPF
router ospf 1
 router-id 1.1.1.1

! Annoncer les réseaux
 network 10.0.0.0 0.255.255.255 area 0
 network 192.168.1.0 0.0.0.255 area 1
```

Ou par interface (plus moderne) :

```cisco
interface GigabitEthernet0/0
 ip ospf 1 area 0
```

---

## Sécurité OSPF

### Les attaques possibles

| Attaque | Description |
|---------|-------------|
| **Rogue Router** | Routeur pirate qui s'infiltre dans OSPF |
| **Route Injection** | Injection de fausses routes |
| **DR Manipulation** | Devenir DR pour contrôler le routage |

### Scénario d'attaque

```
1. Un attaquant branche un routeur au réseau
2. Il établit des adjacences OSPF
3. Il injecte des routes avec des coûts faibles
4. Le trafic est redirigé vers lui (MitM)
```

### Protections

#### 1. Authentification

```cisco
interface GigabitEthernet0/0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 SecretKey123
```

Sans le mot de passe, impossible de devenir voisin OSPF.

#### 2. Passive Interface

Empêche OSPF sur les segments utilisateurs :

```cisco
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/0  ! Seulement vers les autres routeurs
```

---

## Commandes de vérification

```cisco
! Vue d'ensemble
show ip ospf

! Voisins
show ip ospf neighbor

! Routes OSPF
show ip route ospf

! Base de données
show ip ospf database
```

### Exemple de sortie

```
Neighbor ID     Pri   State           Address         Interface
2.2.2.2           1   FULL/DR         10.0.12.2       Gi0/0
3.3.3.3           1   FULL/BDR        10.0.12.3       Gi0/0
```

---

## Checklist sécurité OSPF

```
□ Authentification MD5 ou SHA sur toutes les interfaces
□ Passive-interface par défaut
□ Router ID configuré manuellement
□ Monitoring des adjacences
□ Documentation de la topologie attendue
□ Alertes sur nouveaux voisins
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **OSPF** | Protocole de routage à état de liens |
| **LSA** | Link State Advertisement - message décrivant les liens d'un routeur |
| **LSDB** | Link State Database - base de données contenant tous les LSAs |
| **SPF/Dijkstra** | Shortest Path First - algorithme pour calculer le chemin le moins coûteux |
| **Coût** | Métrique basée sur la bande passante |
| **Area 0** | Aire centrale obligatoire (backbone) |
| **DR** | Designated Router - routeur élu responsable sur un segment multi-accès |
| **BDR** | Backup Designated Router - routeur adjoint prêt à remplacer le DR |
| **ABR** | Area Border Router - routeur situé à la frontière entre plusieurs aires OSPF |
| **ASBR** | Autonomous System Boundary Router - routeur qui redistribue des routes provenant d'autres protocoles |

---

## Résumé en 30 secondes

1. **OSPF** = chaque routeur a la carte complète du réseau
2. Le **coût** est basé sur la bande passante (plus rapide = moins cher)
3. Les **aires** divisent le réseau pour plus de scalabilité
4. **DR/BDR** = responsables de segment pour réduire les échanges
5. **Sécurité** : authentification MD5 obligatoire !
6. Vérifier avec `show ip ospf neighbor`

---

## Schéma récapitulatif

```
COMPARAISON RIP vs OSPF :

RIP (nombre de sauts) :
A ──10Mbps──→ R1 ──10Mbps──→ B   = 2 sauts (choisi par RIP)
A ──1Gbps───→ R2 ──1Gbps───→ R3 ──1Gbps───→ B = 3 sauts

OSPF (coût/vitesse) :
A ──10Mbps──→ R1 ──10Mbps──→ B   = coût 20
A ──1Gbps───→ R2 ──1Gbps───→ R3 ──1Gbps───→ B = coût 3 (choisi !)


TOPOLOGIE MULTI-AIRES :

         ┌─────────────────────────┐
         │        Area 0           │
         │       (Backbone)        │
         │                         │
         │    R1 ──── R2 ──── R3   │
         │     │              │    │
         └─────┼──────────────┼────┘
               │ ABR          │ ABR
         ┌─────┴─────┐  ┌─────┴─────┐
         │  Area 1   │  │  Area 2   │
         │           │  │           │
         │ R4 ── R5  │  │ R6 ── R7  │
         └───────────┘  └───────────┘


ÉLECTION DR/BDR :

    Segment Ethernet avec 4 routeurs :

    R1 (prio 100) ──┬
    R2 (prio 150) ──┼── Élection → R2 = DR, R3 = BDR
    R3 (prio 120) ──┤
    R4 (prio 0)   ──┘   (R4 ne participe pas, prio = 0)
```
