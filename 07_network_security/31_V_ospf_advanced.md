# OSPF Avancé - Version Simplifiée

## L'idée en une phrase

OSPF avancé, c'est comprendre comment le protocole divise les grands réseaux en aires, échange les informations de topologie via des LSAs, et élit des chefs de segment (DR/BDR) pour optimiser les échanges.

---

## Pourquoi OSPF est meilleur que RIP ?

```
RIP (distance-vector) :           OSPF (link-state) :

Chaque routeur ne connaît         Chaque routeur a LA CARTE
que ses voisins directs           COMPLÈTE du réseau

    "Le voisin dit que             "Pour aller à X,
     c'est à 3 sauts"              on passe par A, B, C"

= Téléphone arabe                 = Vue globale

Problèmes :                       Avantages :
- Lent                            - Rapide
- Boucles possibles               - Pas de boucles
- Limite à 15 sauts               - Pas de limite
```

---

## Les LSAs : les messages d'info

Chaque routeur envoie des **LSA** (Link-State Advertisement) pour décrire ses connexions :

```
"Bonjour, je suis R1, et je suis connecté à :
 - R2 avec un coût de 10
 - R3 avec un coût de 5"

Tout le monde reçoit ce message et construit la MÊME carte.
```

### Types de LSAs (simplifié)

| Type | Qui l'envoie | Ça dit quoi |
|------|--------------|-------------|
| **Type 1** | Tous les routeurs | "Voici mes liens" |
| **Type 2** | Le DR | "Voici les routeurs sur ce segment" |
| **Type 3** | L'ABR | "Voici les réseaux des autres aires" |
| **Type 5** | L'ASBR | "Voici les routes externes (autres protocoles)" |

---

## Les aires : diviser pour mieux régner

Dans un grand réseau, si tous les routeurs échangent tout, ça devient énorme. On divise en **aires** :

```
         ┌─────────────────────┐
         │      Area 0         │
         │    (Backbone)       │
         │   = L'autoroute     │
         └──────────┬──────────┘
                    │
         ┌──────────┼──────────┐
         │          │          │
    ┌────┴────┐ ┌───┴───┐ ┌────┴────┐
    │ Area 1  │ │ Area 2│ │ Area 3  │
    │ (RH)    │ │ (IT)  │ │ (Prod)  │
    └─────────┘ └───────┘ └─────────┘

Règle d'or : Toutes les aires doivent toucher Area 0
```

### Types d'aires

| Type | Ça bloque quoi | Usage |
|------|----------------|-------|
| **Standard** | Rien | Normal |
| **Stub** | Routes externes | Simplifié |
| **Totally Stubby** | Externes + inter-aires | Très simplifié |

---

## DR et BDR : les chefs de segment

Sur un segment Ethernet avec 5 routeurs, au lieu que tout le monde parle à tout le monde (chaos), on élit un **chef** :

```
Sans DR :                  Avec DR :

   R1 ── R2                    R1
    │\  /│                      │
    │ \/ │                   ┌──┴──┐
    │ /\ │                   │ DR  │ ← Le chef
    │/  \│                   └──┬──┘
   R3 ── R4                      │
                               R2, R3, R4

= 10 connexions              = 4 connexions (tout le monde
                               parle au DR, pas entre eux)
```

### Élection DR/BDR

```
Priorité la plus haute = devient DR
En cas d'égalité : Router-ID le plus haut gagne

R1 priorité 100 ← DR
R2 priorité 50  ← BDR (backup)
R3 priorité 0   ← Ne participe pas
```

---

## Le coût OSPF

OSPF calcule le **coût** en fonction de la vitesse :

```
Coût = 100 Mbps / Vitesse du lien

FastEthernet (100 Mbps)  : 100/100  = 1
GigabitEthernet (1 Gbps) : 100/1000 = 1 (arrondi)

Problème : tout ce qui est >= 100 Mbps a le même coût !

Solution :
router ospf 1
 auto-cost reference-bandwidth 10000  ! = 10 Gbps
```

---

## Redistribution : mélanger les protocoles

Quand on a plusieurs protocoles de routage (OSPF + RIP + routes statiques), on peut les faire parler :

```cisco
router ospf 1
 redistribute static subnets          ! Routes statiques → OSPF
 redistribute rip subnets             ! RIP → OSPF
```

**Attention** : cela peut créer des boucles si mal configuré !

---

## Attaques sur OSPF

### Rogue Router

```
1. L'attaquant branche son routeur
2. Configure OSPF pareil
3. Devient voisin des vrais routeurs
4. Injecte de fausses routes avec coût faible
5. Tout le trafic passe par lui !
```

### Protections

```cisco
! Authentification MD5 (obligatoire !)
interface GigabitEthernet0/0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 SecretKey123

! OSPF uniquement sur les interfaces nécessaires
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/0
```

---

## Commandes de vérification

```cisco
show ip ospf neighbor      ! Voir les voisins
show ip ospf database      ! Voir tous les LSAs
show ip route ospf         ! Voir les routes OSPF
show ip ospf interface     ! Détail par interface
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **LSA** | Message décrivant les liens d'un routeur |
| **LSDB** | Base de données de tous les LSAs |
| **Area 0** | Aire centrale obligatoire (backbone) |
| **DR** | Routeur chef sur un segment Ethernet |
| **BDR** | Routeur adjoint (backup du DR) |
| **ABR** | Routeur entre plusieurs aires |
| **ASBR** | Routeur qui injecte des routes externes |
| **Coût** | Métrique basée sur la bande passante |
| **SPF/Dijkstra** | Algorithme pour calculer le meilleur chemin |

---

## Résumé en 30 secondes

1. **OSPF link-state** = chaque routeur a la carte complète
2. **LSAs** = messages décrivant la topologie
3. **Aires** = divisent le réseau pour scalabilité
4. **DR/BDR** = chefs de segment pour réduire les échanges
5. **Coût** = basé sur la vitesse (plus rapide = moins cher)
6. **Sécurité** = authentification MD5 obligatoire !

---

## Schéma récapitulatif

```
TOPOLOGIE MULTI-AIRES :

         ┌─────────────────────────┐
         │        Area 0           │
         │       (Backbone)        │
         │    R1 ──── R2 ──── R3   │
         │     │              │    │
         └─────┼──────────────┼────┘
               │ ABR          │ ABR
         ┌─────┴─────┐  ┌─────┴─────┐
         │  Area 1   │  │  Area 2   │
         │ R4 ── R5  │  │ R6 ── R7  │
         └───────────┘  └───────────┘


ÉLECTION DR/BDR :

    Segment Ethernet avec 4 routeurs :

    R1 (prio 100) ──┬
    R2 (prio 150) ──┼── Élection → R2 = DR, R3 = BDR
    R3 (prio 120) ──┤
    R4 (prio 0)   ──┘   (R4 ne participe pas)


TYPES DE LSAs :

    Type 1 (Router)   → "Mes liens"
         ↓
    Type 2 (Network)  → "Qui est sur ce segment"
         ↓
    Type 3 (Summary)  → "Routes des autres aires"
         ↓
    Type 5 (External) → "Routes d'autres protocoles"
```
