# BGP Fondamentaux - Version Simplifiée

## L'idée en une phrase

BGP est le protocole qui fait fonctionner Internet : il permet aux grands réseaux (opérateurs, entreprises, datacenters) de s'échanger les routes pour joindre n'importe quelle adresse IP dans le monde.

---

## Pourquoi BGP est spécial ?

```
OSPF/RIP = Pour l'intérieur d'une entreprise
           "Comment aller du bureau A au bureau B ?"

BGP = Pour Internet, entre opérateurs
      "Comment aller de France vers les serveurs Google aux USA ?"

Analogie :
- OSPF = Plan d'une ville
- BGP  = Carte du monde avec les pays et les frontières
```

---

## Les Systèmes Autonomes (AS)

Internet est composé de milliers de réseaux indépendants. Chaque réseau a un numéro unique : l'**ASN**.

| Exemple | ASN | Propriétaire |
|---------|-----|--------------|
| AS 15169 | Google |
| AS 32934 | Facebook |
| AS 8075 | Microsoft |
| AS 3215 | Orange France |

---

## Comment BGP choisit une route ?

### L'AS_PATH : le secret de BGP

L'AS_PATH est la liste des AS traversés pour atteindre une destination :

```
Route vers 203.0.113.0/24 :
  AS_PATH: 65001 → 65002 → 65003

Signification :
"Pour aller à 203.0.113.0/24, je passe par AS 65001, puis AS 65002,
 puis j'arrive chez AS 65003 qui possède ces IPs"
```

### Règle simple

**Plus l'AS_PATH est court, mieux c'est !**

```
Route A : AS_PATH = 65001 65002 65003     (3 AS) ← Moins bien
Route B : AS_PATH = 65010 65003           (2 AS) ← GAGNE !
```

### Prévention des boucles

```
Si je suis AS 65002 et je reçois :
  AS_PATH = 65001 65002 65003
                   ↑
             C'est moi !

→ Je REJETTE cette route (je suis déjà dedans = boucle)
```

---

## iBGP vs eBGP

### Deux types de sessions BGP

```
eBGP (external) = Entre AS différents = Entre opérateurs

         AS 65001              AS 65002
     ┌─────────────┐       ┌─────────────┐
     │             │ eBGP  │             │
     │    R1   ────┼───────┼────  R2     │
     │             │       │             │
     └─────────────┘       └─────────────┘


iBGP (internal) = Dans le même AS = À l'intérieur d'un opérateur

              AS 65001
     ┌──────────────────────────┐
     │                          │
     │    R1 ───iBGP─── R2      │
     │                          │
     └──────────────────────────┘
```

### Différences importantes

| Aspect | eBGP | iBGP |
|--------|------|------|
| Entre | AS différents | Même AS |
| Next-hop | Change | Reste pareil |
| Fiabilité (AD) | 20 | 200 |
| TTL | 1 (voisins directs) | 255 |

---

## Configuration basique

```cisco
router bgp 65001
 bgp router-id 1.1.1.1

 ! Peering eBGP avec un autre AS
 neighbor 10.0.0.2 remote-as 65002

 ! Annoncer le réseau
 network 203.0.113.0 mask 255.255.255.0
```

---

## BGP Hijacking : l'attaque majeure

### Comment cela fonctionne ?

```
Situation normale :
AS 65001 (banque) annonce 203.0.113.0/24
→ Tout Internet route vers la vraie banque

Attaque Subprefix Hijacking :
AS 65999 (attaquant) annonce 203.0.113.0/25 et 203.0.113.128/25
→ Routes plus spécifiques = PRÉFÉRÉES par tout le monde
→ Tout le trafic va vers l'attaquant !
```

### Cas célèbres

| Année | Victime | Impact |
|-------|---------|--------|
| 2008 | YouTube | 2h d'indisponibilité mondiale |
| 2018 | Amazon/MyEtherWallet | Vol $150,000 en crypto |
| 2022 | KLAYswap | Vol $1.9 million en crypto |

---

## Protections BGP

### 1. RPKI

Validation cryptographique : "AS 65001 est autorisé à annoncer 203.0.113.0/24"

```cisco
router bgp 65001
 rpki server 10.0.0.100
  transport tcp port 8282

 address-family ipv4 unicast
  bgp origin-validation enable
```

### 2. Filtrage de préfixes

```cisco
! Rejeter les adresses privées sur Internet
ip prefix-list BOGON deny 10.0.0.0/8 le 32
ip prefix-list BOGON deny 192.168.0.0/16 le 32
ip prefix-list BOGON permit 0.0.0.0/0 le 24

router bgp 65001
 neighbor 10.0.0.2 prefix-list BOGON in
```

### 3. Maximum Prefix

Limiter le nombre de routes acceptées :

```cisco
router bgp 65001
 neighbor 10.0.0.2 maximum-prefix 1000 80
 ! Alerte à 80%, coupe si > 1000
```

### 4. Authentification

```cisco
router bgp 65001
 neighbor 10.0.0.2 password SecretKey123
```

---

## Commandes de vérification

```cisco
show ip bgp summary           ! Résumé des voisins
show ip bgp                   ! Table BGP complète
show ip bgp 203.0.113.0/24    ! Détail d'un préfixe
show ip bgp neighbors         ! Détail des sessions
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **BGP** | Protocole de routage d'Internet |
| **AS** | Réseau autonome avec un numéro unique |
| **ASN** | Numéro d'AS |
| **AS_PATH** | Liste des AS traversés (plus court = meilleur) |
| **eBGP** | BGP entre AS différents |
| **iBGP** | BGP dans le même AS |
| **Peering** | Relation d'échange de routes entre AS |
| **Transit** | AS qui transporte le trafic pour d'autres |
| **BGP Hijacking** | Annonce de préfixes non possédés |
| **RPKI** | Validation cryptographique des annonces |

---

## Résumé en 30 secondes

1. **BGP** = le protocole qui fait fonctionner Internet
2. Chaque opérateur a un **AS** avec un numéro unique
3. **AS_PATH** = liste des AS traversés (plus court = meilleur)
4. **eBGP** entre opérateurs, **iBGP** à l'intérieur
5. **BGP Hijacking** = détournement par fausse annonce
6. **RPKI** = protection cryptographique (à déployer !)

---

## Schéma récapitulatif

```
FONCTIONNEMENT BGP :

         AS 65001              AS 65002              AS 65003
     ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
     │             │ eBGP  │             │ eBGP  │             │
     │    R1   ────┼───────┼────  R2  ───┼───────┼────  R3     │
     │             │       │             │       │   possède   │
     └─────────────┘       └─────────────┘       │ 203.0.113.0 │
                                                 └─────────────┘

AS 65003 annonce : "J'ai 203.0.113.0/24"
AS 65002 reçoit  : AS_PATH = 65003
AS 65001 reçoit  : AS_PATH = 65002 65003


BGP HIJACKING :

         Normal                         Attaque

    AS 65001 ──→ AS 65003          AS 65001 ──→ AS 65003
         │       (légitime)              │       (légitime)
         │                               │
         └──→ 203.0.113.0/24       AS 65999 ──→ 203.0.113.0/25
                                   (attaquant)  (plus spécifique!)
                                         │
                                         └── Trafic détourné !


SÉLECTION DE ROUTE (simplifié) :

1. AS_PATH le plus court
2. Origin (IGP > EGP > Incomplete)
3. Si égal : MED le plus bas
4. eBGP > iBGP
```
