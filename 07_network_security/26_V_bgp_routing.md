# BGP - Version Simplifiée

## L'idée en une phrase

BGP est le protocole qui fait fonctionner Internet : il permet aux grands opérateurs et entreprises de s'échanger les routes pour joindre n'importe quelle adresse IP dans le monde.

---

## Pourquoi BGP existe ?

### Le problème

Internet est composé de milliers de réseaux indépendants (opérateurs, entreprises, hébergeurs). Comment font-ils pour se connaître et s'échanger du trafic ?

### La solution

BGP (Border Gateway Protocol) permet à ces réseaux de s'annoncer mutuellement les adresses IP qu'ils possèdent.

**Analogie** : chaque pays dispose de son propre service postal. BGP est l'accord international qui permet à chaque service de savoir vers quel pays envoyer un courrier.

---

## Les Systèmes Autonomes (AS)

### Qu'est-ce qu'un AS ?

Un **AS** (Autonomous System) est un ensemble de réseaux sous une même administration. Chaque AS a un numéro unique (ASN).

| Exemple | ASN | Propriétaire |
|---------|-----|--------------|
| AS 15169 | Google |
| AS 32934 | Facebook |
| AS 8075 | Microsoft |

### Types d'AS

| Type | Description |
|------|-------------|
| **Transit** | Opérateur qui transporte le trafic pour d'autres (Orange, Cogent) |
| **Stub** | AS qui n'a qu'un seul fournisseur (PME) |
| **Multi-homed** | AS connecté à plusieurs fournisseurs (grande entreprise) |

---

## Comment BGP choisit une route ?

### L'AS_PATH

L'AS_PATH est la liste des AS traversés pour atteindre une destination :

```
Pour joindre 203.0.113.0/24 :
  AS_PATH: 65001 → 65002 → 65003

Signification :
- Le préfixe appartient à AS 65003
- Il passe par AS 65002
- Puis AS 65001
- Pour arriver à destination
```

**Règle simple** : BGP préfère le chemin le plus court (moins d'AS traversés).

### Prévention des boucles

Si un routeur reçoit une route contenant son propre AS dans l'AS_PATH, il la rejette. Pas de boucles possibles !

---

## iBGP vs eBGP

### Deux types de sessions BGP

| Type | Entre qui ? | Usage |
|------|-------------|-------|
| **eBGP** | AS différents | Entre opérateurs |
| **iBGP** | Même AS | À l'intérieur d'un opérateur |

```
      AS 65001                        AS 65002
┌─────────────────┐              ┌─────────────────┐
│                 │              │                 │
│  R1 ───iBGP─── R2 ───eBGP─── R3 ───iBGP─── R4  │
│                 │              │                 │
└─────────────────┘              └─────────────────┘
```

---

## Configuration basique

### Établir un peering eBGP

```cisco
router bgp 65001
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65002
```

### Annoncer un réseau

```cisco
router bgp 65001
 network 203.0.113.0 mask 255.255.255.0
```

Le réseau doit exister dans la table de routage pour être annoncé.

---

## BGP Hijacking : la menace majeure

### Le problème

BGP fait confiance à ce que les autres annoncent. Si quelqu'un ment, le trafic peut être détourné.

### Comment cela fonctionne ?

```
Situation normale :
AS 65001 (légitime) annonce 203.0.113.0/24
→ Tout le monde route vers AS 65001

Attaque :
AS 65999 (attaquant) annonce AUSSI 203.0.113.0/24
→ Une partie d'Internet route vers l'attaquant !

Ou pire - annonce plus spécifique :
AS 65999 annonce 203.0.113.0/25 et 203.0.113.128/25
→ TOUT Internet préfère les routes plus spécifiques
→ Tout le trafic va vers l'attaquant
```

### Cas célèbres

| Année | Incident | Impact |
|-------|----------|--------|
| 2008 | Pakistan vs YouTube | YouTube inaccessible 2h |
| 2018 | Amazon Route 53 | Vol $150,000 crypto |
| 2022 | KLAYswap | Vol $1.9 million crypto |

---

## Protections BGP

### 1. RPKI (Resource PKI)

RPKI permet de vérifier cryptographiquement qu'un AS est autorisé à annoncer un préfixe :

```
ROA (Route Origin Authorization) :
"AS 65001 est autorisé à annoncer 203.0.113.0/24"

Si AS 65999 annonce ce préfixe → INVALIDE !
```

### 2. Filtrage de préfixes

```cisco
! Rejeter les adresses privées
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
 ! 80% = warning, shutdown si dépassé
```

### 4. Authentification MD5

```cisco
router bgp 65001
 neighbor 10.0.0.2 password SecretKey123
```

---

## Commandes de vérification

```cisco
! Voir les voisins BGP
show ip bgp summary

! Table BGP complète
show ip bgp

! Routes vers un préfixe
show ip bgp 203.0.113.0/24
```

### Exemple de sortie

```
Neighbor        V    AS MsgRcvd MsgSent  Up/Down  State/PfxRcd
10.0.0.2        4 65002    1542    1538  01:15:32       25
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **BGP** | Protocole de routage d'Internet |
| **AS** | Réseau autonome avec un numéro unique |
| **ASN** | Numéro d'AS |
| **AS_PATH** | Liste des AS traversés |
| **eBGP** | BGP entre AS différents |
| **iBGP** | BGP dans le même AS |
| **BGP Hijacking** | Annonce de préfixes non possédés |
| **RPKI** | Validation cryptographique des annonces |
| **ROA** | Autorisation d'annoncer un préfixe |

---

## Résumé en 30 secondes

1. **BGP** = le protocole qui fait fonctionner Internet
2. Chaque opérateur a un **AS** avec un numéro unique
3. BGP échange les **préfixes** (blocs d'adresses IP)
4. **AS_PATH** = liste des AS traversés (plus court = meilleur)
5. **BGP Hijacking** = attaque par annonce frauduleuse
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
AS 65002 reçoit : AS_PATH = 65003
AS 65001 reçoit : AS_PATH = 65002 65003


BGP HIJACKING :

         Normal                         Attaque

    AS 65001 ──→ AS 65003          AS 65001 ──→ AS 65003
         │       (légitime)              │       (légitime)
         │                               │
         └──→ 203.0.113.0/24       AS 65999 ──→ 203.0.113.0/25
                                   (attaquant)  (plus spécifique!)
                                         │
                                         └── Trafic détourné !
```
