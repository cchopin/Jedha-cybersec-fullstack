# Planification d'adresses et Subnetting Avancé - Version Simplifiée

## L'idée en une phrase

VLSM et Supernetting permettent d'utiliser l'espace d'adresses IP de façon intelligente : plus d'adresses là où il y en a besoin, moins là où il y en a moins besoin.

---

## Pourquoi est-ce important ?

Avec le subnetting "classique", un réseau est découpé en parts égales. Mais dans la réalité :
- Un département a 200 machines
- Un autre n'en a que 10
- Les liens entre routeurs n'ont besoin que de 2 adresses

**VLSM** permet de donner à chacun juste ce dont il a besoin.

---

## VLSM : des sous-réseaux de tailles différentes

### Le problème du subnetting classique

Imaginons un /24 découpé en 4 sous-réseaux égaux (/26 = 62 machines chacun) :

| Département | Besoin réel | Adresses données | Gaspillage |
|-------------|-------------|------------------|------------|
| IT | 50 machines | 62 | 12 |
| RH | 10 machines | 62 | 52 ! |
| Direction | 5 machines | 62 | 57 !! |
| Serveurs | 3 machines | 62 | 59 !!! |

Énorme gaspillage d'adresses.

### La solution VLSM

Chaque département reçoit un masque adapté à ses besoins :

| Département | Besoin | Masque utilisé | Adresses disponibles |
|-------------|--------|----------------|---------------------|
| IT | 50 | /26 | 62 |
| RH | 10 | /28 | 14 |
| Direction | 5 | /29 | 6 |
| Serveurs | 3 | /29 | 6 |

Beaucoup moins de gaspillage !

### Comment choisir le masque ?

**Règle simple** : trouver le plus petit masque qui contient tous les hôtes + 2 (réseau + broadcast)

| Besoin | Calcul | Masque |
|--------|--------|--------|
| 2 machines | 2+2=4 → /30 | /30 |
| 5 machines | 5+2=7 → /29 (8) | /29 |
| 10 machines | 10+2=12 → /28 (16) | /28 |
| 25 machines | 25+2=27 → /27 (32) | /27 |
| 50 machines | 50+2=52 → /26 (64) | /26 |
| 100 machines | 100+2=102 → /25 (128) | /25 |

### Exemple pratique

**Réseau de départ** : 192.168.1.0/24

**Besoins** :
- IT : 50 machines
- Marketing : 25 machines
- RH : 10 machines
- Lien routeur : 2 machines

**Allocation VLSM** (du plus grand au plus petit) :

```
IT :        192.168.1.0/26    (.1 à .62)
Marketing : 192.168.1.64/27   (.65 à .94)
RH :        192.168.1.96/28   (.97 à .110)
Routeur :   192.168.1.112/30  (.113 à .114)
Libre :     192.168.1.116 à .255
```

---

## Supernetting : regrouper plusieurs réseaux

### Le problème inverse

Avec beaucoup de petits réseaux, la table de routage devient énorme :

```
192.168.0.0/24 → via routeur A
192.168.1.0/24 → via routeur A
192.168.2.0/24 → via routeur A
192.168.3.0/24 → via routeur A
```

4 routes pour aller au même endroit !

### La solution : supernetting

Ces 4 réseaux sont regroupés en un seul :

```
192.168.0.0/22 → via routeur A
```

Une seule route ! Le routeur traite moins d'informations.

**Analogie** : au lieu de dire "ce courrier va au 1, 2, 3 ou 4 rue du Commerce", il suffit de dire "tout ce qui va rue du Commerce".

### Comment cela fonctionne-t-il ?

Des bits sont "rendus" au réseau (l'inverse du subnetting) :

| Réseaux de départ | Bits rendus | Supernet |
|-------------------|-------------|----------|
| 4 réseaux /24 | 2 bits | /22 |
| 8 réseaux /24 | 3 bits | /21 |
| 16 réseaux /24 | 4 bits | /20 |

### Condition importante

Les réseaux doivent être **contigus** et le premier doit être **divisible** par le nombre de réseaux.

**Exemple valide** : 192.168.0.0, 192.168.1.0, 192.168.2.0, 192.168.3.0 → 192.168.0.0/22

**Exemple invalide** : 192.168.1.0, 192.168.2.0, 192.168.3.0, 192.168.4.0 → ne fonctionne pas car 1 n'est pas divisible par 4.

---

## Résumé visuel

```
VLSM (découpage intelligent) :

    Réseau /24
    ┌────────────────────────────────────────┐
    │    /26     │  /27  │/28│/30│  libre   │
    │  (grand)   │(moyen)│pe │li │          │
    │            │       │tit│en │          │
    └────────────────────────────────────────┘

    Chaque département reçoit ce dont il a besoin


SUPERNETTING (regroupement) :

    4 réseaux /24
    ┌────────┐┌────────┐┌────────┐┌────────┐
    │ .0/24  ││ .1/24  ││ .2/24  ││ .3/24  │
    └────────┘└────────┘└────────┘└────────┘
              ↓ regroupement ↓
    ┌────────────────────────────────────────┐
    │            192.168.0.0/22              │
    └────────────────────────────────────────┘

    Une seule route au lieu de 4
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **VLSM** | Variable Length Subnet Mask - masques de tailles différentes |
| **Supernetting** | Regrouper plusieurs réseaux en un seul plus grand |
| **CIDR** | Notation /XX qui remplace les classes (A, B, C) |
| **Summarisation** | Autre nom pour le regroupement de routes |
| **Contigu** | Qui se suivent sans trou (0, 1, 2, 3...) |

---

## Résumé en 30 secondes

1. **VLSM** = donner des masques différents selon les besoins
2. Toujours commencer par les plus grands besoins
3. **Supernetting** = regrouper des réseaux pour simplifier le routage
4. Les réseaux doivent être contigus pour être regroupés
5. Le premier réseau doit être au début d'un bloc (divisible par la taille)

---

## Tableau pratique : bits hôtes → machines

| Masque | Bits hôtes | Adresses | Machines utilisables |
|--------|------------|----------|---------------------|
| /30 | 2 | 4 | 2 |
| /29 | 3 | 8 | 6 |
| /28 | 4 | 16 | 14 |
| /27 | 5 | 32 | 30 |
| /26 | 6 | 64 | 62 |
| /25 | 7 | 128 | 126 |
| /24 | 8 | 256 | 254 |
