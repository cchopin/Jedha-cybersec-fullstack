# Masques de sous-réseau et classes IP - version simplifiée

## L'idée en une phrase

Le masque de sous-réseau fonctionne comme le code postal : il indique quelle partie de l'adresse identifie le "quartier" (réseau) et quelle partie identifie la "maison" (machine).

---

## Pourquoi c'est important ?

Comprendre les masques permet de :
- Savoir combien de machines peuvent être présentes dans un réseau
- Découper un grand réseau en morceaux plus petits (sécurité, organisation)
- Comprendre pourquoi deux machines ne peuvent pas communiquer directement

---

## Une adresse IP contient deux informations

```
192.168.1.42

Partie RÉSEAU : 192.168.1    → "Dans quel quartier ?"
Partie HÔTE   : 42           → "Quelle maison dans ce quartier ?"
```

Le masque indique où se situe la séparation.

---

## Le masque : deux façons de l'écrire

### Notation décimale (ancienne)

```
255.255.255.0
```

### Notation CIDR (moderne)

```
/24
```

**Les deux expriment la même chose** : les 24 premiers bits sont réservés au réseau.

---

## Comprendre le /XX en 2 minutes

### La règle simple

- **32 bits au total** dans une adresse IPv4
- Le `/XX` = nombre de bits pour le réseau
- Le reste = bits pour les machines

| Notation | Bits réseau | Bits machines | Nombre de machines |
|----------|-------------|---------------|-------------------|
| /8 | 8 | 24 | 16 millions |
| /16 | 16 | 16 | 65 000 |
| /24 | 24 | 8 | 254 |
| /25 | 25 | 7 | 126 |
| /26 | 26 | 6 | 62 |
| /27 | 27 | 5 | 30 |
| /28 | 28 | 4 | 14 |
| /30 | 30 | 2 | 2 |

### Pourquoi 254 et non 256 pour un /24 ?

Deux adresses sont toujours réservées :
- La première = adresse du réseau (ex: 192.168.1.0)
- La dernière = adresse de broadcast (ex: 192.168.1.255)

---

## Les classes historiques (à connaître)

Avant CIDR, des "classes" étaient utilisées :

| Classe | Plage | Masque par défaut | Usage |
|--------|-------|-------------------|-------|
| A | 1.x.x.x - 126.x.x.x | /8 | Très grandes entreprises |
| B | 128.x.x.x - 191.x.x.x | /16 | Grandes entreprises |
| C | 192.x.x.x - 223.x.x.x | /24 | Petites entreprises |

**Aujourd'hui** : le CIDR est utilisé car plus flexible. Les classes sont obsolètes mais parfois encore mentionnées.

---

## Comment trouver l'adresse réseau ?

### La méthode simple (pour /8, /16, /24)

| Masque | Ce qui reste identique | Ce qui devient 0 |
|--------|----------------------|------------------|
| /8 | Premier octet | Les 3 derniers |
| /16 | 2 premiers octets | Les 2 derniers |
| /24 | 3 premiers octets | Le dernier |

**Exemple avec 192.168.45.130/24 :**
- Conservation de : 192.168.45
- Mise à 0 : le dernier octet
- Résultat : **192.168.45.0**

### Pour les autres masques (/25, /26, etc.)

Il faut calculer dans quel "bloc" tombe l'adresse.

**Exemple avec 192.168.1.100/26 :**

1. /26 = blocs de 64 (256 / 4 = 64)
2. Les blocs sont : 0-63, 64-127, 128-191, 192-255
3. 100 est dans le bloc 64-127
4. Adresse réseau : **192.168.1.64**

---

## Découper un réseau (Subnetting)

### Pourquoi découper ?

- Sécurité : isoler les départements
- Performance : réduire le trafic broadcast
- Organisation : séparer serveurs, employés, invités

### Exemple pratique

**Situation** : Le réseau 192.168.1.0/24 (254 machines) doit être divisé en 4 réseaux séparés.

**Solution** :
1. 4 sous-réseaux = 2 bits empruntés (2² = 4)
2. Nouveau masque : /24 + 2 = **/26**
3. Chaque sous-réseau accueille 62 machines

```
Sous-réseau 1 : 192.168.1.0/26    (machines .1 à .62)
Sous-réseau 2 : 192.168.1.64/26   (machines .65 à .126)
Sous-réseau 3 : 192.168.1.128/26  (machines .129 à .190)
Sous-réseau 4 : 192.168.1.192/26  (machines .193 à .254)
```

### Analogie : le gâteau

Un réseau est comparable à un gâteau. Plus il est coupé en parts (sous-réseaux), plus chaque part est petite (moins de machines).

---

## Le tableau de référence

| CIDR | Masque | Taille du bloc | Machines utilisables |
|------|--------|----------------|---------------------|
| /24 | 255.255.255.0 | 256 | 254 |
| /25 | 255.255.255.128 | 128 | 126 |
| /26 | 255.255.255.192 | 64 | 62 |
| /27 | 255.255.255.224 | 32 | 30 |
| /28 | 255.255.255.240 | 16 | 14 |
| /29 | 255.255.255.248 | 8 | 6 |
| /30 | 255.255.255.252 | 4 | 2 |

---

## Importance en sécurité

| Aspect | Impact |
|--------|--------|
| Segmentation | Empêche un attaquant de se propager facilement |
| ACL/Firewall | Les règles utilisent la notation CIDR |
| Scan réseau | Identification de la plage à scanner |
| Détection | Identification du trafic anormal entre sous-réseaux |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **Masque** | Indique quelle partie est réseau, quelle partie est machine |
| **CIDR** | Notation /24 (plus moderne que 255.255.255.0) |
| **Subnetting** | Découpage d'un réseau en morceaux plus petits |
| **Broadcast** | Adresse pour envoyer à tous les appareils du réseau |
| **Octet** | Un des 4 nombres de l'adresse (valeur de 0 à 255) |

---

## Résumé en 30 secondes

1. Une adresse IP = **partie réseau** + **partie machine**
2. Le masque (ou /XX) = indique où est la séparation
3. Plus le /XX est grand = plus le réseau est petit
4. Deux adresses sont toujours perdues (réseau + broadcast)
5. **Subnetting** = découper pour organiser et sécuriser

---

## Formule pour les calculs

**Combien de machines dans un /XX ?**

```
Machines = 2^(32-XX) - 2
```

Exemples :
- /24 : 2^8 - 2 = 256 - 2 = **254**
- /26 : 2^6 - 2 = 64 - 2 = **62**
- /28 : 2^4 - 2 = 16 - 2 = **14**
