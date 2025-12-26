# Masques de sous-réseau et classes IP 

## Introduction

Le subnetting (découpage en sous-réseaux) et la classification des adresses IP sont des concepts fondamentaux pour construire, gérer et sécuriser les réseaux. La maîtrise de ces notions permet de :

- Optimiser l'utilisation des adresses IP
- Segmenter le réseau pour améliorer les performances et la sécurité
- Isoler les zones sensibles (serveurs, management, utilisateurs)
- Comprendre les architectures réseau lors d'audits ou de pentests

---

## Glossaire

| Sigle/Terme | Nom complet | Description |
|-------------|-------------|-------------|
| **IP** | Internet Protocol | Protocole d'adressage réseau |
| **IPv4** | Internet Protocol version 4 | Adresses sur 32 bits (ex: 192.168.1.1) |
| **CIDR** | Classless Inter-Domain Routing | Notation moderne des réseaux (ex: /24) remplaçant les classes |
| **VLSM** | Variable Length Subnet Mask | Technique permettant des masques de taille variable dans un même réseau |
| **Octet** | - | Groupe de 8 bits (valeur de 0 à 255) |
| **Network ID** | Identifiant réseau | Partie de l'adresse IP identifiant le réseau |
| **Host ID** | Identifiant hôte | Partie de l'adresse IP identifiant l'appareil dans le réseau |
| **Broadcast** | Diffusion | Adresse permettant d'envoyer à tous les hôtes d'un réseau |
| **RFC** | Request For Comments | Documents définissant les standards Internet |

---

## Rappel : structure d'une adresse IPv4

Une adresse IPv4 est un nombre de 32 bits, représenté en notation décimale pointée :

```
192.168.1.1 → 11000000.10101000.00000001.00000001

|-- Octet 1 --|-- Octet 2 --|-- Octet 3 --|-- Octet 4 --|
|   8 bits    |   8 bits    |   8 bits    |   8 bits    |
|  0 à 255    |  0 à 255    |  0 à 255    |  0 à 255    |
```

Chaque adresse IP se divise en deux parties :
- **Partie réseau (Network ID)** : identifie le réseau
- **Partie hôte (Host ID)** : identifie l'appareil dans ce réseau

Le **masque de sous-réseau** définit où se situe la frontière entre ces deux parties.

### Conversion décimal ↔ binaire

La maîtrise de la conversion binaire est essentielle pour comprendre le subnetting.

#### Les puissances de 2 dans un octet

Chaque bit d'un octet représente une puissance de 2 :

```
Position :  7     6     5     4     3     2     1     0
Valeur   : 128   64    32    16    8     4     2     1
           ─────────────────────────────────────────────
Total    :                   256 combinaisons (0-255)
```

#### Décimal vers binaire (méthode de soustraction)

Pour convertir un nombre décimal en binaire, soustraire les puissances de 2 de gauche à droite :

**Exemple** : convertir 200 en binaire

```
200 ≥ 128 ? Oui → 1, reste 200-128 = 72
72  ≥ 64  ? Oui → 1, reste 72-64 = 8
8   ≥ 32  ? Non → 0
8   ≥ 16  ? Non → 0
8   ≥ 8   ? Oui → 1, reste 8-8 = 0
0   ≥ 4   ? Non → 0
0   ≥ 2   ? Non → 0
0   ≥ 1   ? Non → 0

Résultat : 11001000
```

**Vérification** : 128 + 64 + 8 = 200

#### Binaire vers décimal

Additionner les valeurs des positions où il y a un 1 :

**Exemple** : convertir 10101010 en décimal

```
Position :  1   0   1   0   1   0   1   0
Valeur   : 128  64  32  16  8   4   2   1
           ─────────────────────────────
Calcul   : 128 + 0 + 32 + 0 + 8 + 0 + 2 + 0 = 170
```

#### Valeurs courantes

| Décimal | Binaire | Remarque |
|---------|---------|----------|
| 0 | 00000000 | Tous les bits à 0 |
| 1 | 00000001 | |
| 128 | 10000000 | Premier bit uniquement |
| 192 | 11000000 | 128 + 64 (masque /26) |
| 224 | 11100000 | 128 + 64 + 32 (masque /27) |
| 240 | 11110000 | 128 + 64 + 32 + 16 (masque /28) |
| 248 | 11111000 | (masque /29) |
| 252 | 11111100 | (masque /30) |
| 254 | 11111110 | (masque /31) |
| 255 | 11111111 | Tous les bits à 1 |

---

## L'adressage par classes (Classful Addressing)

### Historique

Avant CIDR, les adresses IPv4 étaient divisées en 5 classes (A à E) selon les premiers bits de l'adresse. Ce système, bien que largement obsolète, reste important à connaître pour :
- Comprendre les plages d'adresses privées (RFC 1918)
- Interpréter les configurations héritées
- Certaines certifications et examens

### Les 5 classes d'adresses

| Classe | Plage d'adresses | Premier(s) bit(s) | Masque par défaut | CIDR | Réseaux | Hôtes/réseau |
|--------|------------------|-------------------|-------------------|------|---------|--------------|
| A | 0.0.0.0 - 127.255.255.255 | 0 | 255.0.0.0 | /8 | 128 | 16 777 214 |
| B | 128.0.0.0 - 191.255.255.255 | 10 | 255.255.0.0 | /16 | 16 384 | 65 534 |
| C | 192.0.0.0 - 223.255.255.255 | 110 | 255.255.255.0 | /24 | 2 097 152 | 254 |
| D | 224.0.0.0 - 239.255.255.255 | 1110 | - | - | Multicast | - |
| E | 240.0.0.0 - 255.255.255.255 | 1111 | - | - | Expérimental | - |

### Détail des classes principales

#### Classe A

```
|<- 8 bits ->|<-------- 24 bits -------->|
|   Réseau   |          Hôtes            |
|  0XXXXXXX  |      X.X.X                |
```

- **Plage utilisable** : 1.0.0.0 à 126.255.255.255
- **127.x.x.x** : réservé au loopback (127.0.0.1)
- **Réseau privé classe A** : 10.0.0.0/8
- **Usage** : très grands réseaux (FAI, multinationales)

#### Classe B

```
|<--- 16 bits --->|<--- 16 bits --->|
|     Réseau      |      Hôtes      |
|   10XXXXXX.X    |       X.X       |
```

- **Plage** : 128.0.0.0 à 191.255.255.255
- **Réseaux privés classe B** : 172.16.0.0 à 172.31.0.0 (172.16.0.0/12)
- **Usage** : réseaux moyens (universités, grandes entreprises)

#### Classe C

```
|<------ 24 bits ------>|<- 8 bits ->|
|        Réseau         |   Hôtes    |
|   110XXXXX.X.X        |     X      |
```

- **Plage** : 192.0.0.0 à 223.255.255.255
- **Réseau privé classe C** : 192.168.0.0/16
- **Usage** : petits réseaux (PME, réseaux domestiques)

### Identification rapide de la classe

| Premier octet | Classe |
|---------------|--------|
| 1 - 126 | A |
| 128 - 191 | B |
| 192 - 223 | C |
| 224 - 239 | D (multicast) |
| 240 - 255 | E (expérimental) |

**Moyen mnémotechnique** : les seuils sont 128, 192, 224, 240 (puissances de 2 décroissantes ajoutées à 128).

---

## Le masque de sous-réseau

### Principe

Le masque de sous-réseau est un nombre de 32 bits qui indique quelle partie de l'adresse IP correspond au réseau et quelle partie correspond à l'hôte.

```
Adresse IP  : 192.168.1.100   → 11000000.10101000.00000001.01100100
Masque      : 255.255.255.0   → 11111111.11111111.11111111.00000000
                                |<------ Réseau ------->|<- Hôte ->|
```

**Règle** :
- Les bits à **1** dans le masque = partie réseau
- Les bits à **0** dans le masque = partie hôte

### Opération AND logique

#### Qu'est-ce que l'opération AND ?

L'opération AND (ET logique) est une opération binaire fondamentale. Elle compare deux bits et retourne un résultat selon cette règle :

| Bit A | Bit B | A AND B |
|-------|-------|---------|
| 0 | 0 | 0 |
| 0 | 1 | 0 |
| 1 | 0 | 0 |
| 1 | 1 | 1 |

**Règle simple** : le résultat est **1 uniquement si les deux bits sont à 1**. Dans tous les autres cas, le résultat est 0.

#### Pourquoi utiliser AND avec le masque ?

Le masque de sous-réseau agit comme un **filtre** :
- Là où le masque a un **1** : le bit de l'IP est **conservé** (1 AND 1 = 1, 0 AND 1 = 0)
- Là où le masque a un **0** : le bit de l'IP est **effacé** (mis à 0)

Cela permet d'extraire uniquement la partie réseau de l'adresse IP.

#### Exemple détaillé pas à pas

**Objectif** : trouver l'adresse réseau de 192.168.1.100 avec le masque 255.255.255.0

**Étape 1** : convertir l'IP en binaire

```
192 = 128 + 64 = 11000000
168 = 128 + 32 + 8 = 10101000
1   = 1 = 00000001
100 = 64 + 32 + 4 = 01100100

IP : 11000000.10101000.00000001.01100100
```

**Étape 2** : convertir le masque en binaire

```
255 = 11111111
255 = 11111111
255 = 11111111
0   = 00000000

Masque : 11111111.11111111.11111111.00000000
```

**Étape 3** : appliquer AND bit par bit

```
IP      : 11000000.10101000.00000001.01100100
Masque  : 11111111.11111111.11111111.00000000
          ────────────────────────────────────
Résultat: 11000000.10101000.00000001.00000000
```

Détail du dernier octet (le seul qui change) :

```
IP (100)    :  0  1  1  0  0  1  0  0
Masque (0)  :  0  0  0  0  0  0  0  0
              ─────────────────────────
AND         :  0  0  0  0  0  0  0  0  = 0
```

Tous les bits hôtes (là où le masque = 0) sont effacés.

**Étape 4** : convertir le résultat en décimal

```
11000000 = 192
10101000 = 168
00000001 = 1
00000000 = 0

Adresse réseau : 192.168.1.0
```

#### Exemple avec un masque non standard (/26)

**Objectif** : trouver l'adresse réseau de 192.168.1.100 avec le masque /26 (255.255.255.192)

```
IP      : 192.168.1.100  → 11000000.10101000.00000001.01100100
Masque  : 255.255.255.192→ 11111111.11111111.11111111.11000000
                           ─────────────────────────────────────
Réseau  :                  11000000.10101000.00000001.01000000
                         = 192.168.1.64
```

Détail du dernier octet :

```
Position:     128  64  32  16   8   4   2   1
              ─────────────────────────────────
IP (100)    :   0   1   1   0   0   1   0   0
Masque(192) :   1   1   0   0   0   0   0   0
              ─────────────────────────────────
AND         :   0   1   0   0   0   0   0   0  = 64
```

Les deux premiers bits (128, 64) sont conservés car le masque a des 1.
Les six derniers bits sont effacés car le masque a des 0.

**Résultat** : l'IP 192.168.1.100/26 appartient au réseau 192.168.1.64/26

#### Visualisation du filtrage

```
Masque /26 : 11111111.11111111.11111111.11|000000
                                          ↑
                               Frontière réseau/hôte

IP quelconque dans ce réseau :
             XXXXXXXX.XXXXXXXX.XXXXXXXX.XX|HHHHHH
             |<-------- Partie réseau -------->|<-Hôte->|
                      (26 bits fixes)         (6 bits variables)
```

#### Applications pratiques

| Question | Méthode |
|----------|---------|
| À quel réseau appartient cette IP ? | IP AND Masque = Adresse réseau |
| Deux IPs sont-elles sur le même réseau ? | Si (IP1 AND Masque) = (IP2 AND Masque), alors oui |
| Quelle est l'adresse de broadcast ? | Adresse réseau avec tous les bits hôtes à 1 |

**Exemple** : 10.20.30.40/16 et 10.20.50.60/16 sont-ils sur le même réseau ?

```
10.20.30.40 AND 255.255.0.0 = 10.20.0.0
10.20.50.60 AND 255.255.0.0 = 10.20.0.0

Même résultat → Même réseau
```

### Masques standards

| CIDR | Masque décimal | Masque binaire | Bits réseau | Bits hôtes |
|------|----------------|----------------|-------------|------------|
| /8 | 255.0.0.0 | 11111111.00000000.00000000.00000000 | 8 | 24 |
| /16 | 255.255.0.0 | 11111111.11111111.00000000.00000000 | 16 | 16 |
| /24 | 255.255.255.0 | 11111111.11111111.11111111.00000000 | 24 | 8 |
| /25 | 255.255.255.128 | 11111111.11111111.11111111.10000000 | 25 | 7 |
| /26 | 255.255.255.192 | 11111111.11111111.11111111.11000000 | 26 | 6 |
| /27 | 255.255.255.224 | 11111111.11111111.11111111.11100000 | 27 | 5 |
| /28 | 255.255.255.240 | 11111111.11111111.11111111.11110000 | 28 | 4 |
| /29 | 255.255.255.248 | 11111111.11111111.11111111.11111000 | 29 | 3 |
| /30 | 255.255.255.252 | 11111111.11111111.11111111.11111100 | 30 | 2 |
| /31 | 255.255.255.254 | 11111111.11111111.11111111.11111110 | 31 | 1 |
| /32 | 255.255.255.255 | 11111111.11111111.11111111.11111111 | 32 | 0 |

### Valeurs magiques des masques

Les valeurs possibles pour le dernier octet significatif du masque sont :

| Valeur | Binaire | CIDR équivalent (dernier octet) |
|--------|---------|--------------------------------|
| 0 | 00000000 | /0 de l'octet (pas de masquage) |
| 128 | 10000000 | /1 de l'octet |
| 192 | 11000000 | /2 de l'octet |
| 224 | 11100000 | /3 de l'octet |
| 240 | 11110000 | /4 de l'octet |
| 248 | 11111000 | /5 de l'octet |
| 252 | 11111100 | /6 de l'octet |
| 254 | 11111110 | /7 de l'octet |
| 255 | 11111111 | /8 de l'octet (octet complet masqué) |

**Astuce** : ces valeurs sont 256 - 2^n (où n = bits hôtes dans l'octet) : 256-128=128, 256-64=192, 256-32=224, etc.

---

## Calcul des sous-réseaux et des hôtes

### Comprendre le concept avant les formules

#### Analogie : découper un gâteau

Un réseau, c'est comme un gâteau. Le subnetting consiste à le découper en parts.

- **Plus on fait de parts** (sous-réseaux), **plus chaque part est petite** (moins d'hôtes par sous-réseau)
- **Moins on fait de parts**, **plus chaque part est grande** (plus d'hôtes par sous-réseau)

Le nombre total "d'espace" reste le même, on le répartit différemment.

#### Les deux adresses réservées

Dans chaque sous-réseau, **deux adresses ne peuvent jamais être attribuées à des machines** :

| Adresse | Nom | Rôle | Exemple dans 192.168.1.0/24 |
|---------|-----|------|----------------------------|
| Première (tous les bits hôtes à 0) | Adresse réseau | Identifie le réseau lui-même | 192.168.1.0 |
| Dernière (tous les bits hôtes à 1) | Adresse broadcast | Envoie à toutes les machines du réseau | 192.168.1.255 |

C'est pourquoi on soustrait toujours 2 au nombre total d'adresses pour obtenir le nombre d'hôtes **utilisables**.

### Compter les hôtes : la méthode simple

#### Principe de base

Le nombre de bits pour les hôtes détermine combien d'adresses sont disponibles.

Avec **1 bit**, on peut faire 2 combinaisons : 0 et 1
Avec **2 bits**, on peut faire 4 combinaisons : 00, 01, 10, 11
Avec **3 bits**, on peut faire 8 combinaisons : 000, 001, 010, 011, 100, 101, 110, 111

**Règle** : avec N bits, on peut faire **2^N combinaisons** (2 multiplié par lui-même N fois).

#### Tableau pratique : bits hôtes → nombre d'hôtes

| Bits hôtes | Calcul | Adresses totales | Hôtes utilisables (moins 2) |
|------------|--------|------------------|----------------------------|
| 1 | 2^1 | 2 | 0 (inutilisable) |
| 2 | 2^2 | 4 | 2 |
| 3 | 2^3 | 8 | 6 |
| 4 | 2^4 | 16 | 14 |
| 5 | 2^5 | 32 | 30 |
| 6 | 2^6 | 64 | 62 |
| 7 | 2^7 | 128 | 126 |
| 8 | 2^8 | 256 | 254 |

#### Comment trouver le nombre de bits hôtes ?

C'est simple : **32 moins le CIDR**.

| CIDR | Bits réseau | Bits hôtes (32 - CIDR) | Hôtes utilisables |
|------|-------------|------------------------|-------------------|
| /24 | 24 | 32 - 24 = **8** | 254 |
| /25 | 25 | 32 - 25 = **7** | 126 |
| /26 | 26 | 32 - 26 = **6** | 62 |
| /27 | 27 | 32 - 27 = **5** | 30 |
| /28 | 28 | 32 - 28 = **4** | 14 |
| /29 | 29 | 32 - 29 = **3** | 6 |
| /30 | 30 | 32 - 30 = **2** | 2 |

### Découper un réseau en sous-réseaux

#### Le principe

Découper un réseau, c'est **emprunter des bits** à la partie hôte pour créer plus de réseaux.

```
Avant découpage (/24) :
|<------ 24 bits réseau ------>|<-- 8 bits hôtes -->|
         Partie fixe                  254 hôtes

Après découpage en /26 :
|<------ 24 bits réseau ------>|<-2->|<- 6 bits ->|
         Partie fixe            Sous-   62 hôtes
                                réseau
```

Les 2 bits empruntés permettent de créer 2^2 = **4 sous-réseaux**.
Les 6 bits restants permettent 2^6 - 2 = **62 hôtes** par sous-réseau.

#### Exemple concret pas à pas

**Situation** : une entreprise a le réseau 192.168.1.0/24 et veut créer 4 sous-réseaux pour 4 départements.

**Étape 1 : combien de bits emprunter ?**

Pour avoir 4 sous-réseaux, il faut emprunter combien de bits ?
- 1 bit → 2^1 = 2 sous-réseaux (pas assez)
- 2 bits → 2^2 = 4 sous-réseaux (parfait)

Réponse : **2 bits**.

**Étape 2 : quel est le nouveau masque ?**

```
Masque de départ : /24
Bits empruntés : 2
Nouveau masque : /24 + 2 = /26
```

En décimal : 255.255.255.192

**Étape 3 : combien d'hôtes par sous-réseau ?**

```
Bits hôtes restants : 32 - 26 = 6 bits
Hôtes : 2^6 - 2 = 64 - 2 = 62 hôtes utilisables
```

**Étape 4 : quel est le "pas" entre chaque sous-réseau ?**

Le pas, c'est l'écart entre le début de chaque sous-réseau.

Méthode simple : **256 - dernier octet du masque**

```
Masque : 255.255.255.192
Pas = 256 - 192 = 64
```

Les sous-réseaux commencent tous les 64 : à 0, 64, 128, 192.

**Étape 5 : lister les 4 sous-réseaux**

| Sous-réseau | Plage complète | Adresse réseau | Hôtes utilisables | Broadcast |
|-------------|----------------|----------------|-------------------|-----------|
| 1 | .0 à .63 | 192.168.1.0 | .1 à .62 | 192.168.1.63 |
| 2 | .64 à .127 | 192.168.1.64 | .65 à .126 | 192.168.1.127 |
| 3 | .128 à .191 | 192.168.1.128 | .129 à .190 | 192.168.1.191 |
| 4 | .192 à .255 | 192.168.1.192 | .193 à .254 | 192.168.1.255 |

Chaque sous-réseau contient 64 adresses, dont 62 utilisables pour des machines.

### Résumé : les 3 questions à se poser

| Question | Comment répondre |
|----------|------------------|
| **Combien d'hôtes dans ce réseau ?** | 2^(32 - CIDR) - 2 |
| **En combien de sous-réseaux puis-je découper ?** | 2^(bits empruntés) |
| **Où commence chaque sous-réseau ?** | Tous les (256 - dernier octet du masque) |

### Tableau récapitulatif des masques courants

| CIDR | Masque | Pas | Sous-réseaux dans un /24 | Hôtes/sous-réseau |
|------|--------|-----|--------------------------|-------------------|
| /24 | 255.255.255.0 | 256 | 1 | 254 |
| /25 | 255.255.255.128 | 128 | 2 | 126 |
| /26 | 255.255.255.192 | 64 | 4 | 62 |
| /27 | 255.255.255.224 | 32 | 8 | 30 |
| /28 | 255.255.255.240 | 16 | 16 | 14 |
| /29 | 255.255.255.248 | 8 | 32 | 6 |
| /30 | 255.255.255.252 | 4 | 64 | 2 |

### Exercice guidé

**Énoncé** : le réseau 10.0.0.0/8 doit être découpé pour avoir au moins 1000 hôtes par sous-réseau.

**Résolution** :

1. Combien de bits hôtes pour 1000 machines ?
   - 2^9 = 512 (pas assez)
   - 2^10 = 1024 (suffisant, donne 1022 hôtes utilisables)
   - Réponse : **10 bits hôtes**

2. Quel masque ?
   - CIDR = 32 - 10 = **/22**
   - Masque : 255.255.252.0

3. Combien de sous-réseaux possibles ?
   - Bits empruntés : 22 - 8 = 14 bits
   - Sous-réseaux : 2^14 = **16 384 sous-réseaux**

---

## Classful vs CIDR

| Aspect | Adressage par classes | CIDR |
|--------|----------------------|------|
| Blocs fixes | Oui (/8, /16, /24 uniquement) | Non (tout /n possible) |
| Flexibilité | Faible | Élevée |
| Gaspillage d'adresses | Important | Minimal |
| Usage actuel | Obsolète | Standard |
| Exemple | "Réseau classe C" | "Réseau /24" |

**CIDR est la méthode moderne** utilisée par les FAI, les entreprises et sur Internet. L'adressage par classes n'est plus utilisé mais reste important à connaître pour la compréhension historique et certaines références.

---

## Applications en cybersécurité

### Segmentation réseau et défense en profondeur

Le subnetting est un outil fondamental de sécurité :

| Zone | Subnet suggéré | Justification |
|------|----------------|---------------|
| Serveurs DMZ | /28 ou /29 | Peu de serveurs, isolation stricte |
| Réseau utilisateurs | /24 ou /23 | Plus de machines, segmentation par service |
| Management/Admin | /28 | Très restreint, accès limité |
| IoT/Caméras | /24 dédié | Isolation des appareils peu sécurisés |
| Serveurs internes | /27 | Taille adaptée, contrôle d'accès |

### Reconnaissance et énumération

Lors d'un pentest ou d'une analyse réseau, la compréhension du subnetting permet de :

| Action | Utilité |
|--------|---------|
| Identifier la taille du réseau | Estimer le nombre de cibles potentielles |
| Calculer la plage de scan | Éviter de scanner hors périmètre |
| Détecter les sous-réseaux adjacents | Identifier d'autres zones à explorer |
| Comprendre l'architecture | Déduire la segmentation et les flux |

**Exemple** : une IP 10.10.5.100/24 indique :
- Réseau : 10.10.5.0
- Plage à scanner : 10.10.5.1 - 10.10.5.254
- Environ 254 hôtes potentiels
- Probablement d'autres sous-réseaux en 10.10.X.0

### Évasion et contournement

La connaissance du subnetting aide à :

| Technique | Description |
|-----------|-------------|
| Identifier les frontières | Savoir où les ACL/firewalls sont probablement placés |
| Pivot entre sous-réseaux | Comprendre comment accéder à d'autres segments |
| Éviter la détection | Limiter le scan à un sous-réseau pour réduire le bruit |

### Configuration des firewalls et ACL

Les règles de firewall utilisent la notation CIDR :

```
# Autoriser le réseau admin vers les serveurs
permit 10.10.1.0/28 to 10.10.10.0/27

# Bloquer tout le RFC 1918 en entrée (anti-spoofing)
deny from 10.0.0.0/8
deny from 172.16.0.0/12
deny from 192.168.0.0/16
```

### Détection d'anomalies

| Anomalie | Signification possible |
|----------|----------------------|
| IP hors du sous-réseau attendu | Spoofing, misconfiguration, pivot |
| Broadcast excessif | Attaque, misconfiguration, malware |
| Trafic entre sous-réseaux non autorisés | Mouvement latéral, compromission |
| IP dans une plage réservée | Spoofing, tunnel |

---

## Exercices pratiques

### Exercice 1 : identification de classe

Déterminer la classe et le masque par défaut :

| Adresse | Classe | Masque par défaut |
|---------|--------|-------------------|
| 10.25.30.1 | A | 255.0.0.0 |
| 172.20.5.100 | B | 255.255.0.0 |
| 192.168.100.50 | C | 255.255.255.0 |
| 8.8.8.8 | A | 255.0.0.0 |
| 150.10.20.30 | B | 255.255.0.0 |

### Exercice 2 : calcul de plages

**Réseau** : 172.16.0.0/20

```
Masque : 255.255.240.0 (11111111.11111111.11110000.00000000)
Bits hôtes : 12
Nombre d'hôtes : 2^12 - 2 = 4094

Adresse réseau : 172.16.0.0
Première IP : 172.16.0.1
Dernière IP : 172.16.15.254
Broadcast : 172.16.15.255
```

### Exercice 3 : subnetting

**Objectif** : diviser 192.168.10.0/24 en 8 sous-réseaux

```
Bits à emprunter : 3 (car 2^3 = 8)
Nouveau masque : /24 + 3 = /27
Masque décimal : 255.255.255.224
Hôtes par sous-réseau : 2^5 - 2 = 30
Pas : 32

Sous-réseaux :
- 192.168.10.0/27   (0-31)
- 192.168.10.32/27  (32-63)
- 192.168.10.64/27  (64-95)
- 192.168.10.96/27  (96-127)
- 192.168.10.128/27 (128-159)
- 192.168.10.160/27 (160-191)
- 192.168.10.192/27 (192-223)
- 192.168.10.224/27 (224-255)
```

---

## Tableaux de référence rapide

### Puissances de 2

| 2^n | Valeur |
|-----|--------|
| 2^1 | 2 |
| 2^2 | 4 |
| 2^3 | 8 |
| 2^4 | 16 |
| 2^5 | 32 |
| 2^6 | 64 |
| 2^7 | 128 |
| 2^8 | 256 |
| 2^9 | 512 |
| 2^10 | 1024 |
| 2^12 | 4096 |
| 2^16 | 65536 |
| 2^24 | 16777216 |

### Tableau CIDR complet (/16 à /32)

| CIDR | Masque | Hôtes | Réseaux dans un /16 |
|------|--------|-------|---------------------|
| /16 | 255.255.0.0 | 65534 | 1 |
| /17 | 255.255.128.0 | 32766 | 2 |
| /18 | 255.255.192.0 | 16382 | 4 |
| /19 | 255.255.224.0 | 8190 | 8 |
| /20 | 255.255.240.0 | 4094 | 16 |
| /21 | 255.255.248.0 | 2046 | 32 |
| /22 | 255.255.252.0 | 1022 | 64 |
| /23 | 255.255.254.0 | 510 | 128 |
| /24 | 255.255.255.0 | 254 | 256 |
| /25 | 255.255.255.128 | 126 | 512 |
| /26 | 255.255.255.192 | 62 | 1024 |
| /27 | 255.255.255.224 | 30 | 2048 |
| /28 | 255.255.255.240 | 14 | 4096 |
| /29 | 255.255.255.248 | 6 | 8192 |
| /30 | 255.255.255.252 | 2 | 16384 |
| /31 | 255.255.255.254 | 2* | 32768 |
| /32 | 255.255.255.255 | 1 | 65536 |

*Le /31 est un cas spécial pour les liens point-à-point (RFC 3021).

---

## Ressources

### Outil local : NetProbe

L'outil NetProbe permet de valider rapidement les calculs de subnetting :

```bash
./NetProbe info 192.168.1.100/26
```

Sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv4                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 192.168.1.100/26                                          ║
║ Type             : Privée (RFC 1918)                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ INFORMATIONS RÉSEAU                                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse réseau   : 192.168.1.64                                              ║
║ Masque           : 255.255.255.192                                           ║
║ Broadcast        : 192.168.1.127                                             ║
║ Plage hôtes      : 192.168.1.65 - 192.168.1.126                              ║
║ Nb hôtes         : 62                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

Commandes disponibles :
- `./NetProbe info <ip/cidr>` : Informations complètes du réseau
- `./NetProbe classify <ip>` : Classification (public/privé, classe, type)
- `./NetProbe validate <ip>` : Validation du format
- `./NetProbe vlsm <réseau>` : Calcul VLSM interactif
- `./NetProbe supernet <réseaux...>` : Agrégation de routes

### Outils en ligne

- Calculateur de sous-réseaux : https://www.subnet-calculator.com/
- Convertisseur CIDR : https://www.ipaddressguide.com/cidr

### RFC importantes

| RFC | Sujet |
|-----|-------|
| RFC 950 | Standard du subnetting |
| RFC 1918 | Adresses privées (10.x, 172.16.x, 192.168.x) |
| RFC 4632 | CIDR |
| RFC 3021 | Utilisation du /31 |

### Commandes utiles

```bash
# Linux : afficher la configuration IP et le masque
ip addr show
ip route show

# Windows : afficher la configuration IP
ipconfig /all

# Calculer une plage avec ipcalc (Linux)
ipcalc 192.168.1.0/26

# Scanner un sous-réseau avec nmap
nmap -sn 192.168.1.0/24
```

---

## Labs TryHackMe recommandés

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Fondamentaux du networking incluant l'adressage IP | [Accéder](https://tryhackme.com/room/introtonetworking) |
| **Networking Essentials** | Concepts essentiels : IP, subnetting, routage | [Accéder](https://tryhackme.com/room/dvwa) |
| **Network Fundamentals** | Bases du réseau et modèle OSI/TCP-IP | [Accéder](https://tryhackme.com/room/whatisnetworking) |
| **Passive Reconnaissance** | Reconnaissance passive incluant l'énumération réseau | [Accéder](https://tryhackme.com/room/passiverecon) |
| **Active Reconnaissance** | Scanning et énumération de sous-réseaux | [Accéder](https://tryhackme.com/room/activerecon) |
