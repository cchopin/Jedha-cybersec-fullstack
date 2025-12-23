# Subnetting avancé et planification d'adresses

## Objectifs du cours

Ce cours approfondit les bases du subnetting (voir cours 03 et 10) avec des concepts avancés pour la gestion professionnelle des réseaux :

- **CIDR** : allocation flexible de l'espace d'adressage
- **VLSM** : masques de taille variable pour optimiser l'utilisation des adresses
- **Supernetting** : agrégation de routes pour simplifier les tables de routage

Compétences visées :
- Calculer rapidement le nombre d'hôtes et de sous-réseaux
- Allouer des adresses de manière optimale avec VLSM
- Regrouper plusieurs réseaux en un supernet
- Utiliser l'outil NetProbe pour automatiser ces calculs

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **CIDR** | Classless Inter-Domain Routing - Notation moderne des réseaux (/24) |
| **VLSM** | Variable Length Subnet Mask - Masques de taille variable dans un même réseau |
| **Supernetting** | Regroupement de plusieurs réseaux en un seul plus grand |
| **Route Summarization** | Synonyme de supernetting - résumer plusieurs routes en une seule |
| **RFC 1918** | Standard définissant les plages d'adresses IP privées |
| **Prefix** | Nombre de bits réseau dans la notation CIDR (le /XX) |

---

## Rappel : la table magique

Cette table est l'outil principal pour le subnetting :

```
Bits dans l'octet │ Taille du bloc │ On compte de X en X │ Hôtes utilisables
──────────────────┼────────────────┼─────────────────────┼───────────────────
        0         │      256       │  0, 256             │      254
        1         │      128       │  0, 128             │      126
        2         │       64       │  0, 64, 128, 192    │       62
        3         │       32       │  0, 32, 64, 96...   │       30
        4         │       16       │  0, 16, 32, 48...   │       14
        5         │        8       │  0, 8, 16, 24...    │        6
        6         │        4       │  0, 4, 8, 12...     │        2
        7         │        2       │  0, 2, 4, 6...      │        0
        8         │        1       │  0, 1, 2, 3...      │        0
```

**Formules rapides :**
- Bloc = 2^(8 - bits dans l'octet)
- Hôtes = Bloc - 2

---

## CIDR : allocation flexible de l'espace d'adressage

### Pourquoi CIDR ?

L'ancien système par classes (A, B, C) était rigide :
- Classe A : /8 = 16 millions d'adresses (trop grand pour 99% des besoins)
- Classe C : /24 = 254 adresses (trop petit pour beaucoup d'entreprises)

**CIDR permet n'importe quel préfixe** de /1 à /32, offrant une granularité fine.

### Tableau récapitulatif CIDR

| CIDR | Masque | Bloc | Hôtes | Usage typique |
|------|--------|------|-------|---------------|
| /8 | 255.0.0.0 | 16M | 16 777 214 | FAI, très grands réseaux |
| /16 | 255.255.0.0 | 65K | 65 534 | Campus, grandes entreprises |
| /20 | 255.255.240.0 | 4K | 4 094 | Data centers |
| /22 | 255.255.252.0 | 1K | 1 022 | Moyennes entreprises |
| /24 | 255.255.255.0 | 256 | 254 | PME, départements |
| /26 | 255.255.255.192 | 64 | 62 | Petits bureaux |
| /27 | 255.255.255.224 | 32 | 30 | Très petits réseaux |
| /28 | 255.255.255.240 | 16 | 14 | DMZ, serveurs |
| /29 | 255.255.255.248 | 8 | 6 | Liens inter-sites |
| /30 | 255.255.255.252 | 4 | 2 | Liens point-à-point |
| /32 | 255.255.255.255 | 1 | 1 | Hôte unique (loopback) |

### Méthode de calcul rapide

**Question :** Combien d'hôtes dans un /20 ?

```
Étape 1 : Combien de bits hôtes ?
   32 - 20 = 12 bits

Étape 2 : Combien d'adresses ?
   2^12 = 4096 adresses

Étape 3 : Combien d'hôtes utilisables ?
   4096 - 2 = 4094 hôtes

(On enlève 2 pour le réseau et le broadcast)
```

**Question :** Quel masque pour au moins 500 hôtes ?

```
Étape 1 : Combien de bits hôtes minimum ?
   2^8 = 256   → pas assez
   2^9 = 512   → suffisant !
   → Il faut 9 bits hôtes

Étape 2 : Quel préfixe ?
   32 - 9 = /23

Étape 3 : Vérification
   /23 = 255.255.254.0 → 510 hôtes utilisables ✓
```

### Vérification avec NetProbe

L'outil NetProbe permet de valider rapidement les calculs :

```bash
./NetProbe info 10.0.0.45/20
```

Exemple de sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ANALYSE IPv4                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse saisie   : 10.0.0.45/20                                              ║
║ Type             : Privée (RFC 1918)                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ INFORMATIONS RÉSEAU                                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Adresse réseau   : 10.0.0.0                                                  ║
║ Masque           : 255.255.240.0                                             ║
║ Broadcast        : 10.0.15.255                                               ║
║ Plage hôtes      : 10.0.0.1 - 10.0.15.254                                    ║
║ Nb hôtes         : 4094                                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## VLSM : Variable Length Subnet Masking

### Le problème du subnetting classique

Avec le subnetting classique, **tous les sous-réseaux ont la même taille**. C'est du gaspillage !

**Exemple :** Le réseau 192.168.1.0/24 doit être divisé en 4 sous-réseaux pour :
- IT : 50 machines
- HR : 25 machines
- Sales : 10 machines
- Logistics : 5 machines

Avec le subnetting classique (4 sous-réseaux = /26 = 62 hôtes chacun) :

```
Sous-réseau 1 : 62 places pour 50 machines → 12 adresses gaspillées
Sous-réseau 2 : 62 places pour 25 machines → 37 adresses gaspillées
Sous-réseau 3 : 62 places pour 10 machines → 52 adresses gaspillées
Sous-réseau 4 : 62 places pour  5 machines → 57 adresses gaspillées
                                            ─────────────────────────
                                    Total : 158 adresses gaspillées !
```

### La solution : VLSM

Avec VLSM, **chaque sous-réseau a la taille adaptée à ses besoins**.

### Méthode VLSM pas à pas

**Règle d'or :** Toujours allouer du **plus grand au plus petit** pour éviter les trous.

**Étape 1 : Lister les besoins et trouver le bon préfixe**

| Département | Machines | Bits nécessaires | Préfixe | Hôtes réels |
|-------------|----------|------------------|---------|-------------|
| IT | 50 | 6 bits (2^6 = 64) | /26 | 62 |
| HR | 25 | 5 bits (2^5 = 32) | /27 | 30 |
| Sales | 10 | 4 bits (2^4 = 16) | /28 | 14 |
| Logistics | 5 | 3 bits (2^3 = 8) | /29 | 6 |

**Comment trouver le préfixe ?**
```
Machines + 2 (réseau + broadcast) ≤ 2^bits

Pour IT (50 machines) :
  50 + 2 = 52 adresses minimum
  2^5 = 32 → pas assez
  2^6 = 64 → suffisant !
  → 6 bits hôtes → /26 (32 - 6 = 26)
```

**Étape 2 : Trier du plus grand au plus petit**

```
1. IT        : /26 (bloc de 64)
2. HR        : /27 (bloc de 32)
3. Sales     : /28 (bloc de 16)
4. Logistics : /29 (bloc de 8)
```

**Étape 3 : Allouer séquentiellement à partir de 192.168.1.0**

```
┌─────────────────────────────────────────────────────────────────────┐
│                        192.168.1.0/24                               │
│    0                   64       96   112 120                  255   │
│    │────── IT ─────────│── HR ──│─S──│─L─│     (libre)         │   │
│    │       /26         │  /27   │/28 │/29│                     │   │
└─────────────────────────────────────────────────────────────────────┘

IT        : 192.168.1.0/26    (0 à 63)     → 62 hôtes
HR        : 192.168.1.64/27   (64 à 95)    → 30 hôtes
Sales     : 192.168.1.96/28   (96 à 111)   → 14 hôtes
Logistics : 192.168.1.112/29  (112 à 119)  → 6 hôtes
```

**Étape 4 : Calculer les détails de chaque sous-réseau**

| Département | Réseau | Masque | Broadcast | Plage hôtes | Hôtes |
|-------------|--------|--------|-----------|-------------|-------|
| IT | 192.168.1.0/26 | 255.255.255.192 | 192.168.1.63 | .1 à .62 | 62 |
| HR | 192.168.1.64/27 | 255.255.255.224 | 192.168.1.95 | .65 à .94 | 30 |
| Sales | 192.168.1.96/28 | 255.255.255.240 | 192.168.1.111 | .97 à .110 | 14 |
| Logistics | 192.168.1.112/29 | 255.255.255.248 | 192.168.1.119 | .113 à .118 | 6 |

**Résultat :** Seulement 120 adresses utilisées sur 256, il reste de la place pour grandir !

### Avec NetProbe

L'outil NetProbe automatise ce calcul :

```bash
./NetProbe vlsm 192.168.1.0/24
```

Exemple de sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           VLSM - 192.168.1.0/24                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Nombre de départements: 4                                                    ║
║                                                                              ║
║ Département 1: IT, 50 devices                                                ║
║ Département 2: HR, 25 devices                                                ║
║ Département 3: Sales, 10 devices                                             ║
║ Département 4: Logistics, 5 devices                                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ RÉSULTAT VLSM                                                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  #  │ Département  │ Réseau              │ Masque          │ Hôtes │ Demandé ║
║─────┼──────────────┼─────────────────────┼─────────────────┼───────┼─────────║
║  1  │ IT           │ 192.168.1.0/26      │ 255.255.255.192 │   62  │   50    ║
║  2  │ HR           │ 192.168.1.64/27     │ 255.255.255.224 │   30  │   25    ║
║  3  │ Sales        │ 192.168.1.96/28     │ 255.255.255.240 │   14  │   10    ║
║  4  │ Logistics    │ 192.168.1.112/29    │ 255.255.255.248 │    6  │    5    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Efficacité: 90 adresses demandées / 112 allouées = 80.4%                     ║
║ Espace libre: 192.168.1.120 - 192.168.1.255 (136 adresses)                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Supernetting : agrégation de routes

### Pourquoi le supernetting ?

Dans les grands réseaux, les tables de routage peuvent devenir énormes. **Chaque route consomme de la mémoire et du temps de traitement**.

Le supernetting permet de **regrouper plusieurs petits réseaux en un seul grand**, réduisant ainsi la taille de la table de routage.

### Exemple concret

Imaginons ces 4 réseaux dans une table de routage :

```
192.168.0.0/24   →  Interface Fa0/0
192.168.1.0/24   →  Interface Fa0/0
192.168.2.0/24   →  Interface Fa0/0
192.168.3.0/24   →  Interface Fa0/0
```

**Problème :** 4 entrées pour la même interface !

**Solution :** Un seul supernet qui couvre les 4 :

```
192.168.0.0/22   →  Interface Fa0/0
```

### Comment trouver le supernet ?

#### Méthode 1 : La méthode des bits communs (théorique)

**Étape 1 : Écrire les adresses en binaire (3ème octet)**

```
192.168.0.0 → octet 3 = 00000000
192.168.1.0 → octet 3 = 00000001
192.168.2.0 → octet 3 = 00000010
192.168.3.0 → octet 3 = 00000011
               ──────────────────
               000000XX
               ↑     ↑
               │     └── Ces 2 bits varient
               └──────── Ces 6 bits sont communs
```

**Étape 2 : Compter les bits communs**

```
Octet 1 : 8 bits communs (192)
Octet 2 : 8 bits communs (168)
Octet 3 : 6 bits communs (les 2 derniers varient)

Total : 8 + 8 + 6 = 22 bits
→ Nouveau préfixe : /22
```

**Étape 3 : Calculer le masque**

```
/22 = 255.255.252.0

Le supernet est : 192.168.0.0/22
```

#### Méthode 2 : La méthode rapide avec la table magique

C'est la méthode de la cheatsheet, appliquée à l'inverse !

**Étape 1 : Combien de réseaux à regrouper ?**

```
4 réseaux = 2² → 2 bits à "rendre"
```

**Étape 2 : Calculer le nouveau préfixe**

```
Préfixe original : /24
Bits rendus : 2
Nouveau préfixe : /24 - 2 = /22
```

**Étape 3 : Vérifier l'alignement**

Avec /22, les blocs sont de **4** sur le 3ème octet (2² = 4).

Le premier réseau doit être **au début d'un bloc** :

```
0 ÷ 4 = 0 (pile !)  → OK, 192.168.0.0 est bien le début d'un bloc

Les blocs /22 sont : 0, 4, 8, 12, 16...
Le bloc commençant à 0 couvre : 0, 1, 2, 3 ✓
```

**Résultat :** `192.168.0.0/22`

### Tableau récapitulatif : combien de réseaux → combien de bits

| Réseaux /24 à fusionner | Bits à rendre | Nouveau préfixe | Bloc sur l'octet 3 |
|-------------------------|---------------|-----------------|-------------------|
| 2 | 1 | /23 | 2 |
| 4 | 2 | /22 | 4 |
| 8 | 3 | /21 | 8 |
| 16 | 4 | /20 | 16 |
| 32 | 5 | /19 | 32 |
| 64 | 6 | /18 | 64 |
| 128 | 7 | /17 | 128 |
| 256 | 8 | /16 | 256 |

### Vérifier que les réseaux sont contigus

**Important :** On ne peut supernetiser que des réseaux **contigus** et **alignés** !

**Exemple valide :**
```
192.168.0.0/24, 192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24
→ 4 réseaux contigus, débutant à 0 (multiple de 4)
→ Supernet : 192.168.0.0/22 ✓
```

**Exemple invalide :**
```
192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24, 192.168.4.0/24
→ 4 réseaux contigus MAIS débutant à 1 (pas un multiple de 4 !)
→ Impossible de les supernetiser en un seul /22

Vérification : 1 ÷ 4 = 0,25 (pas pile !) → NON aligné
```

**Solution pour les réseaux non alignés :** Il faudrait un /21 (bloc de 8) pour englober 1-4, mais ce serait du gaspillage.

### Avec NetProbe

L'outil NetProbe calcule automatiquement le supernet :

```bash
./NetProbe supernet 192.168.0.0/24 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24
```

Exemple de sortie :
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              SUPERNETTING                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Réseaux à agréger:                                                           ║
║   • 192.168.0.0/24                                                           ║
║   • 192.168.1.0/24                                                           ║
║   • 192.168.2.0/24                                                           ║
║   • 192.168.3.0/24                                                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ RÉSULTAT                                                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Super-réseau : 192.168.0.0/22                                                ║
║ Masque       : 255.255.252.0                                                 ║
║ Hôtes        : 1022                                                          ║
║ Broadcast    : 192.168.3.255                                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ ✓ Tous les réseaux originaux sont couverts par ce supernet                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

Pour une utilisation interactive :
```bash
./NetProbe supernet
# L'outil demande les réseaux un par un
```

---

## Récapitulatif : Subnetting vs Supernetting

| Opération | Ce qu'on fait | Le masque | Exemple |
|-----------|---------------|-----------|---------|
| **Subnetting** | On **divise** un réseau | **Augmente** (ex: /24 → /26) | 192.168.1.0/24 → 4 x /26 |
| **Supernetting** | On **regroupe** des réseaux | **Diminue** (ex: /24 → /22) | 4 x /24 → 192.168.0.0/22 |

**Moyen mnémotechnique :**
- **Sub**netting = **Sou**s-réseaux = on **découpe** = masque plus **grand**
- **Super**netting = réseau plus **grand** = masque plus **petit**

---

## Standards et réglementations

### RFC importantes

| RFC | Sujet | Résumé |
|-----|-------|--------|
| **RFC 1918** | Adresses privées | Définit 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
| **RFC 4632** | CIDR | Définit la méthodologie CIDR |
| **RFC 2050** | Allocation d'IP | Politiques d'allocation des adresses |
| **RFC 4291** | IPv6 | Adressage IPv6 (128 bits) |

### Plages privées (RFC 1918) - À connaître par cœur

| Plage | Classe historique | CIDR | Nombre d'adresses |
|-------|-------------------|------|-------------------|
| 10.0.0.0 - 10.255.255.255 | A | /8 | 16 777 216 |
| 172.16.0.0 - 172.31.255.255 | B | /12 | 1 048 576 |
| 192.168.0.0 - 192.168.255.255 | C | /16 | 65 536 |

Ces adresses **ne sont jamais routées sur Internet**. Utilisez-les librement dans vos réseaux internes !

---

## Exercices pratiques

### Exercice 1 : Calcul CIDR

Déterminez le nombre d'hôtes utilisables pour chaque préfixe :

| CIDR | Bits hôtes | Total adresses | Hôtes utilisables |
|------|------------|----------------|-------------------|
| /19 | ? | ? | ? |
| /23 | ? | ? | ? |
| /25 | ? | ? | ? |
| /28 | ? | ? | ? |

<details>
<summary>Réponses</summary>

| CIDR | Bits hôtes | Total adresses | Hôtes utilisables |
|------|------------|----------------|-------------------|
| /19 | 13 (32-19) | 8 192 | 8 190 |
| /23 | 9 (32-23) | 512 | 510 |
| /25 | 7 (32-25) | 128 | 126 |
| /28 | 4 (32-28) | 16 | 14 |

</details>

### Exercice 2 : VLSM

Réseau disponible : `10.0.0.0/24`

Besoins :
- Administration : 100 postes
- Développement : 50 postes
- Marketing : 25 postes
- Direction : 10 postes
- Lien WAN : 2 adresses

Calculez l'allocation VLSM optimale.

<details>
<summary>Réponse</summary>

**Tri par taille décroissante et calcul des préfixes :**

| Département | Besoins | Préfixe | Bloc |
|-------------|---------|---------|------|
| Administration | 100 | /25 (126 hôtes) | 128 |
| Développement | 50 | /26 (62 hôtes) | 64 |
| Marketing | 25 | /27 (30 hôtes) | 32 |
| Direction | 10 | /28 (14 hôtes) | 16 |
| Lien WAN | 2 | /30 (2 hôtes) | 4 |

**Allocation :**

| Département | Réseau | Plage | Broadcast |
|-------------|--------|-------|-----------|
| Administration | 10.0.0.0/25 | 10.0.0.1 - 10.0.0.126 | 10.0.0.127 |
| Développement | 10.0.0.128/26 | 10.0.0.129 - 10.0.0.190 | 10.0.0.191 |
| Marketing | 10.0.0.192/27 | 10.0.0.193 - 10.0.0.222 | 10.0.0.223 |
| Direction | 10.0.0.224/28 | 10.0.0.225 - 10.0.0.238 | 10.0.0.239 |
| Lien WAN | 10.0.0.240/30 | 10.0.0.241 - 10.0.0.242 | 10.0.0.243 |

**Espace utilisé :** 244 adresses sur 256 (95%)
**Espace libre :** 10.0.0.244 - 10.0.0.255 (12 adresses)

</details>

### Exercice 3 : Supernetting

Trouvez le supernet pour ces réseaux :

**Groupe A :**
```
172.16.32.0/24
172.16.33.0/24
172.16.34.0/24
172.16.35.0/24
172.16.36.0/24
172.16.37.0/24
172.16.38.0/24
172.16.39.0/24
```

**Groupe B :**
```
10.20.16.0/24
10.20.17.0/24
10.20.18.0/24
10.20.19.0/24
```

<details>
<summary>Réponses</summary>

**Groupe A :** 8 réseaux
```
8 réseaux = 2³ → 3 bits à rendre
Nouveau préfixe : /24 - 3 = /21
Vérification : 32 ÷ 8 = 4 (pile !) ✓

Supernet : 172.16.32.0/21
```

**Groupe B :** 4 réseaux
```
4 réseaux = 2² → 2 bits à rendre
Nouveau préfixe : /24 - 2 = /22
Vérification : 16 ÷ 4 = 4 (pile !) ✓

Supernet : 10.20.16.0/22
```

</details>

---

## Checklist de calcul

### Pour VLSM :
```
□ Lister tous les besoins en hôtes
□ Pour chaque besoin : trouver le plus petit bloc suffisant (≥ besoins + 2)
□ Trier du plus grand au plus petit
□ Allouer séquentiellement depuis l'adresse de base
□ Vérifier que tout rentre dans le réseau disponible
```

### Pour Supernetting :
```
□ Compter le nombre de réseaux à fusionner
□ Trouver la puissance de 2 correspondante (ex: 4 = 2²)
□ Nouveau préfixe = ancien - exposant (ex: /24 - 2 = /22)
□ Vérifier l'alignement : premier réseau ÷ bloc = nombre entier ?
□ Vérifier la contiguïté : tous les réseaux se suivent-ils ?
```

---

## Ressources

| Ressource | Lien/Commande |
|-----------|---------------|
| NetProbe (outil local) | `./NetProbe vlsm` ou `./NetProbe supernet` |
| Calculateur CIDR | https://www.ipaddressguide.com/cidr |
| Calculateur VLSM | https://www.subnet-calculator.com/vlsm.php |
| RFC 1918 (adresses privées) | https://datatracker.ietf.org/doc/html/rfc1918 |
| RFC 4632 (CIDR) | https://datatracker.ietf.org/doc/html/rfc4632 |
