# Cheatsheet IPv4 - Version complète

## C'est quoi une adresse IP ?

Une adresse IP c'est 4 nombres séparés par des points :

```
185.161.233.68
```

Chaque nombre s'appelle un **octet** et va de 0 à 255.

```
Octet 1 . Octet 2 . Octet 3 . Octet 4
  185   .   161   .   233   .   68
```

---

## C'est quoi un bit ?

Un bit c'est comme un interrupteur : soit **0** (éteint), soit **1** (allumé).

Avec plusieurs bits, on peut compter :

```
1 bit  = 2 possibilités    (0, 1)
2 bits = 4 possibilités    (00, 01, 10, 11)
3 bits = 8 possibilités
4 bits = 16 possibilités
5 bits = 32 possibilités
6 bits = 64 possibilités
7 bits = 128 possibilités
8 bits = 256 possibilités  (de 0 à 255)
```

**Chaque octet = 8 bits = 256 possibilités (0 à 255)**

Une adresse IP = 4 octets = 32 bits au total.

---

## C'est quoi le /XX (CIDR) ?

Le /XX dit combien de bits sont pour le **réseau**.

```
/12 = les 12 premiers bits sont le réseau
/24 = les 24 premiers bits sont le réseau
```

Le reste des bits = les **machines** (hôtes) dans ce réseau.

---

## Comment savoir quel octet calculer ?

**Soustrais 8 jusqu'à tomber entre 0 et 8 :**

```
/12 :  12 - 8 = 4       → 4 bits dans l'octet 2
/20 :  20 - 8 - 8 = 4   → 4 bits dans l'octet 3
/27 :  27 - 8 - 8 - 8 = 3  → 3 bits dans l'octet 4
```

**Tableau récap :**

| CIDR | Octet à calculer |
|------|------------------|
| /1 à /8 | Octet 1 |
| /9 à /16 | Octet 2 |
| /17 à /24 | Octet 3 |
| /25 à /32 | Octet 4 |

---

## La table magique 

Cette table te dit la **taille du bloc** selon le nombre de bits :

```
Bits dans l'octet │ Taille du bloc │ On compte de X en X
──────────────────┼────────────────┼─────────────────────
        0         │      256       │  0, 256 (tout l'octet)
        1         │      128       │  0, 128
        2         │       64       │  0, 64, 128, 192
        3         │       32       │  0, 32, 64, 96, 128...
        4         │       16       │  0, 16, 32, 48, 64...
        5         │        8       │  0, 8, 16, 24, 32...
        6         │        4       │  0, 4, 8, 12, 16...
        7         │        2       │  0, 2, 4, 6, 8...
        8         │        1       │  0, 1, 2, 3, 4...
```

**Astuce :** Bloc = 2^(8 - bits)

---

## Trouver l'adresse réseau 

### Exemple : 185.161.233.68/12

**Étape 1 : Où coupe le /12 ?**

```
/12 = 12 bits

Octet 1 : 8 bits   → 12 - 8 = 4 restants
Octet 2 : 4 bits   → c'est ICI qu'on calcule
Octet 3 : 0 bits   → devient 0
Octet 4 : 0 bits   → devient 0
```

**Étape 2 : Que faire avec chaque octet ?**

```
185  .  161  .  233  .  68

 ↓       ↓       ↓      ↓

GARDE   CALCULE  → 0   → 0
```

**Étape 3 : Calculer l'octet 2**

4 bits = bloc de **16** (voir la table magique)

On compte de 16 en 16 pour trouver où tombe 161 :

```
0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192...
                                      │         │
                                      └── 161 ──┘
                                      est entre
                                      160 et 176
```

161 est dans le bloc qui commence à **160**.

**Étape 4 : Assembler**

```
185.160.0.0
```

---

## Formule rapide pour trouver le début du bloc

```
Début du bloc = (valeur ÷ taille) × taille
```

**Exemple : octet = 161, bloc = 16**

```
161 ÷ 16 = 10,06...
On garde que 10 (partie entière)
10 × 16 = 160
```

**Exemple : octet = 233, bloc = 32**

```
233 ÷ 32 = 7,28...
On garde que 7
7 × 32 = 224
```

---

## Trouver l'adresse broadcast

Le broadcast c'est la **dernière adresse** du bloc (juste avant le bloc suivant).

**Formule :**
```
Broadcast de l'octet = Début du bloc + Taille - 1
```

**Exemple : 185.161.233.68/12**

- Octet 2 : début = 160, taille = 16
- Broadcast octet 2 = 160 + 16 - 1 = **175**
- Octets 3 et 4 : tout à la fin = **255**

```
Réseau :    185.160.0.0
Broadcast : 185.175.255.255
```

---

## Exemples complets

### Exemple 1 : 192.168.45.130/24

**Étape 1 : Où coupe /24 ?**
```
24 - 8 - 8 - 8 = 0 bits dans l'octet 4
```
Donc : octets 1, 2, 3 = GARDE, octet 4 = calcule

**Étape 2 : 0 bits = bloc de 256**

Tout l'octet 4 devient 0 (réseau) ou 255 (broadcast).

**Réponse :**
```
Réseau :    192.168.45.0
Broadcast : 192.168.45.255
```

---

### Exemple 2 : 10.45.123.89/20

**Étape 1 : Où coupe /20 ?**
```
20 - 8 - 8 = 4 bits dans l'octet 3
```

**Étape 2 : 4 bits = bloc de 16**

Octet 3 = 123. Dans quel bloc de 16 ?
```
123 ÷ 16 = 7,68 → 7
7 × 16 = 112
```

**Étape 3 : Assembler**
```
Réseau :    10.45.112.0
Broadcast : 10.45.127.255  (112 + 16 - 1 = 127)
```

---

### Exemple 3 : 172.16.85.200/27

**Étape 1 : Où coupe /27 ?**
```
27 - 8 - 8 - 8 = 3 bits dans l'octet 4
```

**Étape 2 : 3 bits = bloc de 32**

Octet 4 = 200. Dans quel bloc de 32 ?
```
200 ÷ 32 = 6,25 → 6
6 × 32 = 192
```

**Étape 3 : Assembler**
```
Réseau :    172.16.85.192
Broadcast : 172.16.85.223  (192 + 32 - 1 = 223)
```

---

## Vérifier si une IP appartient à un réseau

**Question : 192.168.1.130 est dans 192.168.1.0/25 ?**

**Étape 1 : Trouver le bloc**
```
/25 = 25 - 8 - 8 - 8 = 1 bit dans l'octet 4
1 bit = bloc de 128
```

**Étape 2 : Quels sont les blocs possibles ?**
```
Bloc 1 : 0 à 127
Bloc 2 : 128 à 255
```

**Étape 3 : L'IP (130) est dans quel bloc ?**
```
130 est entre 128 et 255 → bloc 2
Réseau du bloc 2 = 192.168.1.128
```

**Étape 4 : Comparer**
```
Le réseau donné :    192.168.1.0   (bloc 1)
L'IP testée (130) :  192.168.1.128 (bloc 2)

Pas le même bloc → NON, l'IP n'appartient pas au réseau.
```

---

## Combien d'hôtes dans un réseau ?

**Formule :**
```
Nombre d'hôtes = Taille du bloc - 2
```

On enlève 2 parce que :
- La première adresse = réseau (pas utilisable)
- La dernière adresse = broadcast (pas utilisable)

**Exemples :**

| CIDR | Bloc | Hôtes |
|------|------|-------|
| /24 | 256 | 254 |
| /25 | 128 | 126 |
| /26 | 64 | 62 |
| /27 | 32 | 30 |
| /28 | 16 | 14 |
| /29 | 8 | 6 |
| /30 | 4 | 2 |

---

## Diviser un réseau en sous-réseaux (subnetting)

**Question : Diviser 192.168.1.0/24 en 4 sous-réseaux**

**Étape 1 : Combien de bits pour faire X sous-réseaux ?**

On "emprunte" des bits aux hôtes pour créer des sous-réseaux.

```
Bits empruntés │ Sous-réseaux créés
───────────────┼────────────────────
      1        │   2
      2        │   4
      3        │   8
      4        │  16
      5        │  32
```

Pour 4 sous-réseaux → 2 bits (2² = 4)

**Étape 2 : Nouveau préfixe**
```
/24 + 2 bits empruntés = /26
```

**Étape 3 : Taille des nouveaux blocs**
```
/26 = 26 - 8 - 8 - 8 = 2 bits dans l'octet 4
2 bits = bloc de 64
```

**Étape 4 : Lister les sous-réseaux**
```
Sous-réseau 1 : 192.168.1.0/26    (0 à 63)     → 62 hôtes
Sous-réseau 2 : 192.168.1.64/26   (64 à 127)   → 62 hôtes
Sous-réseau 3 : 192.168.1.128/26  (128 à 191)  → 62 hôtes
Sous-réseau 4 : 192.168.1.192/26  (192 à 255)  → 62 hôtes
```

---

## Regrouper des réseaux en un seul (supernetting)

C'est l'inverse du subnetting : on fusionne plusieurs petits réseaux en un seul plus grand.

**Question : Regrouper ces 4 réseaux en un supernet**
```
192.168.44.0/24
192.168.45.0/24
192.168.46.0/24
192.168.47.0/24
```

**Étape 1 : Combien de réseaux à regrouper ?**

On "rend" des bits au réseau pour fusionner.

```
Réseaux à fusionner │ Bits à rendre
────────────────────┼───────────────
        2           │      1
        4           │      2
        8           │      3
       16           │      4
       32           │      5
```

4 réseaux = 2² → 2 bits à rendre

**Étape 2 : Nouveau préfixe**
```
/24 - 2 bits rendus = /22
```

**Étape 3 : Vérifier que les réseaux sont contigus**

Avec /22, les blocs sont de 4 sur le 3e octet.

Le premier réseau (44) doit être au début d'un bloc :
```
44 ÷ 4 = 11 pile → OK, 44 est bien le début d'un bloc
```

Le bloc 44 couvre : 44, 45, 46, 47 → ça correspond !

**Réponse :**
```
Supernet : 192.168.44.0/22
```

---

### Exemple supernetting avec 8 réseaux

**Question : Regrouper ces 8 réseaux**
```
172.16.32.0/24  à  172.16.39.0/24
```

**Étape 1 :** 8 réseaux = 2³ → 3 bits à rendre

**Étape 2 :** /24 - 3 = /21

**Étape 3 :** Avec /21, blocs de 8. Le premier réseau (32) :
```
32 ÷ 8 = 4 pile → OK
```

**Réponse :**
```
Supernet : 172.16.32.0/21
```

---

## Récap subnetting vs supernetting

| Action | Opération | Ce qui change |
|--------|-----------|---------------|
| Subnetting (découper) | On emprunte des bits | Le masque augmente (/24 → /26) |
| Supernetting (regrouper) | On rend des bits | Le masque diminue (/24 → /22) |

---

## Classes historiques (pour la culture)

Avant, on n'utilisait pas /XX. On avait des "classes" :

| Premier octet | Classe | Masque par défaut |
|---------------|--------|-------------------|
| 0 à 127 | A | /8 |
| 128 à 191 | B | /16 |
| 192 à 223 | C | /24 |

**Exemple :**
- 10.x.x.x → Classe A → /8
- 172.16.x.x → Classe B → /16
- 192.168.x.x → Classe C → /24

---

## Adresses spéciales à connaître

| Plage | C'est quoi ? |
|-------|--------------|
| 10.0.0.0/8 | Privé (maison, entreprise) |
| 172.16.0.0/12 | Privé |
| 192.168.0.0/16 | Privé |
| 127.0.0.1 | Localhost (toi-même) |
| 169.254.x.x | Pas de DHCP (erreur) |

---

## Checklist pour chaque exercice

### Trouver l'adresse réseau :

```
□ Étape 1 : Soustraire 8, 8, 8... pour trouver l'octet à calculer
□ Étape 2 : Regarder la table → taille du bloc
□ Étape 3 : Diviser l'octet par le bloc, garder la partie entière
□ Étape 4 : Multiplier par le bloc = début du bloc
□ Étape 5 : Les octets après = 0
```

### Trouver le broadcast :

```
□ Même chose que réseau, mais :
□ Octet calculé = début + taille - 1
□ Les octets après = 255
```

### Vérifier l'appartenance :

```
□ Calculer le réseau de l'IP testée
□ Comparer avec le réseau donné
□ Pareil = OUI, Différent = NON
```

### Diviser en sous-réseaux (subnetting) :

```
□ Combien de sous-réseaux ? → Combien de bits emprunter ?
□ Nouveau masque = ancien + bits empruntés
□ Calculer la nouvelle taille de bloc
□ Lister les sous-réseaux de X en X
```

### Regrouper des réseaux (supernetting) :

```
□ Combien de réseaux à fusionner ? → Combien de bits rendre ?
□ Nouveau masque = ancien - bits rendus
□ Calculer la nouvelle taille de bloc
□ Vérifier que le 1er réseau est au début d'un bloc (divisible par taille)
□ Vérifier que tous les réseaux sont contigus
```

---

## Exercices pour s'entraîner

### 1. Trouve l'adresse réseau :

- 10.200.50.100/8
- 172.20.100.200/16
- 192.168.10.150/24
- 10.50.200.75/12
- 172.16.130.50/20

### 2. Trouve le broadcast :

- 192.168.1.0/26
- 10.0.0.0/12
- 172.20.53.180/22

### 3. L'IP appartient-elle au réseau ?

- 192.168.1.200 dans 192.168.1.0/25 ?
- 10.10.50.100 dans 10.10.48.0/22 ?

### 4. Divise en sous-réseaux :

- 10.0.0.0/8 en 16 sous-réseaux
- 192.168.50.0/24 en 8 sous-réseaux

### 5. Trouve le supernet :

- 10.20.16.0/24 à 10.20.19.0/24 (4 réseaux)
- 172.16.32.0/24 à 172.16.39.0/24 (8 réseaux)

---

## Réponses

### 1. Adresses réseau :
- 10.200.50.100/8 → 10.0.0.0
- 172.20.100.200/16 → 172.20.0.0
- 192.168.10.150/24 → 192.168.10.0
- 10.50.200.75/12 → 10.48.0.0 (50÷16=3, 3×16=48)
- 172.16.130.50/20 → 172.16.128.0 (130÷16=8, 8×16=128)

### 2. Broadcasts :
- 192.168.1.0/26 → 192.168.1.63 (bloc 64, 0+64-1=63)
- 10.0.0.0/12 → 10.15.255.255 (bloc 16, 0+16-1=15)
- 172.20.53.180/22 → 172.20.55.255 (bloc 4, 52+4-1=55)

### 3. Appartenance :
- 192.168.1.200 dans /25 ? Bloc=128. 200 est dans 128-255. Réseau=192.168.1.128 ≠ .0 → **NON**
- 10.10.50.100 dans 10.10.48.0/22 ? Bloc=4. 50÷4=12, 12×4=48. Réseau=10.10.48.0 → **OUI**

### 4. Sous-réseaux :
- 10.0.0.0/8 en 16 → 4 bits empruntés → /12, blocs de 16 sur octet 2
  - 10.0.0.0/12, 10.16.0.0/12, 10.32.0.0/12... jusqu'à 10.240.0.0/12
- 192.168.50.0/24 en 8 → 3 bits empruntés → /27, blocs de 32
  - 192.168.50.0/27, .32/27, .64/27, .96/27, .128/27, .160/27, .192/27, .224/27

### 5. Supernets :
- 10.20.16.0/24 à .19 → 4 réseaux = 2 bits → /22. 16÷4=4 pile → **10.20.16.0/22**
- 172.16.32.0/24 à .39 → 8 réseaux = 3 bits → /21. 32÷8=4 pile → **172.16.32.0/21**
