# Cheatsheet IPv4 - Calculs Reseau

## Table des puissances de 2

```
Position:    8     7     6     5     4    3    2    1
Valeur:    128    64    32    16     8    4    2    1
```

| Puissance | 2^0 | 2^1 | 2^2 | 2^3 | 2^4 | 2^5 | 2^6 | 2^7 | 2^8 | 2^9 | 2^10 |
|-----------|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|------|
| Valeur    | 1   | 2   | 4   | 8   | 16  | 32  | 64  | 128 | 256 | 512 | 1024 |

---

## Conversion Decimal → Binaire

**Methode : Soustraire les puissances de 2**

Pour convertir un nombre (0-255) en binaire sur 8 bits :

```
Valeurs: 128  64  32  16   8   4   2   1
```

**Exemple : 197 → binaire**

```
197 >= 128 ? OUI → 1, reste 197-128 = 69
 69 >=  64 ? OUI → 1, reste  69-64  =  5
  5 >=  32 ? NON → 0
  5 >=  16 ? NON → 0
  5 >=   8 ? NON → 0
  5 >=   4 ? OUI → 1, reste   5-4   =  1
  1 >=   2 ? NON → 0
  1 >=   1 ? OUI → 1, reste   1-1   =  0

Resultat: 11000101
```

**Exemple : 45 → binaire**

```
45 >= 128 ? NON → 0
45 >=  64 ? NON → 0
45 >=  32 ? OUI → 1, reste 45-32 = 13
13 >=  16 ? NON → 0
13 >=   8 ? OUI → 1, reste 13-8  =  5
 5 >=   4 ? OUI → 1, reste  5-4  =  1
 1 >=   2 ? NON → 0
 1 >=   1 ? OUI → 1, reste  1-1  =  0

Resultat: 00101101
```

---

## Conversion Binaire → Decimal

**Methode : Additionner les valeurs des bits a 1**

```
Binaire:   1  0  1  1  0  1  0  0
Valeurs: 128 64 32 16  8  4  2  1
           ↓     ↓  ↓     ↓
         128 +  32+16 +  4      = 180
```

**Exemple : 11001010**

```
1   1   0   0   1   0   1   0
128 64  32  16  8   4   2   1
↓   ↓           ↓       ↓
128+64        + 8   +   2   = 202
```

---

## Table des masques CIDR

| CIDR | Masque | Binaire (dernier octet) | Bloc | Hotes | Usage |
|------|--------|-------------------------|------|-------|-------|
| /32 | 255.255.255.255 | 11111111 | 1 | 1 | Host route |
| /31 | 255.255.255.254 | 11111110 | 2 | 2 | Point-to-point |
| /30 | 255.255.255.252 | 11111100 | 4 | 2 | Point-to-point |
| /29 | 255.255.255.248 | 11111000 | 8 | 6 | Petit reseau |
| /28 | 255.255.255.240 | 11110000 | 16 | 14 | Petit reseau |
| /27 | 255.255.255.224 | 11100000 | 32 | 30 | Petit reseau |
| /26 | 255.255.255.192 | 11000000 | 64 | 62 | Moyen |
| /25 | 255.255.255.128 | 10000000 | 128 | 126 | Moyen |
| /24 | 255.255.255.0 | 00000000 | 256 | 254 | Standard |
| /23 | 255.255.254.0 | - | 512 | 510 | |
| /22 | 255.255.252.0 | - | 1024 | 1022 | |
| /21 | 255.255.248.0 | - | 2048 | 2046 | |
| /20 | 255.255.240.0 | - | 4096 | 4094 | |
| /16 | 255.255.0.0 | - | 65536 | 65534 | Classe B |
| /8 | 255.0.0.0 | - | 16M | 16M-2 | Classe A |

**Formules :**
- Taille du bloc = 256 - valeur du masque (pour le dernier octet non-255)
- Nombre d'hotes = 2^(32-prefix) - 2

---

## Valeurs magiques des masques

Pour le dernier octet significatif du masque :

| Valeur masque | CIDR (si 4e octet) | Bloc |
|---------------|-------------------|------|
| 0 | /24 | 256 |
| 128 | /25 | 128 |
| 192 | /26 | 64 |
| 224 | /27 | 32 |
| 240 | /28 | 16 |
| 248 | /29 | 8 |
| 252 | /30 | 4 |
| 254 | /31 | 2 |
| 255 | /32 | 1 |

**Astuce :** Bloc = 256 - masque

```
/26 → masque 192 → bloc = 256 - 192 = 64
/27 → masque 224 → bloc = 256 - 224 = 32
```

---

## Calcul de l'adresse reseau

**Formule : IP AND Masque**

**Operation AND bit a bit :**
```
1 AND 1 = 1
1 AND 0 = 0
0 AND 1 = 0
0 AND 0 = 0
```

**Exemple : 192.168.45.130/26**

1. Masque /26 = 255.255.255.192
2. Calcul octet par octet :

```
Octet 1: 192 AND 255 = 192
Octet 2: 168 AND 255 = 168
Octet 3:  45 AND 255 = 45
Octet 4: 130 AND 192 = ?
```

3. Detail octet 4 :
```
130 = 10000010
192 = 11000000
AND = 10000000 = 128
```

**Adresse reseau = 192.168.45.128**

### Methode rapide (sans binaire)

Pour /26 (bloc de 64), les adresses reseau sont : 0, 64, 128, 192
→ 130 est dans le bloc qui commence a 128

---

## Calcul de l'adresse broadcast

**Formule : Adresse reseau + (Taille bloc - 1)**

Ou : Mettre tous les bits hote a 1

**Exemple : 192.168.45.128/26**

- Bloc = 64
- Broadcast = 128 + 64 - 1 = **191**
- Adresse broadcast = 192.168.45.191

**Plage complete :**
```
Reseau:    192.168.45.128  (reserve)
Premier:   192.168.45.129
Dernier:   192.168.45.190
Broadcast: 192.168.45.191  (reserve)
```

---

## Verifier si une IP appartient a un reseau

**Methode : Calculer l'adresse reseau de l'IP et comparer**

**Exemple : 10.45.67.89 appartient a 10.45.64.0/22 ?**

1. Masque /22 = 255.255.252.0 (bloc de 4 sur 3e octet)
2. Calculer 67 AND 252 :
```
 67 = 01000011
252 = 11111100
AND = 01000000 = 64
```
3. Reseau de l'IP = 10.45.64.0
4. Compare avec 10.45.64.0 → **IDENTIQUE = OUI**

**Exemple : 10.45.70.89 appartient a 10.45.64.0/22 ?**

1. Calculer 70 AND 252 :
```
 70 = 01000110
252 = 11111100
AND = 01000100 = 68
```
2. Reseau de l'IP = 10.45.68.0
3. Compare avec 10.45.64.0 → **DIFFERENT = NON**

### Methode rapide

Pour /22 (bloc de 4 sur 3e octet) :
- Reseaux possibles : .0, .4, .8, .12, .16... .64, .68, .72...
- 67 est dans le bloc 64-67
- 70 est dans le bloc 68-71

---

## Classes historiques (Classful)

| Classe | Premier octet | Masque par defaut | Bits de depart |
|--------|---------------|-------------------|----------------|
| A | 0 - 127 | /8 (255.0.0.0) | 0xxxxxxx |
| B | 128 - 191 | /16 (255.255.0.0) | 10xxxxxx |
| C | 192 - 223 | /24 (255.255.255.0) | 110xxxxx |
| D | 224 - 239 | Multicast | 1110xxxx |
| E | 240 - 255 | Reserve | 1111xxxx |

**Astuce rapide :**
```
< 128      → Classe A → /8
128 - 191  → Classe B → /16
192 - 223  → Classe C → /24
```

---

## Adresses speciales

| Plage | Type | Usage |
|-------|------|-------|
| 10.0.0.0/8 | Prive | Classe A privee |
| 172.16.0.0/12 | Prive | Classe B privee (172.16-31.x.x) |
| 192.168.0.0/16 | Prive | Classe C privee |
| 127.0.0.0/8 | Loopback | Interface locale (127.0.0.1) |
| 169.254.0.0/16 | Link-local | APIPA (auto-config sans DHCP) |
| 224.0.0.0/4 | Multicast | Diffusion groupe |
| 255.255.255.255 | Broadcast | Broadcast limite |

---

## Division en sous-reseaux (Subnetting)

**Pour diviser un reseau en N sous-reseaux :**

1. Trouver combien de bits emprunter : 2^n >= N
2. Nouveau prefix = ancien prefix + n
3. Taille de chaque bloc = 2^(32 - nouveau prefix)

**Exemple : Diviser 192.168.1.0/24 en 4 sous-reseaux**

1. 2^2 = 4, donc emprunter 2 bits
2. Nouveau prefix = 24 + 2 = /26
3. Bloc = 64

```
Sous-reseau 1: 192.168.1.0/26   (0-63)
Sous-reseau 2: 192.168.1.64/26  (64-127)
Sous-reseau 3: 192.168.1.128/26 (128-191)
Sous-reseau 4: 192.168.1.192/26 (192-255)
```

**Table rapide :**

| Sous-reseaux | Bits | Ajout au prefix |
|--------------|------|-----------------|
| 2 | 1 | +1 |
| 4 | 2 | +2 |
| 8 | 3 | +3 |
| 16 | 4 | +4 |
| 32 | 5 | +5 |
| 64 | 6 | +6 |

---

## Trouver le prefix pour N hotes

**Formule : 2^(32-prefix) - 2 >= N**

| Hotes necessaires | Bits hotes | Prefix |
|-------------------|------------|--------|
| 1-2 | 2 | /30 |
| 3-6 | 3 | /29 |
| 7-14 | 4 | /28 |
| 15-30 | 5 | /27 |
| 31-62 | 6 | /26 |
| 63-126 | 7 | /25 |
| 127-254 | 8 | /24 |
| 255-510 | 9 | /23 |
| 511-1022 | 10 | /22 |

---

## Checklist des operations

### Pour trouver l'adresse reseau :
- [ ] Identifier le masque (/XX → table)
- [ ] Faire IP AND Masque (ou methode du bloc)
- [ ] Le resultat est l'adresse reseau

### Pour trouver le broadcast :
- [ ] Calculer l'adresse reseau
- [ ] Ajouter (taille bloc - 1) au dernier octet variable
- [ ] Ou : adresse avant le prochain reseau - 1

### Pour verifier l'appartenance :
- [ ] Calculer le reseau de l'IP testee (IP AND Masque)
- [ ] Comparer avec le reseau donne
- [ ] Si identiques → OUI, sinon → NON

### Pour diviser un reseau :
- [ ] Combien de sous-reseaux ? → trouver n (2^n)
- [ ] Nouveau prefix = ancien + n
- [ ] Calculer la taille des blocs
- [ ] Enumerer les adresses reseau

---

## Exercices pratiques

**1. Convertir en binaire :**
- 172 = ?
- 53 = ?
- 199 = ?

**2. Trouver l'adresse reseau :**
- 10.45.123.89/16
- 172.16.45.200/20
- 192.168.100.67/27

**3. L'IP appartient-elle au reseau ?**
- 192.168.1.130 dans 192.168.1.0/25 ?
- 10.0.50.100 dans 10.0.48.0/22 ?

**4. Diviser :**
- 10.0.0.0/8 en 16 sous-reseaux

---

## Reponses

**1. Conversions :**
- 172 = 10101100
- 53 = 00110101
- 199 = 11000111

**2. Adresses reseau :**
- 10.45.123.89/16 → 10.45.0.0
- 172.16.45.200/20 → 172.16.32.0 (bloc de 16 sur 3e octet, 45 AND 240 = 32)
- 192.168.100.67/27 → 192.168.100.64 (bloc de 32, 67 AND 224 = 64)

**3. Appartenance :**
- 192.168.1.130 dans /25 ? Bloc=128. 130 est dans 128-255 → reseau 192.168.1.128 ≠ .0 → **NON**
- 10.0.50.100 dans 10.0.48.0/22 ? 50 AND 252 = 48 → reseau 10.0.48.0 → **OUI**

**4. Division :**
- 10.0.0.0/8 en 16 → /12 (8+4 bits)
- Blocs : 10.0.0.0, 10.16.0.0, 10.32.0.0, 10.48.0.0... jusqu'a 10.240.0.0
