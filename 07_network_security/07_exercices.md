# Exercice Nim : NetProbe - Utilitaire d'analyse réseau

## Contexte

En tant qu'ingénieur cybersécurité, il est fréquent de devoir analyser rapidement des adresses IP ou des plages réseau : valider un format, déterminer si une adresse est publique ou privée, calculer le nombre d'hôtes d'un sous-réseau, etc.

L'objectif de cet exercice est de créer un utilitaire en ligne de commande nommé **NetProbe** qui regroupe ces fonctionnalités courantes.

---

## Objectifs pédagogiques

- Manipuler les chaînes de caractères et les conversions en Nim
- Implémenter des opérations binaires (AND, shifts)
- Structurer un programme CLI avec parsing d'arguments
- Appliquer les concepts réseau : notation CIDR, masques, classes IP, RFC 1918
- Comprendre les différences entre IPv4 et IPv6
- Classifier les adresses selon leur usage (public, privé, loopback, link-local, etc.)

---

## Spécifications fonctionnelles

### Commande générale

```
netprobe <commande> <argument>
```

### Commandes à implémenter

| Commande | Argument | Description |
|----------|----------|-------------|
| `validate` | Adresse IP | Vérifie si l'adresse est valide (IPv4 ou IPv6) |
| `classify` | Adresse IP | Indique la classe, si l'adresse est publique/privée, et son usage spécial |
| `info` | Notation CIDR | Affiche les informations complètes du réseau |
| `contains` | CIDR IP | Vérifie si une IP appartient à un réseau |

Le programme doit détecter automatiquement s'il s'agit d'une adresse IPv4 ou IPv6.

---

## Spécifications détaillées

### 1. Commande `validate`

**Entrée** : une chaîne de caractères représentant une adresse IPv4

**Sortie** : 
- `VALID` si l'adresse est une IPv4 valide
- `INVALID: <raison>` sinon

**Règles de validation** :
- Format : 4 octets séparés par des points
- Chaque octet : nombre entier entre 0 et 255
- Pas de zéros en tête (ex: `01.02.03.04` est invalide)
- Pas d'espaces, pas de caractères autres que chiffres et points

**Exemples** :

```
$ netprobe validate 192.168.1.1
VALID

$ netprobe validate 192.168.1.256
INVALID: octet 4 hors limite (256 > 255)

$ netprobe validate 192.168.1
INVALID: format incorrect (3 octets au lieu de 4)

$ netprobe validate 192.168.01.1
INVALID: zéro en tête dans l'octet 3

$ netprobe validate abc.def.ghi.jkl
INVALID: octet 1 n'est pas un nombre

$ netprobe validate ""
INVALID: chaîne vide

$ netprobe validate 192.168.1.1.1
INVALID: format incorrect (5 octets au lieu de 4)
```

---

### 2. Commande `classify`

**Entrée** : une adresse IPv4 valide

**Sortie** : classification de l'adresse avec détails

**Classifications attendues** :

| Plage | Classification | Détail |
|-------|----------------|--------|
| 10.0.0.0/8 | PRIVATE | RFC 1918 - Classe A privée |
| 172.16.0.0/12 | PRIVATE | RFC 1918 - Classe B privée |
| 192.168.0.0/16 | PRIVATE | RFC 1918 - Classe C privée |
| 127.0.0.0/8 | LOOPBACK | Adresse de bouclage |
| 169.254.0.0/16 | LINK-LOCAL | APIPA (auto-configuration) |
| 224.0.0.0/4 | MULTICAST | Classe D - Multicast |
| 240.0.0.0/4 | RESERVED | Classe E - Expérimental |
| 0.0.0.0/8 | SPECIAL | Réseau "this" |
| 255.255.255.255 | BROADCAST | Broadcast limité |
| 100.64.0.0/10 | CGNAT | RFC 6598 - Carrier-Grade NAT |
| 192.0.2.0/24 | DOCUMENTATION | RFC 5737 - TEST-NET-1 |
| 198.51.100.0/24 | DOCUMENTATION | RFC 5737 - TEST-NET-2 |
| 203.0.113.0/24 | DOCUMENTATION | RFC 5737 - TEST-NET-3 |
| Autre | PUBLIC | Adresse publique routable |

**Exemples** :

```
$ netprobe classify 192.168.1.100
PRIVATE
  Type: RFC 1918 - Classe C privée
  Plage: 192.168.0.0/16

$ netprobe classify 8.8.8.8
PUBLIC
  Classe historique: A
  Note: Adresse routable sur Internet

$ netprobe classify 10.0.50.1
PRIVATE
  Type: RFC 1918 - Classe A privée
  Plage: 10.0.0.0/8

$ netprobe classify 172.20.1.1
PRIVATE
  Type: RFC 1918 - Classe B privée
  Plage: 172.16.0.0/12

$ netprobe classify 172.50.1.1
PUBLIC
  Classe historique: B
  Note: Adresse routable sur Internet

$ netprobe classify 127.0.0.1
LOOPBACK
  Type: Adresse de bouclage locale
  Plage: 127.0.0.0/8

$ netprobe classify 169.254.10.5
LINK-LOCAL
  Type: APIPA (Automatic Private IP Addressing)
  Plage: 169.254.0.0/16

$ netprobe classify 224.0.0.1
MULTICAST
  Type: Classe D - Multicast
  Plage: 224.0.0.0/4

$ netprobe classify 100.64.0.1
CGNAT
  Type: RFC 6598 - Carrier-Grade NAT
  Plage: 100.64.0.0/10
```

#### Classifications IPv6

| Préfixe | Classification | Détail |
|---------|----------------|--------|
| ::1/128 | LOOPBACK | Adresse de bouclage IPv6 |
| fe80::/10 | LINK-LOCAL | Adresse locale au lien |
| fc00::/7 (fd00::/8 en pratique) | ULA | Unique Local Address (équivalent RFC 1918) |
| ff00::/8 | MULTICAST | Adresses multicast |
| 2000::/3 | GUA | Global Unicast Address (publique) |
| ::ffff:0:0/96 | IPV4-MAPPED | Adresse IPv4 mappée en IPv6 |
| 2001:db8::/32 | DOCUMENTATION | Réservé pour la documentation (RFC 3849) |

**Exemples IPv6** :

```
$ netprobe classify 2001:4860:4860::8888
PUBLIC
  Type: GUA (Global Unicast Address)
  Note: Adresse routable sur Internet (Google DNS)

$ netprobe classify fe80::1
LINK-LOCAL
  Type: Adresse locale au lien
  Plage: fe80::/10
  Note: Non routable, valide uniquement sur le segment local

$ netprobe classify fd12:3456:789a::1
ULA (PRIVATE)
  Type: Unique Local Address
  Plage: fd00::/8
  Note: Équivalent IPv6 des adresses RFC 1918

$ netprobe classify ::1
LOOPBACK
  Type: Adresse de bouclage IPv6
  Équivalent IPv4: 127.0.0.1

$ netprobe classify fc00::1234:abcd
ULA (PRIVATE)
  Type: Unique Local Address
  Plage: fc00::/7

$ netprobe classify ff02::1
MULTICAST
  Type: Adresse multicast
  Scope: Link-local (ff02)
  Note: All-nodes multicast address

$ netprobe classify 2001:db8::ff00:42:8329
DOCUMENTATION
  Type: Réservé pour la documentation
  Plage: 2001:db8::/32
  Note: Ne doit pas être utilisé en production (RFC 3849)

$ netprobe classify ::ffff:192.168.1.1
IPV4-MAPPED
  Type: Adresse IPv4 mappée en IPv6
  Adresse IPv4: 192.168.1.1
  Classification IPv4: PRIVATE (RFC 1918)
```

---

### 3. Commande `info`

**Entrée** : une notation CIDR (ex: `192.168.1.0/24`)

**Sortie** : informations complètes sur le réseau

**Informations à afficher** :
- Adresse réseau
- Masque de sous-réseau (décimal et binaire)
- Adresse de broadcast
- Première adresse utilisable
- Dernière adresse utilisable
- Nombre total d'adresses
- Nombre d'hôtes utilisables
- Classe historique (si applicable)
- Type (public/privé)

**Exemples** :

```
$ netprobe info 192.168.1.0/24
Réseau: 192.168.1.0/24
├── Adresse réseau    : 192.168.1.0
├── Masque            : 255.255.255.0
├── Masque binaire    : 11111111.11111111.11111111.00000000
├── Broadcast         : 192.168.1.255
├── Première IP       : 192.168.1.1
├── Dernière IP       : 192.168.1.254
├── Total adresses    : 256
├── Hôtes utilisables : 254
├── Classe historique : C
└── Type              : PRIVATE (RFC 1918)

$ netprobe info 10.0.0.0/8
Réseau: 10.0.0.0/8
├── Adresse réseau    : 10.0.0.0
├── Masque            : 255.0.0.0
├── Masque binaire    : 11111111.00000000.00000000.00000000
├── Broadcast         : 10.255.255.255
├── Première IP       : 10.0.0.1
├── Dernière IP       : 10.255.255.254
├── Total adresses    : 16777216
├── Hôtes utilisables : 16777214
├── Classe historique : A
└── Type              : PRIVATE (RFC 1918)

$ netprobe info 192.168.1.64/26
Réseau: 192.168.1.64/26
├── Adresse réseau    : 192.168.1.64
├── Masque            : 255.255.255.192
├── Masque binaire    : 11111111.11111111.11111111.11000000
├── Broadcast         : 192.168.1.127
├── Première IP       : 192.168.1.65
├── Dernière IP       : 192.168.1.126
├── Total adresses    : 64
├── Hôtes utilisables : 62
├── Classe historique : C
└── Type              : PRIVATE (RFC 1918)

$ netprobe info 203.0.113.0/28
Réseau: 203.0.113.0/28
├── Adresse réseau    : 203.0.113.0
├── Masque            : 255.255.255.240
├── Masque binaire    : 11111111.11111111.11111111.11110000
├── Broadcast         : 203.0.113.15
├── Première IP       : 203.0.113.1
├── Dernière IP       : 203.0.113.14
├── Total adresses    : 16
├── Hôtes utilisables : 14
├── Classe historique : C
└── Type              : PUBLIC
```

**Cas particuliers à gérer** :

```
$ netprobe info 192.168.1.0/31
Réseau: 192.168.1.0/31
├── Adresse réseau    : 192.168.1.0
├── Masque            : 255.255.255.254
├── Masque binaire    : 11111111.11111111.11111111.11111110
├── Broadcast         : (aucun - lien point-à-point)
├── Première IP       : 192.168.1.0
├── Dernière IP       : 192.168.1.1
├── Total adresses    : 2
├── Hôtes utilisables : 2 (RFC 3021 - point-à-point)
├── Classe historique : C
└── Type              : PRIVATE (RFC 1918)

$ netprobe info 192.168.1.100/32
Réseau: 192.168.1.100/32
├── Adresse réseau    : 192.168.1.100
├── Masque            : 255.255.255.255
├── Masque binaire    : 11111111.11111111.11111111.11111111
├── Broadcast         : (aucun - hôte unique)
├── Première IP       : 192.168.1.100
├── Dernière IP       : 192.168.1.100
├── Total adresses    : 1
├── Hôtes utilisables : 1 (hôte unique)
├── Classe historique : C
└── Type              : PRIVATE (RFC 1918)
```

---

### 4. Commande `contains`

**Entrée** : notation CIDR suivie d'une adresse IP (séparées par un espace)

**Sortie** : indique si l'IP appartient au réseau

**Exemples** :

```
$ netprobe contains 192.168.1.0/24 192.168.1.100
YES
  192.168.1.100 appartient à 192.168.1.0/24

$ netprobe contains 192.168.1.0/24 192.168.2.1
NO
  192.168.2.1 n'appartient pas à 192.168.1.0/24
  Réseau de l'IP: 192.168.2.0/24

$ netprobe contains 10.0.0.0/8 10.255.255.254
YES
  10.255.255.254 appartient à 10.0.0.0/8

$ netprobe contains 192.168.1.64/26 192.168.1.100
YES
  192.168.1.100 appartient à 192.168.1.64/26

$ netprobe contains 192.168.1.64/26 192.168.1.50
NO
  192.168.1.50 n'appartient pas à 192.168.1.64/26
  Réseau de l'IP: 192.168.1.0/26
```

---

## Gestion des erreurs

Le programme doit gérer gracieusement les erreurs :

```
$ netprobe
ERREUR: Commande manquante
Usage: netprobe <commande> <argument>
Commandes: validate, classify, info, contains

$ netprobe invalid_cmd 192.168.1.1
ERREUR: Commande inconnue 'invalid_cmd'
Commandes disponibles: validate, classify, info, contains

$ netprobe info 192.168.1.0
ERREUR: Notation CIDR invalide (masque manquant)
Format attendu: X.X.X.X/Y (ex: 192.168.1.0/24)

$ netprobe info 192.168.1.0/33
ERREUR: Masque CIDR invalide (33 > 32)

$ netprobe info 192.168.1.0/-1
ERREUR: Masque CIDR invalide (valeur négative)

$ netprobe contains 192.168.1.0/24
ERREUR: Argument manquant
Usage: netprobe contains <CIDR> <IP>

$ netprobe classify not_an_ip
ERREUR: Adresse IP invalide
```

---

## Structure suggérée du code

```
netprobe/
├── src/
│   ├── netprobe.nim      # Point d'entrée, parsing des arguments
│   ├── ipv4.nim          # Type IPv4, parsing, validation
│   ├── ipv6.nim          # Type IPv6, parsing, validation, expansion ::
│   ├── cidr.nim          # Type CIDR, calculs réseau (IPv4)
│   ├── classifier.nim    # Classification des adresses (IPv4 et IPv6)
│   └── display.nim       # Formatage de l'affichage
└── tests/
    ├── test_ipv4.nim     # Tests unitaires IPv4
    ├── test_ipv6.nim     # Tests unitaires IPv6
    ├── test_cidr.nim     # Tests unitaires CIDR
    └── test_classifier.nim
```

---

## Indices techniques

### Parsing d'une adresse IPv4

```nim
# Piste : utiliser split et parseInt
let parts = ip.split('.')
# Vérifier : len(parts) == 4
# Pour chaque part : convertir en int, vérifier 0-255
```

### Conversion IP vers entier 32 bits

```nim
# Une IP peut être représentée comme un uint32
# 192.168.1.1 = (192 << 24) + (168 << 16) + (1 << 8) + 1
#             = 3232235777

proc ipToUint32(octets: array[4, uint8]): uint32 =
  # À implémenter...
```

### Calcul du masque depuis le CIDR

```nim
# /24 = 24 bits à 1, puis 8 bits à 0
# = 11111111.11111111.11111111.00000000
# = 0xFFFFFF00
# = 4294967040

proc cidrToMask(prefix: int): uint32 =
  # Piste : utiliser un shift
  # Si prefix = 24 : décaler 0xFFFFFFFF de (32-24) vers la gauche
  # Attention au cas prefix = 0
```

### Opération AND pour trouver l'adresse réseau

```nim
# Adresse réseau = IP AND Masque
let networkAddr = ipAsUint32 and maskAsUint32
```

### Vérification d'appartenance à un réseau

```nim
# Une IP appartient à un réseau si :
# (IP AND Masque) == Adresse réseau
```

### Calcul du broadcast

```nim
# Broadcast = Adresse réseau OR (NOT Masque)
let broadcast = networkAddr or (not mask)
```

---

## Critères de validation

### Niveau 1 : Fonctionnel

- [ ] `validate` détecte correctement les IPs valides et invalides
- [ ] `classify` identifie correctement les types (privé, public, loopback, etc.)
- [ ] `info` calcule correctement toutes les informations réseau
- [ ] `contains` vérifie correctement l'appartenance

### Niveau 2 : Robustesse

- [ ] Gestion de toutes les erreurs d'entrée
- [ ] Messages d'erreur clairs et utiles
- [ ] Pas de crash sur entrées malformées

### Niveau 3 : Qualité du code

- [ ] Code modulaire (séparation des responsabilités)
- [ ] Types bien définis (IPv4Address, CIDRNetwork, etc.)
- [ ] Fonctions pures quand possible
- [ ] Commentaires sur les parties complexes

### Niveau 4 : Tests

- [ ] Tests unitaires pour chaque fonction de calcul
- [ ] Tests des cas limites (/0, /31, /32)
- [ ] Tests des plages spéciales (RFC 1918, CGNAT, etc.)
- [ ] Tests IPv6 (ULA, link-local, GUA, multicast)

---

## Exercices pratiques de validation

Ces exercices permettent de vérifier que l'implémentation est correcte. Le programme doit produire les résultats attendus pour chaque adresse.

### Partie 1 : Classification IPv4

Pour chaque adresse, le programme doit indiquer la classe historique (A, B, C, D, E), si elle est publique ou privée, et tout usage spécial.

| Adresse | Classe | Type | Usage spécial | Plage associée |
|---------|--------|------|---------------|----------------|
| `10.0.45.2` | A | PRIVATE | RFC 1918 | 10.0.0.0/8 |
| `172.20.10.5` | B | PRIVATE | RFC 1918 | 172.16.0.0/12 |
| `192.168.100.200` | C | PRIVATE | RFC 1918 | 192.168.0.0/16 |
| `8.8.4.4` | A | PUBLIC | - | Google DNS |
| `203.0.113.15` | C | DOCUMENTATION | RFC 5737 (TEST-NET-3) | 203.0.113.0/24 |
| `127.0.0.1` | A | LOOPBACK | Bouclage local | 127.0.0.0/8 |
| `224.5.6.7` | D | MULTICAST | Classe D | 224.0.0.0/4 |
| `240.0.0.1` | E | RESERVED | Expérimental | 240.0.0.0/4 |
| `169.254.1.1` | B | LINK-LOCAL | APIPA | 169.254.0.0/16 |
| `198.51.100.25` | C | DOCUMENTATION | RFC 5737 (TEST-NET-2) | 198.51.100.0/24 |

**Note** : Les plages de documentation (RFC 5737) sont :
- 192.0.2.0/24 (TEST-NET-1)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24 (TEST-NET-3)

Ces plages sont réservées pour la documentation et les exemples, elles ne doivent pas être utilisées en production.

**Sorties attendues** :

```
$ netprobe classify 10.0.45.2
PRIVATE
  Classe: A
  Type: RFC 1918 - Classe A privée
  Plage: 10.0.0.0/8

$ netprobe classify 172.20.10.5
PRIVATE
  Classe: B
  Type: RFC 1918 - Classe B privée
  Plage: 172.16.0.0/12

$ netprobe classify 192.168.100.200
PRIVATE
  Classe: C
  Type: RFC 1918 - Classe C privée
  Plage: 192.168.0.0/16

$ netprobe classify 8.8.4.4
PUBLIC
  Classe: A
  Note: Adresse routable sur Internet

$ netprobe classify 203.0.113.15
DOCUMENTATION
  Classe: C
  Type: RFC 5737 - TEST-NET-3
  Plage: 203.0.113.0/24
  Note: Réservé pour documentation, non routable

$ netprobe classify 127.0.0.1
LOOPBACK
  Classe: A
  Type: Adresse de bouclage locale
  Plage: 127.0.0.0/8

$ netprobe classify 224.5.6.7
MULTICAST
  Classe: D
  Type: Adresse multicast
  Plage: 224.0.0.0/4

$ netprobe classify 240.0.0.1
RESERVED
  Classe: E
  Type: Expérimental / Réservé
  Plage: 240.0.0.0/4
  Note: Non utilisable en production

$ netprobe classify 169.254.1.1
LINK-LOCAL
  Classe: B
  Type: APIPA (Automatic Private IP Addressing)
  Plage: 169.254.0.0/16
  Note: Auto-configuration en l'absence de DHCP

$ netprobe classify 198.51.100.25
DOCUMENTATION
  Classe: C
  Type: RFC 5737 - TEST-NET-2
  Plage: 198.51.100.0/24
  Note: Réservé pour documentation, non routable
```

### Partie 2 : Classification IPv6

Pour chaque adresse IPv6, le programme doit indiquer si elle est publique ou privée et son usage spécifique.

| Adresse | Type | Usage | Détail |
|---------|------|-------|--------|
| `2001:db8::ff00:42:8329` | DOCUMENTATION | RFC 3849 | Réservé pour exemples/documentation |
| `fe80::1` | LINK-LOCAL | Locale au lien | Non routable, fe80::/10 |
| `fc00::1234:abcd` | ULA (PRIVATE) | Unique Local Address | fc00::/7 |
| `::1` | LOOPBACK | Bouclage | Équivalent de 127.0.0.1 |
| `2001:4860:4860::8888` | PUBLIC (GUA) | Global Unicast | Google DNS public |
| `ff02::1` | MULTICAST | All-nodes link-local | Scope link-local |
| `fd12:3456:789a::1` | ULA (PRIVATE) | Unique Local Address | fd00::/8 |
| `::ffff:192.168.1.1` | IPV4-MAPPED | IPv4 mappée | Encapsule 192.168.1.1 (privée) |

**Sorties attendues** :

```
$ netprobe classify 2001:db8::ff00:42:8329
DOCUMENTATION
  Type: RFC 3849 - Documentation
  Plage: 2001:db8::/32
  Note: Réservé pour exemples et documentation, non routable

$ netprobe classify fe80::1
LINK-LOCAL
  Type: Adresse locale au lien
  Plage: fe80::/10
  Note: Valide uniquement sur le segment local, non routable

$ netprobe classify fc00::1234:abcd
ULA (PRIVATE)
  Type: Unique Local Address
  Plage: fc00::/7
  Note: Équivalent IPv6 des adresses RFC 1918

$ netprobe classify ::1
LOOPBACK
  Type: Adresse de bouclage IPv6
  Équivalent IPv4: 127.0.0.1

$ netprobe classify 2001:4860:4860::8888
PUBLIC
  Type: GUA (Global Unicast Address)
  Note: Adresse routable sur Internet (Google Public DNS)

$ netprobe classify ff02::1
MULTICAST
  Type: Adresse multicast
  Scope: Link-local (ff02)
  Usage: All-nodes multicast address
  Note: Envoie à tous les noeuds du lien local

$ netprobe classify fd12:3456:789a::1
ULA (PRIVATE)
  Type: Unique Local Address
  Plage: fd00::/8
  Note: Équivalent IPv6 des adresses RFC 1918

$ netprobe classify ::ffff:192.168.1.1
IPV4-MAPPED
  Type: Adresse IPv4 mappée en IPv6
  Plage: ::ffff:0:0/96
  Adresse IPv4 encapsulée: 192.168.1.1
  Classification IPv4: PRIVATE (RFC 1918 - 192.168.0.0/16)
```

### Partie 3 : Tests de validation de format

Ces entrées doivent être rejetées avec des messages d'erreur appropriés :

| Entrée | Erreur attendue |
|--------|-----------------|
| `256.1.1.1` | Octet hors limite |
| `192.168.1` | Format incorrect (3 octets) |
| `192.168.01.1` | Zéro en tête |
| `192.168.1.1.1` | Format incorrect (5 octets) |
| `abc.def.ghi.jkl` | Octets non numériques |
| `192.168.1.-1` | Valeur négative |
| `fe80:::1` | Format IPv6 invalide (triple deux-points) |
| `2001:db8::gggg` | Caractère hexadécimal invalide |
| `::1::2` | Plusieurs groupes :: |

---

## Indices techniques supplémentaires (IPv6)

### Détection IPv4 vs IPv6

```nim
proc isIPv6(s: string): bool =
  # Une adresse contient ':' si c'est de l'IPv6
  ':' in s

proc isIPv4(s: string): bool =
  # Une adresse contient '.' et pas de ':' si c'est de l'IPv4
  '.' in s and ':' notin s
```

### Parsing IPv6

L'IPv6 est plus complexe à parser à cause de la compression (`::`). Approche suggérée :

```nim
# Étapes :
# 1. Gérer le cas spécial :: (expansion en zéros)
# 2. Split par ':'
# 3. Chaque groupe est un nombre hex de 0 à FFFF
# 4. Résultat : 8 groupes de 16 bits = 128 bits

proc expandIPv6(s: string): string =
  ## Expanse :: en groupes de zéros
  if "::" notin s:
    return s
  
  let parts = s.split("::")
  # Compter combien de groupes manquent
  # ...
```

### Classification IPv6 par préfixe

```nim
proc classifyIPv6(groups: array[8, uint16]): string =
  # Loopback : ::1
  if groups == [0u16, 0, 0, 0, 0, 0, 0, 1]:
    return "LOOPBACK"
  
  # Link-local : fe80::/10
  if (groups[0] and 0xFFC0) == 0xFE80:
    return "LINK-LOCAL"
  
  # ULA : fc00::/7
  if (groups[0] and 0xFE00) == 0xFC00:
    return "ULA"
  
  # Multicast : ff00::/8
  if (groups[0] and 0xFF00) == 0xFF00:
    return "MULTICAST"
  
  # Documentation : 2001:db8::/32
  if groups[0] == 0x2001 and groups[1] == 0x0DB8:
    return "DOCUMENTATION"
  
  # IPv4-mapped : ::ffff:x.x.x.x
  if groups[0..4] == [0u16, 0, 0, 0, 0] and groups[5] == 0xFFFF:
    return "IPV4-MAPPED"
  
  # GUA : 2000::/3
  if (groups[0] and 0xE000) == 0x2000:
    return "PUBLIC"
  
  return "UNKNOWN"
```

---

## Bonus (optionnel)

### Bonus 1 : Commande `range`

Lister toutes les IPs d'un petit réseau (/28 ou plus petit) :

```
$ netprobe range 192.168.1.0/30
192.168.1.0   (réseau)
192.168.1.1   (utilisable)
192.168.1.2   (utilisable)
192.168.1.3   (broadcast)
```

### Bonus 2 : Commande `split`

Découper un réseau en N sous-réseaux :

```
$ netprobe split 192.168.1.0/24 4
Découpage de 192.168.1.0/24 en 4 sous-réseaux:
  1. 192.168.1.0/26   (62 hôtes)
  2. 192.168.1.64/26  (62 hôtes)
  3. 192.168.1.128/26 (62 hôtes)
  4. 192.168.1.192/26 (62 hôtes)
```

### Bonus 3 : Sortie JSON

Option `--json` pour une sortie structurée :

```
$ netprobe info 192.168.1.0/24 --json
{
  "network": "192.168.1.0",
  "prefix": 24,
  "mask": "255.255.255.0",
  "broadcast": "192.168.1.255",
  "first_usable": "192.168.1.1",
  "last_usable": "192.168.1.254",
  "total_addresses": 256,
  "usable_hosts": 254,
  "type": "PRIVATE",
  "rfc": "RFC 1918"
}
```

### Bonus 4 : Couleurs

Ajouter des couleurs dans le terminal (vert pour VALID, rouge pour INVALID, etc.) en utilisant les codes ANSI.

### Bonus 5 : Commande `info` pour IPv6

Étendre la commande `info` pour supporter les réseaux IPv6 :

```
$ netprobe info 2001:db8::/32
Réseau: 2001:db8::/32
├── Adresse réseau    : 2001:db8::
├── Préfixe           : /32
├── Première IP       : 2001:db8::1
├── Dernière IP       : 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
├── Total adresses    : 79228162514264337593543950336 (2^96)
└── Type              : DOCUMENTATION (RFC 3849)
```

---

## Ressources utiles

| Ressource | Usage |
|-----------|-------|
| Nim by Example | https://nim-by-example.github.io/ |
| Nim std/strutils | Manipulation de chaînes (split, parseInt) |
| Nim std/parseopt | Parsing d'arguments CLI |
| RFC 1918 | Plages d'adresses privées IPv4 |
| RFC 3021 | Utilisation des /31 |
| RFC 3849 | Plage IPv6 de documentation (2001:db8::/32) |
| RFC 4193 | Unique Local Addresses IPv6 (ULA) |
| RFC 5737 | Plages IPv4 de documentation (TEST-NET) |
| RFC 6598 | Plage CGNAT (100.64.0.0/10) |

---

## Commandes de compilation

```bash
# Compilation debug
nim c -o:netprobe src/netprobe.nim

# Compilation optimisée
nim c -d:release -o:netprobe src/netprobe.nim

# Compilation avec checks désactivés 
nim c -d:release -d:danger -o:netprobe src/netprobe.nim

# Exécution des tests
nim c -r tests/test_ipv4.nim
```

---
