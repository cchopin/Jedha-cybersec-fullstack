# Subnetting et planification d'adresses

## Objectifs du cours

Maintenant que vous avez appris les masques de sous-réseau et les bases des classes IP, il est temps de découvrir des concepts de subnetting plus avancés comme CIDR, VLSM et le supernetting. Ces sujets permettent de planifier et gérer votre réseau plus efficacement, en permettant une meilleure utilisation des adresses, une segmentation réseau optimisée et un routage plus efficient.

Compétences visées :
- Comprendre et utiliser la notation CIDR pour gérer efficacement l'espace d'adressage IP
- Calculer le nombre d'hôtes et de sous-réseaux dans un bloc CIDR
- Maîtriser l'art du VLSM (Variable Length Subnet Masking) pour l'allocation dynamique d'adresses IP
- Comprendre le concept de supernetting et de summarisation de routes pour réduire la taille des tables de routage et améliorer les performances

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **CIDR** | Classless Inter-Domain Routing - Méthode d'allocation flexible d'adresses IP |
| **VLSM** | Variable Length Subnet Masking - Masques de sous-réseau de longueur variable |
| **Supernetting** | Agrégation de plusieurs sous-réseaux en un seul réseau plus large |
| **Summarization** | Technique de regroupement de routes pour réduire les tables de routage |
| **Prefix Length** | Nombre de bits utilisés pour la partie réseau (notation /24, /16, etc.) |
| **RFC 1918** | Standard définissant les plages d'adresses IP privées |

---

## CIDR : Une méthode flexible d'allocation d'espace d'adressage

Comme vu dans les cours précédents, l'adressage classful était autrefois la méthode utilisée pour assigner des adresses IP aux réseaux. Cependant, CIDR (Classless Inter-Domain Routing) est apparu comme une méthode plus flexible et efficace. CIDR supprime les restrictions rigides de l'adressage classful traditionnel et permet un contrôle plus fin sur la façon dont les adresses réseau sont allouées.

La notation CIDR permet de représenter une adresse IP suivie d'un slash et du nombre de bits utilisés pour la partie réseau. Par exemple, dans l'adresse `192.168.1.0/24`, le "/24" indique que les 24 premiers bits sont réservés pour le réseau, laissant 8 bits pour les adresses d'hôtes. Cela offre plus de flexibilité que l'ancien système, permettant la création de réseaux de tailles variées selon les besoins.

Pour rappel, en notation CIDR :
- Un préfixe /8 signifie 8 bits alloués pour le réseau, laissant 24 bits pour les hôtes
- Un préfixe /16 signifie 16 bits alloués pour le réseau, laissant 16 bits pour les hôtes
- Un préfixe /24 signifie 24 bits alloués pour le réseau, laissant 8 bits pour les hôtes

Ce système élimine les inefficacités des réseaux basés sur les classes, où des réseaux comme la Classe A pouvaient gaspiller de grandes quantités d'espace d'adressage.

---

## Standards et réglementations réseau

Lors du traitement du subnetting et de l'adressage IP, il est important de considérer les standards et réglementations suivants :

### RFC 1918 - Adressage IP privé

Définit les plages d'adresses IP privées qui ne doivent pas être routées sur Internet public :
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

### RFC 2050 - Politiques d'allocation d'adresses IP

Établit les directives pour l'allocation d'adresses IP afin d'assurer l'équité et prévenir l'épuisement des adresses.

### Épuisement des adresses IPv4

Les organisations comme IANA (Internet Assigned Numbers Authority) et les RIR (Regional Internet Registries) gèrent l'allocation globale d'IP. L'épuisement d'IPv4 a conduit à l'adoption d'IPv6.

### RFC 4632 - Classless Inter-Domain Routing (CIDR)

Détaille la méthodologie CIDR et ses avantages par rapport à l'adressage traditionnel basé sur les classes.

### Adoption IPv6

En raison de l'épuisement d'IPv4, IPv6 a été introduit, offrant un adressage sur 128 bits et une meilleure scalabilité pour les réseaux modernes.

---

## Calcul des hôtes et sous-réseaux en CIDR

### Nombre d'hôtes dans un bloc CIDR

Pour n'importe quel bloc CIDR, le nombre d'hôtes disponibles est déterminé par le nombre de bits d'hôte, qui sont les bits restants après que la portion réseau ait été allouée.

**Formule :**

```
Nombre d'hôtes = 2^(32 - longueur du préfixe) - 2
```

La soustraction de 2 prend en compte l'adresse réseau et l'adresse de broadcast, qui ne peuvent pas être assignées aux hôtes.

**Exemple avec un bloc /24 :**

```
32 - 24 = 8 bits d'hôte
2^8 = 256 adresses totales
256 - 2 = 254 hôtes utilisables
```

Donc, un sous-réseau /24 fournit 254 adresses d'hôtes utilisables.

### Nombre de sous-réseaux dans un bloc CIDR

Pour déterminer combien de sous-réseaux vous pouvez créer à partir d'un réseau plus large, vous devez emprunter des bits de la portion hôte de l'adresse.

**Formule :**

```
Nombre de sous-réseaux = 2^(nombre de bits empruntés)
```

**Exemple :** Si vous avez un réseau /24 et avez besoin de 4 sous-réseaux, vous devez emprunter 2 bits de la portion hôte, changeant le masque de sous-réseau en /26.

```
Bits empruntés : 2
2^2 = 4 sous-réseaux
```

Chaque sous-réseau /26 a :

```
Bits d'hôte restants : 32 - 26 = 6
2^6 = 64 adresses totales
64 - 2 = 62 hôtes utilisables
```

Donc, un masque de sous-réseau /26 fournit 4 sous-réseaux, chacun avec 62 hôtes utilisables.

---

## Variable Length Subnet Masking (VLSM)

Dans les réseaux réels, tous les sous-réseaux n'ont pas besoin du même nombre d'hôtes. Certains sous-réseaux peuvent nécessiter seulement une poignée d'hôtes, tandis que d'autres peuvent en nécessiter des centaines ou même des milliers. C'est là qu'intervient le Variable Length Subnet Masking (VLSM).

Avec VLSM, vous pouvez assigner différents masques de sous-réseau à différents sous-réseaux au sein du même réseau. Par exemple, vous pouvez avoir un sous-réseau /26 pour un département, un sous-réseau /24 pour un autre, et un sous-réseau /30 pour une petite connexion point-à-point, le tout à partir du même réseau plus large.

### Exemple de VLSM

Supposons que vous ayez un réseau `192.168.1.0/24`, et que vous ayez besoin de créer 4 sous-réseaux avec des tailles variables :

- Sous-réseau A : Besoin de 50 hôtes
- Sous-réseau B : Besoin de 30 hôtes
- Sous-réseau C : Besoin de 10 hôtes
- Sous-réseau D : Besoin de 5 hôtes

**Étape 1 : Déterminer les masques nécessaires**

```
Sous-réseau A : 50 hôtes → besoin de 6 bits hôte → /26 (62 hôtes utilisables)
Sous-réseau B : 30 hôtes → besoin de 5 bits hôte → /27 (30 hôtes utilisables)
Sous-réseau C : 10 hôtes → besoin de 4 bits hôte → /28 (14 hôtes utilisables)
Sous-réseau D : 5 hôtes → besoin de 3 bits hôte → /29 (6 hôtes utilisables)
```

**Étape 2 : Allocation à partir de 192.168.1.0/24**

```
Sous-réseau A : 192.168.1.0/26    (192.168.1.0 - 192.168.1.63)
Sous-réseau B : 192.168.1.64/27   (192.168.1.64 - 192.168.1.95)
Sous-réseau C : 192.168.1.96/28   (192.168.1.96 - 192.168.1.111)
Sous-réseau D : 192.168.1.112/29  (192.168.1.112 - 192.168.1.119)
```

Cette méthode d'allocation flexible assure une utilisation efficace de votre espace d'adressage IP tout en répondant aux besoins spécifiques de chaque sous-réseau.

---

## Supernetting et summarisation de routes

Dans les grands réseaux, gérer de nombreux petits sous-réseaux peut conduire à des tables de routage gonflées. C'est là qu'intervient le supernetting. Le supernetting est le processus de combinaison de plusieurs sous-réseaux en un réseau plus large, réduisant le nombre d'entrées dans une table de routage.

### Exemple de supernetting

Imaginons que vous ayez les quatre réseaux suivants :

```
192.168.0.0/24
192.168.1.0/24
192.168.2.0/24
192.168.3.0/24
```

Plutôt que d'avoir quatre routes séparées, vous pouvez créer un supernet qui englobe tous les quatre réseaux. La question clé est : comment trouver la bonne longueur de préfixe (/22) ?

**Étape 1 : Écrire les adresses en binaire**

On se concentre sur le troisième octet (puisque les deux premiers sont identiques : 192.168) :

```
192.168.0.0 → 00000000
192.168.1.0 → 00000001
192.168.2.0 → 00000010
192.168.3.0 → 00000011
```

**Étape 2 : Comparer les bits**

On compare maintenant ces valeurs binaires de gauche à droite :

```
00000000
00000001
00000010
00000011
```

En regardant les bits, les 6 premiers bits sont communs à travers les quatre valeurs, ce qui signifie que seuls les 6 premiers bits du troisième octet peuvent être considérés comme faisant partie du préfixe réseau.

**Étape 3 : Compter la longueur du préfixe**

```
Premier octet : 8 bits (192)
Deuxième octet : 8 bits (168)
Troisième octet : 6 bits (communs)

Total : 8 + 8 + 6 = 22 bits
```

Donc le masque de supernet correct est /22, ou en notation décimale pointée : 255.255.252.0.

**Étape 4 : Vérifier la plage**

Un /22 couvre 2^(8-6) = 4 sous-réseaux de /24. Cela signifie qu'un /22 inclut :

```
192.168.0.0/24
192.168.1.0/24
192.168.2.0/24
192.168.3.0/24
```

Donc le supernet est `192.168.0.0/22`, qui couvre toutes les adresses de 192.168.0.0 à 192.168.3.255.

### Résumé final

Pour résumer les quatre sous-réseaux, vous pouvez les remplacer par :

```
192.168.0.0/22
```

Cela signifie qu'une seule route couvre maintenant tous les quatre réseaux, réduisant drastiquement la taille de votre table de routage.

---

## Exercice pratique

### Scénario

Vous disposez du réseau `10.0.0.0/16` et devez créer les sous-réseaux suivants :
- Département IT : 500 hôtes
- Département Marketing : 200 hôtes
- Département RH : 50 hôtes
- Liens point-à-point : 4 liens (2 hôtes chacun)

**Questions :**
1. Quel masque de sous-réseau utiliser pour chaque département ?
2. Quelle est la première adresse utilisable de chaque sous-réseau ?
3. Combien d'espace d'adressage reste-t-il après allocation ?

---

## Ressources

- CIDR AWS : [Documentation AWS CIDR](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html)
- Guide VLSM : [VLSM Tutorial](https://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13788-3.html)
- Supernetting expliqué : [Supernetting Overview](https://www.networkacademy.io/ccna/ip-subnetting/supernetting)
- Outil de pratique de subnetting : [Subnet Calculator](https://www.subnet-calculator.com/)
