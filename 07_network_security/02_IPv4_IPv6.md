# IPv4 et IPv6

## Fondamentaux

Chaque appareil connecté à un réseau a besoin d'une adresse IP unique pour communiquer.  

Deux protocoles coexistent : IPv4 (1981) et IPv6 (plus récent, conçu pour pallier l'épuisement des adresses IPv4).

---

## Glossaire

Avant de plonger dans le cours, voici les définitions des termes techniques utilisés :

### Protocoles et adressage

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **IP** | Internet Protocol | Protocole de couche 3 (réseau) qui permet l'adressage et le routage des paquets |
| **IPv4** | Internet Protocol version 4 | Version historique d'IP, adresses sur 32 bits (ex: 192.168.1.1) |
| **IPv6** | Internet Protocol version 6 | Version moderne d'IP, adresses sur 128 bits (ex: 2001:db8::1) |
| **CIDR** | Classless Inter-Domain Routing | Notation pour indiquer la taille d'un réseau (ex: /24, /64) |
| **MAC** | Media Access Control | Adresse physique unique de la carte réseau, sur 48 bits (ex: 00:1A:2B:3C:4D:5E). Fonctionne en couche 2 (liaison) |

### Protocoles de découverte et configuration

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **ARP** | Address Resolution Protocol | Protocole IPv4 qui associe une adresse IP à une adresse MAC. Envoie une requête broadcast "Qui a cette IP ?" et reçoit une réponse avec l'adresse MAC |
| **NDP** | Neighbor Discovery Protocol | Équivalent d'ARP pour IPv6. Utilise ICMPv6 pour découvrir les voisins, les routeurs, et configurer les adresses. Plus complet qu'ARP mais mêmes vulnérabilités |
| **DHCP** | Dynamic Host Configuration Protocol | Protocole qui attribue automatiquement les adresses IP aux appareils. Un serveur DHCP distribue IP, masque, passerelle, DNS |
| **DHCPv6** | DHCP for IPv6 | Version IPv6 de DHCP, souvent utilisé avec SLAAC |
| **SLAAC** | Stateless Address Autoconfiguration | Mécanisme IPv6 permettant à un appareil de se configurer automatiquement sans serveur DHCP, en utilisant le préfixe annoncé par le routeur |

### Protocoles réseau courants

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **ICMP** | Internet Control Message Protocol | Protocole de diagnostic et d'erreur (ping, traceroute). ICMPv6 est la version IPv6 |
| **DNS** | Domain Name System | Système qui traduit les noms de domaine (google.com) en adresses IP |
| **NAT** | Network Address Translation | Mécanisme qui permet à plusieurs appareils de partager une seule IP publique. Traduit les adresses privées en adresse publique |
| **TCP** | Transmission Control Protocol | Protocole de transport fiable, avec connexion (handshake), accusés de réception, retransmission |
| **UDP** | User Datagram Protocol | Protocole de transport rapide mais non fiable, sans connexion ni garantie de livraison |

### Types d'adresses IPv6

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **ULA** | Unique Local Address | Adresses IPv6 privées (fc00::/7), équivalent des 10.x.x.x et 192.168.x.x en IPv4 |
| **GUA** | Global Unicast Address | Adresses IPv6 publiques routables sur internet (2000::/3) |
| **EUI-64** | Extended Unique Identifier 64-bit | Méthode pour générer l'interface ID (64 bits) d'une adresse IPv6 à partir de l'adresse MAC |

### Sécurité et mécanismes de protection

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **APIPA** | Automatic Private IP Addressing | Adresse IPv4 auto-attribuée (169.254.x.x) quand DHCP échoue |
| **SEND** | SEcure Neighbor Discovery | Extension sécurisée de NDP utilisant la cryptographie pour authentifier les messages |
| **RA Guard** | Router Advertisement Guard | Protection sur les switches contre les fausses annonces de routeur IPv6 |
| **DAI** | Dynamic ARP Inspection | Fonctionnalité de switch qui valide les paquets ARP contre une table de confiance |
| **IPsec** | Internet Protocol Security | Suite de protocoles pour chiffrer et authentifier les communications IP |

### Termes d'attaque

| Terme | Description |
|-------|-------------|
| **Spoofing** | Usurpation d'identité (IP spoofing = fausse IP source, MAC spoofing = fausse adresse MAC) |
| **MitM** | Man-in-the-Middle, attaque où l'attaquant s'intercale entre deux parties |
| **DoS/DDoS** | Denial of Service / Distributed DoS, attaque visant à rendre un service indisponible |
| **Rogue** | "Pirate" ou "frauduleux" (rogue DHCP = serveur DHCP non autorisé) |

---

## Comprendre la notation CIDR (/8, /16, /24, /48, /64...)

### Le principe : séparer réseau et hôte

Une adresse IP est composée de deux parties :
- **La partie réseau** : identifie le réseau (comme le nom d'une rue)
- **La partie hôte** : identifie l'appareil dans ce réseau (comme le numéro de maison)

La notation CIDR (Classless Inter-Domain Routing) indique **combien de bits sont réservés à la partie réseau**. Le reste est pour les hôtes.

### Notation CIDR en IPv4 (32 bits total)

Le nombre après le `/` indique le nombre de bits pour le réseau.

```
Adresse IPv4 : 192.168.1.0/24

En binaire (32 bits) :
11000000.10101000.00000001 | 00000000
<------ 24 bits réseau --->|<- 8 bits hôtes ->

/24 signifie : 24 bits pour le réseau, 8 bits pour les hôtes
```

**Calcul du nombre d'hôtes possibles** : 2^(bits hôtes) - 2

(On retire 2 : l'adresse réseau et l'adresse de broadcast)

| Notation CIDR | Bits réseau | Bits hôtes | Nombre d'hôtes | Masque décimal |
|---------------|-------------|------------|----------------|----------------|
| /8 | 8 | 24 | 16 777 214 | 255.0.0.0 |
| /16 | 16 | 16 | 65 534 | 255.255.0.0 |
| /24 | 24 | 8 | 254 | 255.255.255.0 |
| /25 | 25 | 7 | 126 | 255.255.255.128 |
| /26 | 26 | 6 | 62 | 255.255.255.192 |
| /27 | 27 | 5 | 30 | 255.255.255.224 |
| /28 | 28 | 4 | 14 | 255.255.255.240 |
| /29 | 29 | 3 | 6 | 255.255.255.248 |
| /30 | 30 | 2 | 2 | 255.255.255.252 |
| /31 | 31 | 1 | 2 (cas spécial) | 255.255.255.254 |
| /32 | 32 | 0 | 1 (hôte unique) | 255.255.255.255 |

### Le cas particulier du /31 (RFC 3021)

Avec la formule classique (2^n - 2), un /31 donnerait : 2^1 - 2 = 0 hôtes. Ça semble inutile !

**Problème théorique** :
```
Réseau /31 : 192.168.1.0/31
├── 192.168.1.0 → Adresse réseau (inutilisable ?)
└── 192.168.1.1 → Broadcast (inutilisable ?)
```

**Solution (RFC 3021)** : pour les liens **point-à-point** entre deux routeurs, on n'a pas besoin de broadcast. Les deux adresses peuvent être utilisées directement.

```
[Routeur A: 192.168.1.0] ←────────→ [Routeur B: 192.168.1.1]
                         Lien /31
```

**Pourquoi utiliser /31 ?**

| Avant (avec /30) | Après (avec /31) |
|------------------|------------------|
| 4 adresses par lien | 2 adresses par lien |
| 2 adresses gaspillées (réseau + broadcast) | 0 adresse gaspillée |
| Pour 1000 liens : 4000 IPs | Pour 1000 liens : 2000 IPs |

**Usage typique** : interconnexions entre routeurs dans les datacenters et chez les opérateurs. Économise 50% d'adresses IP sur les liens point-à-point.

**Attention** : le /31 ne fonctionne que pour les liens point-à-point (2 appareils uniquement). Pour un réseau avec plusieurs hôtes, utiliser /30 ou plus grand.

### Exemples concrets IPv4

```
10.0.0.0/8
├── Partie réseau : 10
├── Partie hôte : 0.0.0 à 255.255.255
└── Plage : 10.0.0.1 à 10.255.255.254 (16+ millions d'adresses)

192.168.1.0/24
├── Partie réseau : 192.168.1
├── Partie hôte : 0 à 255
└── Plage : 192.168.1.1 à 192.168.1.254 (254 adresses)

192.168.1.0/26
├── Partie réseau : 192.168.1 + 2 bits supplémentaires
├── Partie hôte : 6 bits
└── Plage : 192.168.1.1 à 192.168.1.62 (62 adresses)
```

### Correspondance CIDR et masque de sous-réseau

Le masque de sous-réseau est une autre façon d'exprimer la même chose :

```
/24 = 255.255.255.0

En binaire :
11111111.11111111.11111111.00000000
<------- 24 bits à 1 -----><- 8 bits à 0 ->

Les bits à 1 = partie réseau
Les bits à 0 = partie hôte
```

### Notation CIDR en IPv6 (128 bits total)

Le principe est identique, mais sur 128 bits au lieu de 32.

```
Adresse IPv6 : 2001:db8:1234::/48

128 bits au total :
<-- 48 bits réseau (préfixe global) --><-- 80 bits restants -->
```

| Notation CIDR | Bits réseau | Bits restants | Usage typique |
|---------------|-------------|---------------|---------------|
| /32 | 32 | 96 | Allocation à un FAI |
| /48 | 48 | 80 | Allocation à une organisation/site |
| /56 | 56 | 72 | Allocation à un particulier (certains FAI) |
| /64 | 64 | 64 | Un sous-réseau (standard) |
| /128 | 128 | 0 | Une seule adresse (hôte unique) |

### Structure typique d'une allocation IPv6

```
2001:0db8:1234:0056:0000:0000:0000:0001/64

|<--- 48 bits --->|<-- 16 -->|<----------- 64 bits ----------->|
|    Préfixe      |  Sous-   |         Interface ID            |
|    global       |  réseau  |                                 |
|   (du FAI)      | (local)  |      (identifie l'hôte)         |

Préfixe global /48 : 2001:db8:1234::/48 (attribué par le FAI)
Sous-réseau    /64 : 2001:db8:1234:56::/64 (géré par l'organisation)
```

**Explication** :
- Le FAI attribue un **/48** à l'organisation : `2001:db8:1234::/48`
- L'organisation dispose de 16 bits pour créer des sous-réseaux (2^16 = 65 536 sous-réseaux possibles)
- Chaque sous-réseau est un **/64** : `2001:db8:1234:0001::/64`, `2001:db8:1234:0002::/64`, etc.
- Dans chaque /64, il y a 64 bits pour les hôtes (2^64 = 18 quintillions d'adresses)

### Pourquoi /64 est le standard pour les sous-réseaux IPv6 ?

Le /64 est obligatoire pour que SLAAC (Stateless Address Autoconfiguration) fonctionne :
- 64 bits pour le préfixe réseau
- 64 bits pour l'interface ID (généré à partir de l'adresse MAC ou aléatoirement)

### Visualisation comparative

```
IPv4 /24 (réseau domestique typique) :
[-------- 24 bits réseau --------][8 bits hôtes]
         192.168.1                     .X
                                    254 hôtes

IPv6 /64 (sous-réseau standard) :
[----------- 64 bits réseau -----------][------- 64 bits hôtes -------]
        2001:db8:1234:56                    ::X
                                    18 446 744 073 709 551 616 hôtes
```

### Implications sécurité de la notation CIDR

| Aspect | Impact sécurité |
|--------|-----------------|
| Taille du réseau | Plus le réseau est grand (/8 vs /24), plus la surface d'attaque est large |
| Segmentation | Des sous-réseaux plus petits (/28, /29) limitent la propagation latérale |
| ACL/Firewall | Les règles utilisent la notation CIDR pour définir les plages autorisées/bloquées |
| Scan réseau | Scanner un /24 (254 hôtes) est trivial, scanner un /16 (65k hôtes) prend du temps |
| IPv6 /64 | Impossible à scanner par force brute (2^64 adresses), mais patterns prévisibles exploitables |

---

## IPv4

**Structure** : adresse sur 32 bits, divisée en 4 octets, notation décimale pointée.

```
11000000.10101000.00000001.00000001 → 192.168.1.1
```

Chaque octet va de 0 à 255 (2^8 = 256 valeurs possibles).

**Capacité totale** : environ 4,3 milliards d'adresses uniques.

### Plages réservées IPv4

| Adresse | Usage | Implications sécurité |
|---------|-------|----------------------|
| 127.0.0.1 | Loopback (test local) | Ne doit jamais apparaître sur le réseau. Si vu en trafic externe = anomalie/attaque |
| 169.254.0.0/16 | APIPA (quand DHCP échoue) | Indicateur de misconfiguration. Risque : appareil isolé sans protection réseau normale |
| 10.0.0.0/8 | Privé (RFC 1918) | Non routable sur internet. Doit être filtré en entrée/sortie (anti-spoofing) |
| 172.16.0.0/12 | Privé (RFC 1918) | Idem |
| 192.168.0.0/16 | Privé (RFC 1918) | Idem |
| 255.255.255.255 | Broadcast limité | Vecteur d'attaques (smurf, amplification). À filtrer si possible |

### Considérations sécurité IPv4

- **Adresses privées RFC 1918** : utilisées derrière NAT. Ne doivent jamais être routées sur internet. Un pare-feu bien configuré bloque ces plages en entrée (Bogon filtering/anti-spoofing).
- **APIPA (169.254.x.x)** : un appareil avec cette adresse n'a pas réussi à obtenir d'IP via DHCP. Peut indiquer une attaque DHCP starvation ou un rogue DHCP.
- **Broadcast** : utilisé par ARP et DHCP, deux protocoles vulnérables (ARP spoofing/poisoning, DHCP starvation, rogue DHCP server).

---

## IPv6

**Structure** : adresse sur 128 bits, notation hexadécimale, 8 hextets séparés par des deux-points.

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

**Capacité** : 3,4 x 10^38 adresses.

### Règles de simplification

1. Zéros en tête omis : `0db8` → `db8`
2. Séquence de zéros consécutifs remplacée par `::` (une seule fois par adresse)

```
2001:0db8:0000:0000:0000:0000:0000:0001 → 2001:db8::1
fe80:0000:0000:0000:0202:b3ff:fe1e:8329 → fe80::202:b3ff:fe1e:8329
```

### Notation préfixe (rappel)

IPv6 utilise la notation CIDR (voir section détaillée plus haut) : `2001:db8::/64` signifie 64 bits pour le réseau, 64 bits pour l'hôte.

### Structure hiérarchique IPv6

Une adresse IPv6 typique se décompose ainsi :

```
2001:0db8:1234:0056:0202:b3ff:fe1e:8329

|<--- Préfixe global --->|<- Sous ->|<----- Interface ID ----->|
|      (48 bits)         |  réseau  |       (64 bits)          |
|    Attribué par FAI    | (16 bits)|   Identifie l'appareil   |
```

- **Préfixe global** (/48) : attribué par le FAI à l'organisation
- **Sous-réseau** (16 bits) : géré par l'organisation (permet 65 536 sous-réseaux)
- **Interface ID** (64 bits) : identifie l'appareil dans le sous-réseau

**Exemple concret** :
- Le FAI attribue `2001:db8:abcd::/48` à une entreprise
- L'entreprise crée le sous-réseau RH : `2001:db8:abcd:0001::/64`
- L'entreprise crée le sous-réseau IT : `2001:db8:abcd:0002::/64`
- Un PC dans le sous-réseau IT obtient : `2001:db8:abcd:0002:a1b2:c3d4:e5f6:7890`

### Plages réservées IPv6

| Adresse | Usage | Implications sécurité |
|---------|-------|----------------------|
| ::1 | Loopback | Équivalent 127.0.0.1, mêmes considérations |
| fe80::/10 | Link-local | Non routable, portée limitée au lien. Utilisé par NDP (vulnérable au spoofing) |
| fc00::/7 | ULA (équivalent privé) | Non routable sur internet, filtrage recommandé |
| ::/128 | Non spécifié | Appareil sans adresse, état transitoire |
| ff00::/8 | Multicast | Remplace broadcast. Certains groupes multicast sensibles à surveiller |

### Comprendre les adresses link-local et la notion de "portée"

#### Qu'est-ce qu'un "lien" (link) ?

Un **lien** est un segment de réseau où les appareils peuvent communiquer directement entre eux sans passer par un routeur. Concrètement :

- Tous les appareils connectés au même switch
- Tous les appareils sur le même réseau Wi-Fi
- Deux machines reliées par un câble Ethernet direct

```
[PC1]---[Switch]---[PC2]      ← Même lien (layer 2)
           |
        [Routeur]
           |
[PC3]---[Switch]---[PC4]      ← Autre lien (layer 2)
```

PC1 et PC2 sont sur le même lien. PC3 et PC4 sont sur un autre lien. Pour que PC1 communique avec PC3, il doit passer par le routeur.

#### Adresses link-local (fe80::/10)

Une adresse **link-local** est une adresse IPv6 qui ne fonctionne que sur le lien local. Elle ne traverse jamais un routeur.

**Caractéristiques** :
- Commence toujours par `fe80::`
- Générée automatiquement par chaque interface réseau (pas besoin de DHCP)
- Utilisable uniquement pour communiquer avec les voisins directs
- Les routeurs ne la transmettent jamais vers d'autres réseaux

**Exemple** :

```
Adresse link-local typique : fe80::1a2b:3c4d:5e6f:7890

fe80:0000:0000:0000:1a2b:3c4d:5e6f:7890
|<-- Préfixe fixe -->|<-- Interface ID (64 bits) -->|
     (10 bits)              (généré localement)
```

#### Pourquoi "portée limitée au lien" ?

Les routeurs sont programmés pour **ne jamais faire suivre** (forward) un paquet avec une adresse source ou destination link-local. C'est une règle fondamentale d'IPv6.

```
[PC1: fe80::1] -----> [Routeur] ----X---> [PC2: fe80::2]
                          |
                    "Je refuse de
                     router fe80::"
```

**Conséquence** : une adresse fe80:: ne peut communiquer qu'avec les autres fe80:: du même segment physique.

#### À quoi servent les adresses link-local ?

Elles sont essentielles pour le fonctionnement d'IPv6 :

| Usage | Description |
|-------|-------------|
| NDP (Neighbor Discovery) | Découverte des voisins, équivalent d'ARP |
| Router Discovery | Les PC trouvent leur routeur via son adresse link-local |
| DHCPv6 | Communication initiale avec le serveur DHCP |
| Protocoles de routage | OSPF et autres protocoles utilisent link-local entre routeurs |

**Exemple concret** : la commande `ip -6 route` sur Linux affiche souvent une passerelle par défaut en adresse link-local :

```
default via fe80::1 dev eth0
```

Le PC connaît son routeur par son adresse link-local, pas par son adresse globale.

#### Spécifier l'interface avec les adresses link-local

Problème : plusieurs interfaces peuvent avoir des voisins avec la même adresse link-local (fe80::1 existe sur chaque lien).

Solution : on spécifie l'interface avec `%` :

```bash
ping fe80::1%eth0      # Ping fe80::1 via l'interface eth0
ping fe80::1%wlan0     # Ping fe80::1 via l'interface wlan0

ssh user@fe80::1%eth0  # Connexion SSH via eth0
```

Le `%eth0` s'appelle le **zone ID** ou **scope ID**.

#### Les différentes portées (scopes) en IPv6

IPv6 définit plusieurs niveaux de portée :

| Portée | Préfixe | Traverse un routeur ? | Usage |
|--------|---------|----------------------|-------|
| Node-local | ::1 (loopback) | Non | Communication interne à la machine |
| Link-local | fe80::/10 | Non | Communication sur le lien local uniquement |
| Unique Local (ULA) | fc00::/7 | Oui (en interne) | Équivalent des IP privées, routables en interne |
| Global | 2000::/3 | Oui | Adresses publiques internet |

#### Implications sécurité des adresses link-local

**Avantages** :
- Isolation naturelle : impossible d'attaquer une machine via son fe80:: depuis internet
- Fonctionne même sans configuration réseau (utile pour le troubleshooting)

**Risques** :
- Vulnérable aux attaques locales (NDP spoofing, rogue router advertisement)
- Un attaquant sur le même lien peut usurper des adresses link-local
- Les adresses link-local sont utilisées par NDP, qui n'a pas d'authentification par défaut

**Contre-mesures** :
- SEND (Secure Neighbor Discovery)
- RA Guard sur les switches
- Segmentation physique des réseaux sensibles

#### Comparaison avec IPv4

| Concept IPv6 | Équivalent IPv4 |
|--------------|-----------------|
| Link-local (fe80::/10) | APIPA (169.254.0.0/16) |
| ULA (fc00::/7) | Adresses privées RFC 1918 (10.x, 172.16.x, 192.168.x) |
| Global (2000::/3) | Adresses publiques |

La différence majeure : en IPv6, les adresses link-local sont **obligatoires** et **toujours présentes** sur chaque interface. En IPv4, APIPA n'est utilisé qu'en cas d'échec DHCP.

---

## Types d'adresses et implications sécurité

### Unicast

Communication point à point. Le plus courant et le plus simple à tracer/filtrer.

### Multicast

Un vers plusieurs (abonnement à des groupes).

- IPv4 : 224.0.0.0 à 239.255.255.255
- IPv6 : ff00::/8
- **Sécurité** : peut être utilisé pour de la reconnaissance réseau. Certains groupes multicast révèlent des informations (ff02::1 = tous les noeuds, ff02::2 = tous les routeurs).

### Broadcast (IPv4 uniquement)

Un vers tous sur le sous-réseau.

- **Sécurité** : vecteur d'attaques classiques (smurf attack, broadcast storm). IPv6 l'a supprimé volontairement.
- Utilisé par ARP (vulnérable au spoofing/poisoning) et DHCP (vulnérable aux rogue servers et starvation).

### Anycast

Un vers le plus proche. Utilisé pour CDN, DNS racine.

- **Sécurité** : utile pour la résilience et l'atténuation DDoS (distribution de charge géographique).

---

## Concepts sécurité critiques

### NAT (Network Address Translation)

**En IPv4** : NAT masque les adresses privées derrière une IP publique.

- **Avantage sécurité perçu** : les machines internes ne sont pas directement exposées sur internet (security through obscurity partiel).
- **Inconvénient** : casse la connectivité de bout en bout, complique certains protocoles (VoIP, P2P), nécessite du port forwarding qui peut créer des failles.

**En IPv6** : NAT n'est plus nécessaire (assez d'adresses pour tous).

- **Conséquence** : chaque appareil peut avoir une IP publique unique = exposition directe potentielle.
- **Impératif** : le pare-feu devient absolument critique. La sécurité ne peut plus reposer sur l'obscurité du NAT.

### IPsec

**IPv4** : IPsec est optionnel, ajouté après coup.

**IPv6** : IPsec était prévu pour être obligatoire dans la spécification initiale (maintenant "fortement recommandé").

- Chiffrement et authentification intégrés au niveau IP.
- Modes : transport (payload chiffré) et tunnel (paquet entier encapsulé).
- Headers : AH (Authentication Header) pour l'intégrité, ESP (Encapsulating Security Payload) pour confidentialité + intégrité.

### NDP (Neighbor Discovery Protocol) en IPv6

NDP est le protocole qui permet aux appareils IPv6 de se découvrir mutuellement sur un réseau local. Il remplace plusieurs protocoles IPv4 (ARP, ICMP Router Discovery, ICMP Redirect) en un seul protocole unifié basé sur ICMPv6.

#### Fonctions principales de NDP

| Fonction | Description | Équivalent IPv4 |
|----------|-------------|-----------------|
| Résolution d'adresses | Trouver l'adresse MAC associée à une IPv6 | ARP |
| Découverte de routeurs | Trouver les routeurs sur le lien local | ICMP Router Discovery |
| Découverte de préfixes | Apprendre quels préfixes sont disponibles | (manuel ou DHCP) |
| Détection d'adresses dupliquées (DAD) | Vérifier qu'une adresse n'est pas déjà utilisée | ARP Gratuit |
| Redirection | Informer d'une meilleure route | ICMP Redirect |

#### Messages NDP (types ICMPv6)

| Message | Code | Rôle |
|---------|------|------|
| Router Solicitation (RS) | 133 | "Y a-t-il un routeur ici ?" (envoyé par les hôtes) |
| Router Advertisement (RA) | 134 | "Je suis un routeur, voici le préfixe réseau" (envoyé par les routeurs) |
| Neighbor Solicitation (NS) | 135 | "Qui a cette adresse IPv6 ?" (équivalent ARP request) |
| Neighbor Advertisement (NA) | 136 | "C'est moi, voici mon adresse MAC" (équivalent ARP reply) |
| Redirect | 137 | "Utilise plutôt ce routeur pour cette destination" |

#### Fonctionnement simplifié

```
1. PC démarre, génère son adresse link-local (fe80::...)
2. PC envoie Router Solicitation (RS) vers ff02::2 (tous les routeurs)
3. Routeur répond avec Router Advertisement (RA) contenant le préfixe
4. PC génère son adresse globale avec le préfixe + son interface ID
5. PC vérifie que l'adresse n'est pas déjà prise (DAD via NS/NA)
6. Pour communiquer, PC utilise NS/NA pour résoudre IPv6 → MAC
```

#### Vulnérabilités NDP (similaires à ARP)

| Attaque | Description | Impact |
|---------|-------------|--------|
| NA spoofing | Fausses réponses Neighbor Advertisement | Empoisonnement du cache, MitM |
| RA spoofing | Fausses annonces de routeur | Redirection du trafic, DoS, MitM |
| NS flooding | Saturation avec des requêtes NS | DoS, épuisement des ressources |
| DAD attack | Répondre à toutes les vérifications DAD | Empêcher les hôtes d'obtenir une adresse |

#### Contre-mesures NDP

- **SEND (SEcure Neighbor Discovery)** : authentification cryptographique des messages NDP
- **RA Guard** : filtrage des Router Advertisements sur les ports non autorisés (switches)
- **ND Inspection** : validation des messages NDP contre une table de confiance (similaire à DAI pour ARP)
- **Segmentation** : limiter la portée des attaques en segmentant les réseaux

### Reconnaissance et scan

**IPv4** : scanner un /24 (256 adresses) est trivial.

**IPv6** : scanner un /64 standard (2^64 adresses) est théoriquement impossible par force brute.

- **Mais** : les attaquants utilisent des techniques de découverte ciblée (DNS, patterns d'adresses prévisibles comme SLAAC basé sur MAC, adresses basses).
- **Recommandation** : utiliser des adresses IPv6 aléatoires (privacy extensions, RFC 4941) plutôt que basées sur l'adresse MAC.

### Privacy extensions (RFC 4941)

SLAAC (Stateless Address Autoconfiguration) génère par défaut l'interface ID à partir de l'adresse MAC (via EUI-64).

- **Problème** : permet le tracking d'un appareil à travers les réseaux.
- **Solution** : privacy extensions génèrent des interface ID aléatoires et temporaires.
- **Vérification** : s'assurer que les privacy extensions sont activées sur les postes clients.

---

## Coexistence IPv4/IPv6 et risques associés

### Dual stack

Appareils avec IPv4 et IPv6 simultanément.

- **Risque** : double surface d'attaque. Les règles de pare-feu doivent couvrir les deux protocoles. Oublier de sécuriser IPv6 est une erreur classique.
- **Risque supplémentaire** : si IPv6 est activé par défaut mais non géré, un attaquant peut exploiter ce vecteur ignoré.

### Tunneling (6to4, ISATAP, Teredo)

IPv6 encapsulé dans IPv4.

- **Risques sécurité majeurs** :
  - Contourne potentiellement les pare-feux qui n'inspectent pas le contenu des tunnels.
  - Teredo notamment est connu pour créer des chemins de communication non contrôlés.
  - Peut permettre l'exfiltration de données ou le bypass de contrôles.
- **Recommandation** : désactiver les mécanismes de tunneling automatique si non nécessaires, ou les contrôler strictement.

### Translation (NAT64/DNS64)

Conversion entre protocoles.

- **Complexité** : ajoute des couches pouvant masquer l'origine réelle du trafic.
- **Logs** : s'assurer que la corrélation d'adresses est possible pour l'investigation.

---

## Checklist sécurité

1. **Filtrage Bogon/RFC 1918** : bloquer les adresses privées et réservées en entrée sur les interfaces publiques
2. **Pare-feu IPv6** : ne pas oublier de configurer des règles pour IPv6 si dual stack
3. **Désactiver les tunnels automatiques** : 6to4, ISATAP, Teredo si non utilisés
4. **Privacy extensions** : activer sur les postes clients pour éviter le tracking MAC
5. **Protection NDP/ARP** : RA Guard, DHCP snooping, Dynamic ARP Inspection
6. **Monitoring multicast** : surveiller les requêtes vers les groupes ff02::1 et ff02::2
7. **IPsec** : utiliser pour les communications sensibles, surtout en IPv6
8. **Logs et corrélation** : s'assurer de pouvoir tracer les adresses à travers NAT/NAT64

---

# Annexe : description des attaques réseau

## 1. ARP spoofing / ARP cache poisoning

### Principe

L'ARP spoofing, également connu sous le nom d'ARP poisoning, est une attaque Man-in-the-Middle (MitM) qui permet aux attaquants d'intercepter les communications entre les appareils du réseau.

Le protocole ARP (Address Resolution Protocol) est utilisé pour résoudre les adresses de couche réseau (IP) en adresses de couche liaison (MAC). Le protocole ARP n'a pas été conçu avec la sécurité en tête, donc il ne vérifie pas qu'une réponse ARP provient réellement d'une partie autorisée. Il permet aussi aux hôtes d'accepter des réponses ARP même s'ils n'ont jamais envoyé de requête.

### Fonctionnement de l'attaque

L'attaquant envoie des réponses ARP falsifiées pour une adresse IP donnée, typiquement la passerelle par défaut d'un sous-réseau particulier. Cela amène les machines victimes à remplir leur cache ARP avec l'adresse MAC de la machine de l'attaquant au lieu de l'adresse MAC du routeur local.

Les machines victimes vont alors transmettre incorrectement leur trafic réseau vers l'attaquant. Des outils comme Ettercap permettent à l'attaquant d'agir comme un proxy, visualisant ou modifiant les informations avant de les transmettre à leur destination prévue.

### Conséquences

Une fois l'attaque réussie, l'attaquant peut :

- Continuer à router les communications telles quelles pour espionner les paquets et voler des données (sauf si elles sont chiffrées via HTTPS)
- Effectuer un détournement de session s'il obtient un identifiant de session
- Altérer les communications
- Lancer une attaque DDoS en fournissant l'adresse MAC d'un serveur cible au lieu de sa propre machine

### Contre-mesures

- Utiliser un VPN pour chiffrer toutes les communications
- Configurer des entrées ARP statiques pour les services critiques
- Utiliser le filtrage de paquets pour identifier et bloquer les paquets ARP empoisonnés
- Implémenter des systèmes de détection d'intrusion (IDS) pour surveiller les requêtes ARP anormales
- Segmenter le réseau en VLANs pour réduire la portée des attaques

### Outils d'attaque

Ettercap, arpspoof (Kali Linux), MITMf, Cain & Abel

### Référence MITRE ATT&CK

T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning

### Liens

- https://attack.mitre.org/techniques/T1557/002/
- https://www.imperva.com/learn/application-security/arp-spoofing/
- https://www.varonis.com/blog/arp-poisoning
- https://en.wikipedia.org/wiki/ARP_spoofing

---

## 2. DHCP starvation

### Principe

Dans les attaques DHCP starvation, un attaquant inonde le serveur DHCP avec des requêtes DHCP pour consommer toutes les adresses IP disponibles que le serveur DHCP peut allouer.

Pour réaliser cette attaque, l'attaquant envoie un grand nombre de messages DHCP Discover falsifiés avec des adresses MAC source usurpées. Le serveur DHCP tente de répondre à tous ces messages, et par conséquent, le pool d'adresses IP est épuisé.

### Fonctionnement de l'attaque

L'attaquant envoie un flot de faux messages DHCP Discover avec des adresses MAC usurpées. Le serveur DHCP répond avec un message DHCP Offer à chacun des messages Discover précédemment reçus. Toutes les adresses IP disponibles deviennent très rapidement réservées pour ces "potentiels" clients DHCP, pendant une période donnée. Puisque ces clients n'existent pas réellement, le serveur DHCP ne recevra jamais de message DHCP Request en retour.

### Conséquences

- Un utilisateur légitime ne pourra pas obtenir d'adresse IP via DHCP (déni de service)
- L'attaquant peut mettre en place un serveur DHCP pirate pour assigner des adresses IP aux utilisateurs légitimes
- Les attaques DHCP starvation sont souvent réalisées avant une attaque DHCP spoofing pour désactiver le serveur DHCP légitime

### Contre-mesures

- **Port security** : limiter le nombre d'adresses MAC apprises par port et appliquer une action (fermeture de l'interface) en cas de violation
- **DHCP snooping** : fonctionnalité de sécurité de couche 2 qui construit et maintient une table de liaison DHCP snooping

### Outils d'attaque

Yersinia, Gobbler, DHCPIG

### Liens

- https://www.prosec-networks.com/en/blog/dhcp-starvation-attack/
- https://www.geeksforgeeks.org/ethical-hacking/dhcp-starvation-attack/
- https://info.pivitglobal.com/resources/dhcp-spoofing-and-starvation-attacks

---

## 3. Rogue DHCP server (serveur DHCP pirate)

### Principe

Un serveur DHCP pirate est un serveur DHCP sur un réseau qui n'est pas sous le contrôle administratif du personnel réseau. Il peut s'agir d'un appareil réseau comme un modem ou un routeur connecté par un utilisateur qui peut ne pas être conscient des conséquences de ses actions, ou qui l'utilise sciemment pour des attaques réseau comme le man-in-the-middle.

### Fonctionnement de l'attaque

Lorsque des clients se connectent au réseau, à la fois le serveur DHCP pirate et le serveur légitime leur offrent des adresses IP ainsi que la passerelle par défaut, les serveurs DNS, les serveurs WINS, etc. Si les informations fournies par le serveur DHCP pirate diffèrent de celles du serveur réel, les clients qui acceptent des adresses IP de celui-ci peuvent rencontrer des problèmes d'accès réseau.

En interceptant le trafic passant par le serveur DHCP, l'attaquant peut lancer des attaques man-in-the-middle, intercepter des informations sensibles et compromettre la sécurité des utilisateurs.

### Conséquences

- Redirection du trafic vers des serveurs malveillants
- DNS spoofing
- Attaques man-in-the-middle
- Interception de données sensibles

### Contre-mesures

- **DHCP snooping** : rejette les messages DHCP provenant de serveurs DHCP non fiables (ports trusted/untrusted)
- **Autorisation AD DS** : dans les environnements Microsoft, autoriser uniquement les serveurs DHCP légitimes
- **Isolation VLAN** : isoler le serveur DHCP avec des VLANs et ACLs
- **Port security** : limiter les adresses MAC autorisées par port
- **IP Source Guard** : filtrer le trafic IP basé sur les adresses MAC et IP source
- **Monitoring** : surveillance active des réponses DHCP sur le réseau

### Outils de détection

Nmap, Wireshark, DHCP Sentry, Roadkil.net DHCP Find, dhcp_probe

### Liens

- https://en.wikipedia.org/wiki/Rogue_DHCP
- https://www.auvik.com/franklyit/blog/rogue-dhcp-server/
- https://www.manageengine.com/products/oputils/tech-topics/rogue-dhcp-servers.html
- https://www.techtarget.com/searchsecurity/tip/How-to-defend-against-rogue-DHCP-server-malware

---

## 4. NDP spoofing (attaques IPv6)

### Principe

Les noeuds IPv6 (hôtes et routeurs) utilisent le Neighbor Discovery Protocol (NDP) pour découvrir la présence et les adresses de couche liaison des autres noeuds résidant sur le même lien. Les messages NDP ne sont pas sécurisés, ce qui rend NDP susceptible aux attaques impliquant l'usurpation d'adresses de couche liaison.

NDP est responsable du mappage des adresses IPv6 vers les adresses MAC et de la découverte de la disponibilité des appareils voisins sur le réseau.

### Types d'attaques NDP

- **RA Flooding** : envoie un grand nombre de messages Router Advertisement à un hôte spécifique ou à tous les noeuds multicast
- **NS Flooding** : inonde les réseaux IPv6 avec un grand nombre de messages Neighbor Solicitation, causant la suppression des entrées dans le cache voisin
- **Neighbor Spoofing** : l'attaquant usurpe l'identité d'un voisin légitime en envoyant de faux messages NDP avec une adresse IP ou MAC usurpée
- **Cache poisoning** : équivalent IPv6 de l'ARP spoofing, l'attaquant associe sa propre adresse MAC avec une adresse IP réseau légitime
- **Attaques DoS de routage** : l'attaquant amène un hôte à désactiver son routeur de premier saut
- **Attaques de redirection** : l'attaquant utilise les messages ICMPv6 redirect pour intercepter le trafic

### Contre-mesures

- **SEND (Secure Neighbor Discovery)** : protocole de sécurité pour NDP utilisant des adresses cryptographiquement générées (CGA)
- **RA Guard** : configuration sur les switches pour prévenir les router advertisements pirates
- **DHCPv6 snooping** : inspection des messages neighbor discovery contre la table de snooping DHCPv6
- **ND Inspection** : vérification des messages NDP sur les interfaces non fiables

### Outils d'attaque

THC-IPv6, IPv6 Toolkit, Scapy

### Liens

- https://www.mdpi.com/2073-431X/12/6/125
- https://www.hpc.mil/solution-areas/networking/ipv6-knowledge-base/ipv6-knowledge-base-security/neighbor-discovery-protocol-attacks
- https://www.juniper.net/documentation/us/en/software/junos/security-services/topics/concept/port-security-nd-inspection.html
- https://www.cbtnuggets.com/blog/technology/networking/what-is-neighbor-discovery-protocol-ndp

---

## Tableau récapitulatif des contre-mesures

| Attaque | Contre-mesures principales |
|---------|---------------------------|
| ARP spoofing | Dynamic ARP Inspection (DAI), entrées ARP statiques, VPN, segmentation VLAN |
| DHCP starvation | Port security (limite MAC/port), DHCP snooping |
| Rogue DHCP server | DHCP snooping (ports trusted/untrusted), autorisation AD DS, monitoring |
| NDP spoofing (IPv6) | SEND, RA Guard, DHCPv6 snooping, ND Inspection |

---

## Ressources

### Documentation Cisco

- https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_switching/network_mgmt/b_Network_Mgmt_Catalyst_Switches/b_Network_Mgmt_Catalyst_Switches_chapter_0111.html

### NIST SP 800-119

Guidelines for the Secure Deployment of IPv6 : https://csrc.nist.gov/publications/detail/sp/800-119/final

### RFC pertinentes

| RFC | Description |
|-----|-------------|
| RFC 826 | ARP (Address Resolution Protocol) |
| RFC 2131 | DHCP (Dynamic Host Configuration Protocol) |
| RFC 4861 | NDP (Neighbor Discovery for IPv6) |
| RFC 3971 | SEND (SEcure Neighbor Discovery) |
| RFC 4941 | Privacy Extensions for SLAAC |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Introduction aux concepts fondamentaux du réseau (IP, subnetting) | https://tryhackme.com/room/introtonetworking |
| **What is Networking?** | Concepts de base du réseau et adressage IP | https://tryhackme.com/room/whatisnetworking |
| **Networking Essentials** | Fondamentaux du réseau incluant IPv4/IPv6 | https://tryhackme.com/room/dvwa |
| **Layer 2 MAC Flooding & ARP Spoofing** | Attaques sur ARP et NDP | https://tryhackme.com/r/room/dvwa |
