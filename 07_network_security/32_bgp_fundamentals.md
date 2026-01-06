# BGP - Border Gateway Protocol

## Objectifs du cours

Ce cours explore en profondeur le Border Gateway Protocol (BGP), la pierre angulaire du routage Internet moderne. Nous decouvrirons ce qui rend BGP essentiel pour la connectivite globale, explorerons sa logique et ses politiques, et analyserons son utilisation dans les backbones ISP et les environnements d'entreprise.

Competences visees :
- Comprendre les principes du routage path-vector et le role des numeros AS
- Differencier le comportement de iBGP (internal BGP) et eBGP (external BGP)
- Configurer le peering, les annonces de routes et le filtrage avec precision
- Apprecier comment BGP est applique dans le contexte des fournisseurs de services et des WAN d'entreprise
- Identifier les vulnerabilites BGP et les mesures de securisation

---

## Glossaire

### Concepts fondamentaux

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **BGP** | Border Gateway Protocol | Protocole de routage inter-AS (EGP) de l'Internet |
| **AS** | Autonomous System | Ensemble de reseaux sous une meme administration |
| **ASN** | Autonomous System Number | Identifiant unique d'un AS (16 ou 32 bits) |
| **EGP** | Exterior Gateway Protocol | Categorie de protocoles de routage inter-AS |
| **IGP** | Interior Gateway Protocol | Protocole de routage intra-AS (OSPF, EIGRP) |
| **Path-Vector** | Vecteur de chemin | Type de protocole utilisant le chemin d'AS comme metrique |

### Types de BGP

| Terme | Description |
|-------|-------------|
| **eBGP** | External BGP - Peering entre AS differents |
| **iBGP** | Internal BGP - Peering au sein du meme AS |
| **MP-BGP** | Multiprotocol BGP - Extension pour IPv6, VPN, etc. |

### Attributs BGP

| Attribut | Type | Description |
|----------|------|-------------|
| **AS_PATH** | Well-known mandatory | Liste des AS traverses |
| **NEXT_HOP** | Well-known mandatory | Adresse IP du prochain saut |
| **ORIGIN** | Well-known mandatory | Origine de la route (IGP, EGP, Incomplete) |
| **LOCAL_PREF** | Well-known discretionary | Preference locale (plus haut = meilleur) |
| **MED** | Optional non-transitive | Multi-Exit Discriminator (plus bas = meilleur) |
| **WEIGHT** | Cisco proprietary | Poids local (plus haut = meilleur) |
| **COMMUNITY** | Optional transitive | Tag pour le filtrage et les politiques |
| **ATOMIC_AGGREGATE** | Well-known discretionary | Indique une route summarisee |
| **AGGREGATOR** | Optional transitive | Identifie le routeur qui a summarise |

### Termes de peering

| Terme | Description |
|-------|-------------|
| **Peer / Neighbor** | Routeur BGP avec lequel une session est etablie |
| **Peering** | Relation d'echange de routes entre deux AS |
| **Transit** | AS qui transporte le trafic entre deux autres AS |
| **Upstream** | Fournisseur de connectivite Internet |
| **Downstream** | Client recevant la connectivite |
| **Full Table** | Table de routage Internet complete (~900k+ routes) |
| **Default Route** | Route par defaut (0.0.0.0/0) |

### Mecanismes avances

| Terme | Description |
|-------|-------------|
| **Route Reflector** | Routeur iBGP centralisant la distribution de routes |
| **Confederation** | Division d'un AS en sous-AS pour la scalabilite |
| **AS_PATH Prepending** | Ajout d'AS pour influencer la selection de route |
| **Route Aggregation** | Summarization de prefixes BGP |
| **Prefix-list** | Liste pour filtrer les prefixes IP |
| **AS-path ACL** | Liste pour filtrer selon l'AS_PATH |

### Termes de securite

| Terme | Description |
|-------|-------------|
| **BGP Hijacking** | Annonce illegitime de prefixes d'un autre AS |
| **Route Leak** | Propagation non autorisee de routes |
| **RPKI** | Resource Public Key Infrastructure - Validation des origines |
| **ROA** | Route Origin Authorization - Certificat d'origine |
| **BGPsec** | Extension de securite pour BGP |

---

## Logique Path-Vector, Numeros AS et AS_PATH

BGP est different des protocoles link-state ou distance-vector. C'est un protocole **path-vector**, utilisant une liste de systemes autonomes (AS) que la route doit traverser pour atteindre sa destination.

### Numeros de Systeme Autonome (ASN)

Chaque AS est identifie par un numero unique (ASN) :

| Type | Plage | Usage |
|------|-------|-------|
| **Public 16-bit** | 1-64495 | Internet global |
| **Private 16-bit** | 64512-65534 | Usage interne, non propage |
| **Reserved** | 64496-64511, 65535 | Documentation, reserve |
| **Public 32-bit** | 65536-4294967294 | Extension (AS.AS notation) |
| **Private 32-bit** | 4200000000-4294967294 | Usage interne etendu |

Les ASN publics sont attribues par les registres regionaux :
- **ARIN** : Amerique du Nord
- **RIPE NCC** : Europe, Moyen-Orient
- **APNIC** : Asie-Pacifique
- **LACNIC** : Amerique Latine
- **AFRINIC** : Afrique

### L'attribut AS_PATH

L'AS_PATH est l'outil de decision le plus critique en BGP :

1. Chaque fois qu'une route passe par un AS, cet ASN est **prepend** a l'AS_PATH
2. Si un routeur recoit une route contenant son propre ASN, il la **rejette** (prevention des boucles)
3. Plus l'AS_PATH est **court**, plus la route est **preferee**

**Exemple :**
```
Route recue avec AS_PATH: 65001 65002 65003
- La route a traverse 3 AS
- Si votre ASN est 65001, vous rejetez cette route (boucle detectee)
- Si votre ASN est 65004, vous acceptez et prepend : 65004 65001 65002 65003
```

### AS_PATH Prepending

Technique pour rendre une route moins attractive en ajoutant son propre ASN plusieurs fois :

```
Route originale :     AS_PATH: 65001
Apres prepending x3 : AS_PATH: 65001 65001 65001 65001
```

Cela influence le choix des autres AS qui preferent les chemins plus courts.

### Processus de selection BGP

BGP utilise une collection d'attributs pour prendre ses decisions, dans cet ordre de priorite :

| Priorite | Attribut | Critere |
|----------|----------|---------|
| 1 | **Weight** | Plus haut = meilleur (Cisco, local) |
| 2 | **Local Preference** | Plus haut = meilleur |
| 3 | **Locally Originated** | Routes locales preferees |
| 4 | **AS_PATH** | Plus court = meilleur |
| 5 | **Origin** | IGP < EGP < Incomplete |
| 6 | **MED** | Plus bas = meilleur |
| 7 | **eBGP > iBGP** | eBGP prefere |
| 8 | **IGP Metric** | Plus bas = meilleur |
| 9 | **Oldest Route** | Route la plus ancienne |
| 10 | **Router ID** | Plus bas = meilleur |
| 11 | **Neighbor IP** | Plus bas = meilleur |

Cette complexite donne aux ingenieurs un controle fin sur les politiques de routage a l'echelle d'Internet.

---

## iBGP vs eBGP

![iBGP vs eBGP](assets/iBGP-and-eBGP.webp)

### eBGP (External BGP)

eBGP forme des relations entre routeurs de **differents systemes autonomes**. C'est la fondation du routage Internet.

**Caracteristiques cles :**

| Aspect | Comportement |
|--------|--------------|
| TTL par defaut | 1 (peers directement connectes) |
| Next-hop | Change vers l'IP du peer eBGP |
| AD (Administrative Distance) | 20 |
| Propagation | Routes annoncees aux peers iBGP et eBGP |
| AS_PATH | ASN du peer ajoute a la reception |

**Configuration eBGP :**
```cisco
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
```

**eBGP multi-hop :**
Pour des peers non directement connectes :
```cisco
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 ebgp-multihop 2
```

### iBGP (Internal BGP)

iBGP est utilise **au sein du meme AS** pour partager les routes externes apprises via eBGP.

**Caracteristiques cles :**

| Aspect | Comportement |
|--------|--------------|
| TTL par defaut | 255 (pas de restriction) |
| Next-hop | **Non modifie** (preserve le next-hop eBGP) |
| AD (Administrative Distance) | 200 |
| Propagation | Routes **non** annoncees aux autres peers iBGP |
| AS_PATH | Non modifie |

**Configuration iBGP :**
```cisco
router bgp 65001
 neighbor 192.168.1.2 remote-as 65001
 neighbor 192.168.1.2 update-source Loopback0
```

### Regle critique iBGP : Split Horizon

**Regle :** Un routeur iBGP **n'annonce pas** les routes apprises d'un peer iBGP vers d'autres peers iBGP.

**Consequence :** Necessite d'un **full-mesh** de sessions iBGP.

| Nombre de routeurs | Sessions iBGP necessaires |
|-------------------|---------------------------|
| 4 | 6 |
| 10 | 45 |
| 50 | 1225 |
| 100 | 4950 |

Formule : n*(n-1)/2

### Solutions au full-mesh

#### 1. Route Reflectors (RR)

Un ou plusieurs routeurs designes pour redistribuer les routes aux clients iBGP :

```cisco
! Configuration du Route Reflector
router bgp 65001
 neighbor 192.168.1.2 remote-as 65001
 neighbor 192.168.1.2 route-reflector-client
 neighbor 192.168.1.3 remote-as 65001
 neighbor 192.168.1.3 route-reflector-client
```

**Avantages :**
- Reduit drastiquement le nombre de sessions
- Simple a implementer
- Hierarchie possible (RR de RR)

#### 2. Confederations

Division de l'AS en sous-AS internes :

```cisco
router bgp 65001
 bgp confederation identifier 65000
 bgp confederation peers 65002 65003
```

Les sous-AS utilisent eBGP entre eux mais apparaissent comme un seul AS vers l'exterieur.

### Probleme du Next-Hop iBGP

iBGP preserve le next-hop eBGP original, ce qui peut causer des problemes :

```
Internet --- R1 (eBGP) --- R2 (iBGP) --- R3 (iBGP)
             10.0.0.1

R1 apprend une route avec next-hop 10.0.0.1
R1 annonce a R2 avec next-hop 10.0.0.1 (preserve)
R3 ne peut pas joindre 10.0.0.1 directement !
```

**Solution :** `next-hop-self`
```cisco
router bgp 65001
 neighbor 192.168.1.2 remote-as 65001
 neighbor 192.168.1.2 next-hop-self
```

---

## Annonces de routes, Peering et Filtrage

### Etablissement du Peering BGP

Contrairement a OSPF ou EIGRP, BGP ne decouvre pas automatiquement ses voisins. Le peering est configure manuellement.

**Processus d'etablissement :**
1. Configuration manuelle des neighbors
2. Etablissement d'une session TCP (port 179)
3. Echange de messages OPEN
4. Negociation des capacites
5. Echange initial de la table de routage complete
6. Envoi d'updates incrementaux

**Etats de la session BGP :**

| Etat | Description |
|------|-------------|
| **Idle** | Pas de tentative de connexion |
| **Connect** | Tentative de connexion TCP |
| **Active** | Attente de connexion entrante |
| **OpenSent** | Message OPEN envoye |
| **OpenConfirm** | Message OPEN recu, attente de KEEPALIVE |
| **Established** | Session etablie, echange de routes |

### Annonce de routes

BGP n'annonce **aucune route par defaut**. Vous devez specifier explicitement les reseaux a annoncer.

#### Methode 1 : Commande network

```cisco
router bgp 65001
 network 192.168.0.0 mask 255.255.255.0
```

**Important :** La route doit exister dans la table de routage locale (statique, connected, IGP).

#### Methode 2 : Redistribution

```cisco
router bgp 65001
 redistribute static
 redistribute connected
 redistribute ospf 1
```

**Attention :** La redistribution peut introduire des boucles ou des routes indesirables. Utilisez des route-maps pour filtrer.

### Filtrage de routes

Le filtrage est essentiel pour controler ce qui est annonce et accepte.

#### Prefix-list

```cisco
! Bloquer un prefixe specifique
ip prefix-list BLOCK-PREFIX deny 192.168.5.0/24
ip prefix-list BLOCK-PREFIX permit 0.0.0.0/0 le 32

router bgp 65001
 neighbor 10.1.1.1 prefix-list BLOCK-PREFIX out
```

#### AS-path access-list

```cisco
! Bloquer toutes les routes originant de AS 65005
ip as-path access-list 10 deny _65005$
ip as-path access-list 10 permit .*

router bgp 65001
 neighbor 10.2.2.2 filter-list 10 in
```

**Syntaxe regex AS-path :**

| Pattern | Signification |
|---------|---------------|
| `^$` | Routes locales (AS_PATH vide) |
| `^65001$` | Routes originant directement de AS 65001 |
| `_65001_` | Routes passant par AS 65001 |
| `^65001_` | Routes originant de AS 65001 |
| `_65001$` | Routes avec AS 65001 comme origine |
| `.*` | Tout (wildcard) |

#### Route-maps

```cisco
! Route-map complexe
route-map POLICY permit 10
 match as-path 10
 set local-preference 200

route-map POLICY permit 20
 set local-preference 100

router bgp 65001
 neighbor 10.1.1.1 route-map POLICY in
```

#### Communities

Les communities permettent de taguer les routes pour un traitement ulterieur :

```cisco
! Definir une community
route-map SET-COMMUNITY permit 10
 set community 65001:100

! Filtrer par community
ip community-list 1 permit 65001:100

route-map FILTER-COMMUNITY deny 10
 match community 1
route-map FILTER-COMMUNITY permit 20
```

**Communities bien connues :**

| Community | Signification |
|-----------|---------------|
| `no-export` | Ne pas annoncer aux peers eBGP |
| `no-advertise` | Ne pas annoncer du tout |
| `local-as` | Ne pas annoncer hors de la confederation |

---

## Utilisation ISP et Enterprise WAN

### Utilisation ISP

Les ISP utilisent BGP pour :

| Fonction | Description |
|----------|-------------|
| **Peering** | Connexion aux autres ISP |
| **Transit** | Transport du trafic pour les clients |
| **Annonces** | Publication des prefixes clients |
| **Full Table** | Reception de la table Internet complete |
| **Traffic Engineering** | Controle des flux entrants/sortants |

**Architecture ISP typique :**
- Milliers de peers BGP
- Route Reflectors pour la scalabilite iBGP
- Communities pour le tagging et le filtrage
- Politiques complexes basees sur les SLAs clients

### Utilisation Enterprise

Les entreprises utilisent BGP pour :

| Use Case | Description |
|----------|-------------|
| **Dual-homing** | Connexion a 2+ ISPs pour la redondance |
| **MPLS VPN** | Routage entre sites via le backbone MPLS |
| **Cloud Connectivity** | AWS Direct Connect, Azure ExpressRoute |
| **Traffic Control** | Influence du routage entrant/sortant |

### Scenario Dual-Homing

```
                    Internet
                   /        \
              ISP A          ISP B
             AS 65501       AS 65502
                 \            /
                  \          /
               Enterprise AS 65010
```

**Configuration :**
```cisco
router bgp 65010
 ! Peering avec ISP A
 neighbor 10.1.1.1 remote-as 65501
 neighbor 10.1.1.1 route-map ISP-A-IN in
 neighbor 10.1.1.1 route-map ISP-A-OUT out

 ! Peering avec ISP B
 neighbor 10.2.2.2 remote-as 65502
 neighbor 10.2.2.2 route-map ISP-B-IN in
 neighbor 10.2.2.2 route-map ISP-B-OUT out

! Preferer ISP A (local-pref plus eleve)
route-map ISP-A-IN permit 10
 set local-preference 200

route-map ISP-B-IN permit 10
 set local-preference 100
```

### MPLS VPN avec BGP

MPLS utilise BGP (MP-BGP) pour echanger les routes VPN entre les PE (Provider Edge) routers :

```
Site A --- CE --- PE --- P --- PE --- CE --- Site B
              \                   /
               \--- MP-BGP VPNv4 ---/
```

**Configuration PE :**
```cisco
router bgp 65001
 address-family vpnv4
  neighbor 10.0.0.2 activate
  neighbor 10.0.0.2 send-community extended
```

### Cloud Connectivity

AWS Direct Connect et Azure ExpressRoute utilisent BGP pour le routage dynamique :

```cisco
! AWS Direct Connect
router bgp 65010
 neighbor 169.254.x.x remote-as 7224  ! Amazon ASN
 neighbor 169.254.x.x password xxxxxxx

 ! Annoncer les prefixes on-premises
 network 10.0.0.0 mask 255.0.0.0
```

---

## Securite BGP et implications cyber

### Vulnerabilites BGP

| Attaque | Description | Impact |
|---------|-------------|--------|
| **BGP Hijacking** | Annonce de prefixes appartenant a un autre AS | Interception MitM, blackhole |
| **Prefix Hijacking** | Annonce du meme prefixe qu'un AS legitime | Detournement partiel |
| **Subprefix Hijacking** | Annonce d'un prefixe plus specifique | Detournement complet |
| **AS_PATH Manipulation** | Falsification du chemin d'AS | Apparence de legitimite |
| **Route Leak** | Propagation non autorisee de routes | Perturbation du routage |
| **BGP Session Hijacking** | Prise de controle d'une session TCP | Injection de routes |

### Cas celebres de BGP Hijacking

| Annee | Incident | Impact |
|-------|----------|--------|
| 2008 | Pakistan Telecom vs YouTube | YouTube inaccessible mondialement 2h |
| 2018 | Amazon Route 53 Hijack | Vol de $150k en crypto |
| 2022 | KLAYswap | Vol de $1.9M en crypto |

### Scenario d'attaque : Subprefix Hijacking

```
Situation normale :
AS 65001 (legitime) annonce 203.0.113.0/24
Tout Internet route vers AS 65001

Attaque :
AS 65999 (attaquant) annonce 203.0.113.0/25 et 203.0.113.128/25
Routes plus specifiques = preferees par tous
Tout le trafic vers 203.0.113.0/24 va vers l'attaquant
```

### Contre-mesures

#### 1. RPKI (Resource Public Key Infrastructure)

RPKI permet de valider cryptographiquement l'origine des annonces BGP.

**Composants :**
- **ROA (Route Origin Authorization)** : Certificat liant un prefixe a un AS
- **Validation** : Valid, Invalid, ou Unknown

```cisco
! Configuration RPKI sur Cisco IOS-XR
router bgp 65001
 rpki server 10.0.0.100
  transport tcp port 8282
  refresh-time 300

 address-family ipv4 unicast
  bgp origin-validation enable
```

#### 2. Filtrage de prefixes

```cisco
! Bogon filter (prefixes invalides)
ip prefix-list BOGON-FILTER deny 0.0.0.0/8 le 32
ip prefix-list BOGON-FILTER deny 10.0.0.0/8 le 32
ip prefix-list BOGON-FILTER deny 127.0.0.0/8 le 32
ip prefix-list BOGON-FILTER deny 169.254.0.0/16 le 32
ip prefix-list BOGON-FILTER deny 172.16.0.0/12 le 32
ip prefix-list BOGON-FILTER deny 192.168.0.0/16 le 32
ip prefix-list BOGON-FILTER deny 224.0.0.0/4 le 32
ip prefix-list BOGON-FILTER permit 0.0.0.0/0 le 24

router bgp 65001
 neighbor 10.0.0.2 prefix-list BOGON-FILTER in
```

#### 3. Maximum Prefix

Limite le nombre de prefixes acceptes d'un peer :

```cisco
router bgp 65001
 neighbor 10.0.0.2 maximum-prefix 1000 80 restart 5
 ! Alerte a 80%, restart apres 5 min si limite atteinte
```

#### 4. AS_PATH Filtering

```cisco
! Rejeter les AS prives sur Internet
ip as-path access-list 10 deny _64[5-9][0-9][0-9]_
ip as-path access-list 10 deny _65[0-4][0-9][0-9]_
ip as-path access-list 10 deny _65[5][0-2][0-9]_
ip as-path access-list 10 permit .*

router bgp 65001
 neighbor 10.0.0.2 filter-list 10 in
```

#### 5. Authentification TCP-MD5

```cisco
router bgp 65001
 neighbor 10.0.0.2 password SecretKey123!
```

#### 6. TCP-AO (Authentication Option)

Plus securise que MD5 :
```cisco
router bgp 65001
 neighbor 10.0.0.2 ao KEYCHAIN-BGP include-tcp-options
```

### Outils de monitoring BGP

| Outil | Description |
|-------|-------------|
| **BGPStream** | Detection temps reel d'anomalies |
| **RIPE RIS** | Looking glass et historique |
| **RouteViews** | Archives des tables BGP |
| **BGPalerter** | Alertes sur changements |
| **Cloudflare Radar** | Visualisation des anomalies |

### Checklist securite BGP

```
[ ] RPKI deploye avec ROAs valides
[ ] Authentification MD5/TCP-AO sur tous les peerings
[ ] Filtrage de prefixes (bogons, max prefix length)
[ ] Maximum prefix configure
[ ] AS-path filtering (AS prives)
[ ] Monitoring des annonces (BGPStream, alertes)
[ ] Documentation des peerings autorises
[ ] IRR (Internet Routing Registry) a jour
[ ] Tests de failover planifies
[ ] Plan de reponse aux incidents BGP
```

### Mapping MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| BGP Hijacking | T1583.006 | Acquire Infrastructure: BGP Hijacking |
| Adversary-in-the-Middle | T1557 | Interception via manipulation BGP |
| Network Denial of Service | T1498 | Perturbation du routage |

---

## Configuration et verification

### Configuration complete

```cisco
! Configuration BGP de base
router bgp 65001
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes

 ! Peering eBGP
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 description ISP-A
 neighbor 10.0.0.2 password SecretKey123
 neighbor 10.0.0.2 prefix-list INBOUND in
 neighbor 10.0.0.2 prefix-list OUTBOUND out
 neighbor 10.0.0.2 maximum-prefix 100000 80

 ! Peering iBGP
 neighbor 192.168.1.2 remote-as 65001
 neighbor 192.168.1.2 update-source Loopback0
 neighbor 192.168.1.2 next-hop-self

 ! Annonces
 network 203.0.113.0 mask 255.255.255.0
```

### Commandes de verification

```cisco
! Resume des voisins
show ip bgp summary

! Detail d'un voisin
show ip bgp neighbors 10.0.0.2

! Table BGP
show ip bgp

! Routes pour un prefixe specifique
show ip bgp 203.0.113.0/24

! Routes annoncees a un voisin
show ip bgp neighbors 10.0.0.2 advertised-routes

! Routes recues d'un voisin
show ip bgp neighbors 10.0.0.2 received-routes

! Verification RPKI
show ip bgp rpki table
```

### Exemple show ip bgp summary

```
BGP router identifier 1.1.1.1, local AS number 65001
BGP table version is 1250, main routing table version 1250
1200 network entries using 172800 bytes of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65002   15234   14521     1250    0    0 3d12h        1200
192.168.1.2     4 65001    8521    8432     1250    0    0 5d06h        1150
```

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [RFC 4271](https://tools.ietf.org/html/rfc4271) | Specification BGP-4 |
| [Cisco - BGP Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-16/irg-xe-16-book.html) | Guide officiel Cisco |
| [Juniper - BGP Fundamentals](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/concept/routing-protocol-bgp-overview.html) | Documentation Juniper |
| [BGP Stream](https://bgpstream.caida.org/) | Monitoring BGP temps reel |
| [RPKI Documentation](https://rpki.readthedocs.io/) | Guide de deploiement RPKI |
| [MANRS](https://www.manrs.org/) | Bonnes pratiques securite routage |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Fondamentaux reseau | https://tryhackme.com/room/introtonetworking |
| **Network Services** | Services et protocoles reseau | https://tryhackme.com/room/networkservices |
| **Wireshark: The Basics** | Analyse de paquets BGP | https://tryhackme.com/room/wiresharkthebasics |

> **Note** : BGP est principalement pratique sur des environnements de lab comme GNS3, EVE-NG ou des labs cloud specialises. Pour les tests de securite BGP, des outils comme ExaBGP permettent de simuler des annonces dans un contexte de recherche autorise. Les incidents BGP reels sont documentes sur bgpstream.caida.org.
