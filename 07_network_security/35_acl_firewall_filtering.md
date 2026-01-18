# ACL et Filtrage Firewall

## Objectifs du cours

Ce cours explore les Access Control Lists (ACLs), un outil fondamental de la sécurité réseau. Des ACLs standard aux ACLs etendues, vous decouvrirez comment contrôler le trafic avec precision. Nous demystifierons egalement les differences entre le filtrage stateless et stateful, vous permettant de comprendre comment les firewalls traitent les paquets et maintiennent la connaissance des sessions.

Competences visees :
- Comprendre et configurer les ACLs standard et etendues
- Reconnaitre les cas d'usage appropries pour chaque type d'ACL
- Expliquer la difference entre les firewalls stateless et stateful
- Choisir la bonne approche selon le scenario réseau
- Appliquer des strategies de filtrage alignees avec les bonnes pratiques de sécurité

---

## Glossaire

### Concepts fondamentaux

| Terme | Description |
|-------|-------------|
| **ACL** | Access Control List - Liste de regles pour filtrer le trafic réseau |
| **ACE** | Access Control Entry - Une regle individuelle dans une ACL |
| **Wildcard Mask** | Masque inverse du subnet mask pour matcher des plages d'adresses |
| **Implicit Deny** | Regle implicite en fin d'ACL qui bloque tout le reste |
| **Packet Filtering** | Filtrage base sur les en-tetes des paquets |

### Types d'ACL

| Type | Plage | Description |
|------|-------|-------------|
| **Standard** | 1-99, 1300-1999 | Filtre uniquement sur l'adresse IP source |
| **Extended** | 100-199, 2000-2699 | Filtre sur source, destination, protocole, ports |
| **Named** | Alphanumerique | ACL nommee, standard ou extended |

### Actions ACL

| Action | Description |
|--------|-------------|
| **permit** | Autorise le trafic correspondant |
| **deny** | Bloque le trafic correspondant |
| **remark** | Commentaire pour documenter l'ACL |

### Direction d'application

| Direction | Description |
|-----------|-------------|
| **in** | Appliquee au trafic entrant sur l'interface |
| **out** | Appliquee au trafic sortant de l'interface |

### Types de filtrage

| Type | Description |
|------|-------------|
| **Stateless** | Chaque paquet evalue independamment, sans mémoire |
| **Stateful** | Maintient une table des connexions actives |
| **Session Table** | Table stockant l'etat des connexions (stateful) |
| **State Tracking** | Suivi de l'etat des connexions TCP/UDP |

### Termes de protocoles

| Terme | Description |
|-------|-------------|
| **TCP** | Transmission Control Protocol - Protocole oriente connexion |
| **UDP** | User Datagram Protocol - Protocole sans connexion |
| **ICMP** | Internet Control Message Protocol - Protocole de contrôle |
| **IP** | Internet Protocol - Tout protocole IP |

### Operateurs de ports

| Operateur | Description |
|-----------|-------------|
| **eq** | Egal a (equal to) |
| **neq** | Different de (not equal to) |
| **lt** | Inferieur a (less than) |
| **gt** | Superieur a (greater than) |
| **range** | Plage de ports (ex: range 20 21) |

### Termes firewall

| Terme | Description |
|-------|-------------|
| **Firewall** | Dispositif de filtrage du trafic réseau |
| **DMZ** | Demilitarized Zone - Zone réseau semi-exposee |
| **Perimeter** | Frontiere entre le réseau interne et externe |
| **Deep Packet Inspection** | Analyse du contenu des paquets au-dela des en-tetes |

---

## Introduction aux Access Control Lists (ACLs)

Les Access Control Lists sont l'un des outils les plus fondamentaux et essentiels de la sécurité réseau. Elles agissent comme des gardes de sécurité, positionnees aux interfaces des routeurs, switches et firewalls, verifiant les credentials et decidant d'autoriser ou de bloquer chaque paquet.

### Role des ACLs

Les ACLs sont des regles ou filtres appliques aux interfaces des équipements réseau. Ces filtres examinent les en-tetes des paquets et determinent si le trafic spécifique est autorise a traverser le réseau.

| Fonction | Description |
|----------|-------------|
| **Controle du trafic** | Autoriser ou bloquer des flux spécifiques |
| **Securite** | Proteger les ressources sensibles |
| **Restriction d'acces** | Limiter l'acces a certains services |
| **Gestion de bande passante** | Controler l'utilisation des ressources |

### Flux de traitement d'une ACL

```
Paquet arrive
    │
    ▼
┌─────────────────┐
│ Premiere regle  │──── Match? ──── Oui ───> Action (permit/deny)
└────────┬────────┘
         │ Non
         ▼
┌─────────────────┐
│ Deuxieme regle  │──── Match? ──── Oui ───> Action (permit/deny)
└────────┬────────┘
         │ Non
         ▼
        ...
         │
         ▼
┌─────────────────┐
│ Implicit Deny   │───────────────────────> Deny (paquet rejete)
└─────────────────┘
```

**Points cles :**
- Les ACLs sont traitees de haut en bas
- Le premier match determine l'action
- Un implicit deny existe a la fin de chaque ACL

---

## ACLs Standard : Filtrage par IP Source

### Fonctionnement

Les ACLs standard sont le type le plus simple. Elles filtrent le trafic uniquement sur l'adresse IP source du paquet. Elles ne considerent pas la destination, le protocole ou le port.

| Avantage | Inconvenient |
|----------|--------------|
| Simple a configurer | Filtrage limite |
| Traitement rapide | Pas de granularite |
| Faible surcharge CPU | Placement critique |

### Syntaxe et structure

Les ACLs standard sont numerotees de 1 a 99 et de 1300 a 1999 (plage etendue).

**Syntaxe générale :**
```
access-list [numero] [permit|deny] [source] [wildcard]
```

**Exemple basique :**
```cisco
access-list 10 permit 192.168.1.0 0.0.0.255
```

Cette regle autorise tout le trafic provenant du subnet 192.168.1.0/24.

### Wildcard Masks

Les ACLs utilisent des wildcard masks plutot que des subnet masks. Un wildcard mask est l'inverse du subnet mask.

| Subnet Mask | Wildcard Mask | Signification |
|-------------|---------------|---------------|
| 255.255.255.255 | 0.0.0.0 | Hote unique |
| 255.255.255.0 | 0.0.0.255 | Reseau /24 |
| 255.255.0.0 | 0.0.255.255 | Reseau /16 |
| 255.0.0.0 | 0.255.255.255 | Reseau /8 |

**Logique du wildcard :**
- `0` = le bit doit correspondre exactement
- `1` = le bit peut etre n'importe quoi (ignore)

**Calcul :**
```
Subnet mask:   255.255.255.0
               11111111.11111111.11111111.00000000

Wildcard mask: 0.0.0.255
               00000000.00000000.00000000.11111111
```

### Mots-cles speciaux

| Mot-cle | Equivalent | Description |
|---------|------------|-------------|
| **any** | 0.0.0.0 255.255.255.255 | Toute adresse |
| **host** | [IP] 0.0.0.0 | Hote unique |

**Exemples :**
```cisco
access-list 10 permit any
! Equivalent a : access-list 10 permit 0.0.0.0 255.255.255.255

access-list 10 deny host 192.168.1.50
! Equivalent a : access-list 10 deny 192.168.1.50 0.0.0.0
```

### Exemple complet d'ACL Standard

**Scenario :** Bloquer l'acces depuis un hote spécifique (192.168.1.50) et autoriser tout le reste.

```cisco
! Configuration de l'ACL
R1(config)# access-list 10 deny host 192.168.1.50
R1(config)# access-list 10 permit any

! Application sur l'interface
R1(config)# interface GigabitEthernet0/1
R1(config-if)# ip access-group 10 in
```

**Explication :**
- `access-list 10 deny host 192.168.1.50` : Bloque les paquets venant de 192.168.1.50
- `access-list 10 permit any` : Autorise toutes les autres sources
- `ip access-group 10 in` : Applique l'ACL sur le trafic entrant

### Placement des ACLs Standard

**Regle fondamentale :** Placer les ACLs standard **pres de la destination**.

```
Source ────────────────────────────────────> Destination
                                                 │
                                        ACL Standard ici
```

**Raison :** Les ACLs standard ne filtrent que sur la source. Les placer pres de la source bloquerait le trafic vers toutes les destinations.

### Cas d'usage des ACLs Standard

| Scenario | Exemple |
|----------|---------|
| Bloquer un subnet source | Bloquer 10.0.0.0/8 vers le réseau interne |
| Autoriser des hotes de confiance | Autoriser uniquement les admins |
| Restreindre l'acces infrastructure | Limiter l'acces aux VTY (SSH/Telnet) |

**Exemple : Restreindre l'acces SSH**
```cisco
access-list 5 permit 192.168.1.0 0.0.0.255
access-list 5 deny any

line vty 0 4
 access-class 5 in
 transport input ssh
```

---

## ACLs Etendues : Controle de Trafic Precis

### Fonctionnement

Les ACLs etendues offrent un filtrage granulaire base sur plusieurs criteres :

| Critere | Description |
|---------|-------------|
| **IP Source** | Adresse IP de l'emetteur |
| **IP Destination** | Adresse IP du recepteur |
| **Protocole** | TCP, UDP, ICMP, IP, etc. |
| **Port Source** | Port de l'application emettrice |
| **Port Destination** | Port de l'application receptrice |

### Syntaxe et structure

Les ACLs etendues sont numerotees de 100 a 199 et de 2000 a 2699.

**Syntaxe générale :**
```
access-list [numero] [permit|deny] [protocole] [source] [wildcard] [destination] [wildcard] [operateur] [port]
```

**Exemple :**
```cisco
access-list 110 permit tcp 192.168.1.0 0.0.0.255 host 10.1.1.10 eq 80
```

Cette regle autorise le trafic TCP depuis le subnet 192.168.1.0/24 vers l'hote 10.1.1.10 sur le port 80 (HTTP).

### Protocoles supportes

| Protocole | Numero | Description |
|-----------|--------|-------------|
| **ip** | - | Tout protocole IP |
| **tcp** | 6 | Transmission Control Protocol |
| **udp** | 17 | User Datagram Protocol |
| **icmp** | 1 | Internet Control Message Protocol |
| **gre** | 47 | Generic Routing Encapsulation |
| **esp** | 50 | Encapsulating Security Payload |
| **ahp** | 51 | Authentication Header Protocol |
| **eigrp** | 88 | EIGRP |
| **ospf** | 89 | OSPF |

### Ports communs

| Port | Service | Protocole |
|------|---------|-----------|
| 20-21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67-68 | DHCP | UDP |
| 69 | TFTP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 3389 | RDP | TCP |

### Operateurs de comparaison

| Operateur | Signification | Exemple |
|-----------|---------------|---------|
| **eq** | Egal a | eq 80 |
| **neq** | Different de | neq 23 |
| **lt** | Inferieur a | lt 1024 |
| **gt** | Superieur a | gt 1023 |
| **range** | Entre deux valeurs | range 20 21 |

### Exemple complet d'ACL Etendue

**Scenario :** Bloquer le trafic HTTP (port 80) depuis l'IP 192.168.2.100 vers le serveur web 10.0.0.5, mais autoriser tout le reste.

```cisco
! Configuration de l'ACL
R1(config)# access-list 100 deny tcp host 192.168.2.100 host 10.0.0.5 eq 80
R1(config)# access-list 100 permit ip any any

! Application sur l'interface
R1(config)# interface GigabitEthernet0/2
R1(config-if)# ip access-group 100 out
```

**Explication :**
- `deny tcp host 192.168.2.100 host 10.0.0.5 eq 80` : Bloque TCP depuis 192.168.2.100 vers 10.0.0.5 sur le port 80
- `permit ip any any` : Autorise tout autre trafic IP
- `ip access-group 100 out` : Applique l'ACL sur le trafic sortant

### Placement des ACLs Etendues

**Regle fondamentale :** Placer les ACLs etendues **pres de la source**.

```
Source ─────────────────────────────────────> Destination
   │
   ACL Etendue ici
```

**Raison :** Filtrer le trafic au plus tot economise la bande passante et les ressources.

### ACLs etendues avec ICMP

```cisco
! Bloquer tout le ping (ICMP echo)
access-list 101 deny icmp any any echo
access-list 101 deny icmp any any echo-reply
access-list 101 permit ip any any
```

**Types ICMP courants :**

| Type | Nom | Description |
|------|-----|-------------|
| 0 | echo-reply | Reponse ping |
| 3 | unreachable | Destination inaccessible |
| 5 | redirect | Redirection |
| 8 | echo | Requete ping |
| 11 | time-exceeded | TTL expire |

### ACLs nommees

Les ACLs nommees offrent une meilleure lisibilite et flexibilite.

```cisco
! ACL standard nommee
ip access-list standard ADMIN-ACCESS
 permit host 192.168.1.10
 permit host 192.168.1.11
 deny any

! ACL etendue nommee
ip access-list extended WEB-TRAFFIC
 permit tcp any host 10.0.0.5 eq 80
 permit tcp any host 10.0.0.5 eq 443
 deny ip any any
```

**Avantages des ACLs nommees :**

| Avantage | Description |
|----------|-------------|
| Lisibilite | Nom descriptif au lieu d'un numero |
| Modification | Suppression/insertion de lignes individuelles |
| Sequencement | Controle de l'ordre avec des numeros de sequence |

### Modification d'ACL nommee

```cisco
ip access-list extended WEB-TRAFFIC
 no 20
 15 permit tcp any host 10.0.0.6 eq 80
```

---

## Filtrage Stateless : Le Monde des ACLs

### Fonctionnement

Le filtrage stateless signifie que chaque paquet est evalue independamment. Le routeur ou firewall ne garde aucune mémoire des paquets precedents.

```
Paquet 1 ───> Evaluation ───> Decision
Paquet 2 ───> Evaluation ───> Decision
Paquet 3 ───> Evaluation ───> Decision
(Aucun lien entre les paquets)
```

### Caracteristiques

| Aspect | Description |
|--------|-------------|
| **Memoire** | Aucune - chaque paquet est isolé |
| **Performance** | Rapide - pas de tracking de session |
| **Complexite** | Simple et deterministe |
| **Detection** | Limitee - pas de vision du flux |

### Exemple de problème stateless

**Scenario :** Un client interne initie une connexion TCP vers un serveur externe.

```
Trafic sortant (autorise) :
Client 192.168.1.10:54321 ───> Serveur 8.8.8.8:80 (SYN)

Trafic retour (problème) :
Serveur 8.8.8.8:80 ───> Client 192.168.1.10:54321 (SYN-ACK)
```

Avec un filtrage stateless, il faut explicitement autoriser le trafic retour :

```cisco
! Autoriser le trafic sortant
access-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 80

! Autoriser le trafic retour (ports ephemeres)
access-list 100 permit tcp any gt 1023 192.168.1.0 0.0.0.255 established
```

Le mot-cle `established` matche les paquets TCP avec les flags ACK ou RST, indiquant une connexion etablie.

### Limitations du filtrage Stateless

| Limitation | Consequence |
|------------|-------------|
| Pas de suivi de session | Regles complexes pour le trafic retour |
| Vulnerabilite aux spoofing | Paquets forges peuvent passer |
| Gestion UDP difficile | Pas de flags pour identifier les reponses |
| Detection d'anomalies limitee | Half-open sessions invisibles |

---

## Filtrage Stateful : Firewalls Intelligents

### Fonctionnement

Le filtrage stateful maintient une table d'etat (state table ou session table) qui enregistre les details des connexions actives.

```
┌─────────────────────────────────────────────────────┐
│                   STATE TABLE                        │
├──────────────┬──────────────┬─────────┬────────────┤
│ Source       │ Destination  │ Proto   │ State      │
├──────────────┼──────────────┼─────────┼────────────┤
│ 192.168.1.10:54321 │ 8.8.8.8:80   │ TCP   │ ESTABLISHED│
│ 192.168.1.11:49152 │ 1.1.1.1:443  │ TCP   │ SYN_SENT   │
│ 192.168.1.12:60000 │ 9.9.9.9:53   │ UDP   │ ACTIVE     │
└──────────────┴──────────────┴─────────┴────────────┘
```

### Processus de traitement

```
Nouveau paquet arrive
        │
        ▼
┌───────────────────────┐
│ Verifier State Table  │
└───────────┬───────────┘
            │
     ┌──────┴──────┐
     │             │
     ▼             ▼
 Connexion     Nouvelle
 existante?    connexion
     │             │
     │             ▼
     │     ┌───────────────┐
     │     │ Verifier ACL  │
     │     └───────┬───────┘
     │             │
     ▼             ▼
 Autoriser     Autoriser?
 (match)           │
                   ├──── Oui ──> Creer entree + Autoriser
                   │
                   └──── Non ──> Rejeter
```

### Exemple concret

1. Un utilisateur interne ouvre son navigateur vers http://example.com
2. Le firewall voit la requete sortante et l'enregistre dans la state table
3. Quand la reponse revient du serveur, le firewall la reconnait comme partie de la connexion etablie
4. La reponse est autorisee sans regle explicite

### Avantages du filtrage Stateful

| Avantage | Description |
|----------|-------------|
| **Suivi des connexions** | Reconnait les paquets de retour |
| **Regles simplifiees** | Pas besoin de regles pour le trafic retour |
| **Securite renforcee** | Detection des paquets hors-session |
| **Support UDP/ICMP** | Pseudo-sessions pour protocoles sans connexion |
| **Integration avancee** | NAT, VPN, IDS/IPS |

### Etats TCP suivis

| Etat | Description |
|------|-------------|
| **SYN_SENT** | SYN envoye, attente SYN-ACK |
| **SYN_RECEIVED** | SYN-ACK envoye, attente ACK |
| **ESTABLISHED** | Connexion etablie |
| **FIN_WAIT** | FIN envoye, fermeture en cours |
| **TIME_WAIT** | Attente avant liberation |
| **CLOSED** | Connexion terminee |

### Detection d'attaques

Les firewalls stateful peuvent detecter :

| Attaque | Detection |
|---------|-----------|
| **SYN Flood** | Nombreuses sessions SYN_SENT sans completion |
| **ACK Scan** | ACK sans SYN prealable |
| **Spoofed Responses** | Reponses sans requete correspondante |
| **Session Hijacking** | Numeros de sequence anormaux |

### Exemple de configuration Cisco ASA

```cisco
! Politique de connexion par defaut
access-list OUTBOUND extended permit tcp any any
access-list OUTBOUND extended permit udp any any
access-list OUTBOUND extended permit icmp any any

! Application a l'interface interne
access-group OUTBOUND in interface inside

! Inspection stateful activee par defaut
! Les reponses sont automatiquement autorisees
```

### ACL avec mot-cle established

Sur les routeurs Cisco IOS, le mot-cle `established` offre un filtrage pseudo-stateful :

```cisco
! Autoriser les connexions initiees depuis l'interieur
access-list 110 permit tcp any any established
access-list 110 deny tcp any any

interface GigabitEthernet0/0
 ip access-group 110 in
```

**Limitation :** `established` ne matche que les flags TCP (ACK/RST), pas une vraie table d'etat.

---

## Comparaison : Quand utiliser quoi ?

### ACL Standard vs Etendue

| Critere | ACL Standard | ACL Etendue |
|---------|--------------|-------------|
| **Filtrage** | Source IP uniquement | Source, dest, proto, ports |
| **Placement** | Pres de la destination | Pres de la source |
| **Performance** | Plus rapide | Plus lente |
| **Granularite** | Faible | Elevee |
| **Cas d'usage** | Controle d'acces simple | Politiques complexes |

### Stateless vs Stateful

| Critere | Stateless | Stateful |
|---------|-----------|----------|
| **Memoire** | Aucune | State table |
| **Performance** | Plus rapide | Plus lente |
| **Securite** | Basique | Avancee |
| **Configuration** | Complexe (retour) | Simple |
| **Cout** | Faible | Plus élevé |
| **Detection** | Limitee | Avancee |

### Guide de choix

```
┌─────────────────────────────────────────────────────────┐
│                   CHOIX DU FILTRAGE                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Besoin simple (filtrer par source) ?                   │
│     └── Oui ──> ACL Standard                            │
│     └── Non ──> Continuer                               │
│                                                          │
│  Besoin de filtrer par protocole/port ?                 │
│     └── Oui ──> ACL Etendue                             │
│                                                          │
│  Trafic unidirectionnel/previsible ?                    │
│     └── Oui ──> Filtrage Stateless (ACL)                │
│     └── Non ──> Filtrage Stateful (Firewall)            │
│                                                          │
│  Securite perimetre/DMZ ?                               │
│     └── Toujours ──> Filtrage Stateful                  │
│                                                          │
│  Ressources limitees ?                                   │
│     └── Oui ──> Filtrage Stateless                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Scenarios recommandes

| Scenario | Recommandation |
|----------|----------------|
| Filtrage inter-VLAN simple | ACL Standard ou Etendue |
| Protection serveur spécifique | ACL Etendue |
| Perimetre Internet | Firewall Stateful |
| DMZ | Firewall Stateful |
| Entre sites WAN | ACL Etendue ou Firewall |
| Controle d'acces VTY | ACL Standard |
| QoS et classification | ACL Etendue |

---

## Bonnes pratiques de gestion des ACLs

### Organisation et documentation

```cisco
! Toujours commenter les ACLs
access-list 110 remark === POLITIQUE SERVEUR WEB ===
access-list 110 remark Autorise HTTP/HTTPS depuis Internet
access-list 110 permit tcp any host 10.0.0.5 eq 80
access-list 110 permit tcp any host 10.0.0.5 eq 443
access-list 110 remark Bloque tout autre trafic
access-list 110 deny ip any any log
```

### L'ordre est critique

Les ACLs sont traitees de haut en bas. Le premier match determine l'action.

**Mauvais ordre :**
```cisco
access-list 100 permit ip any any
access-list 100 deny tcp any any eq 23
! Le deny ne sera JAMAIS atteint !
```

**Bon ordre :**
```cisco
access-list 100 deny tcp any any eq 23
access-list 100 permit ip any any
```

### Implicit Deny

Toute ACL se termine par un `deny any` implicite.

```cisco
! Ces deux configurations sont equivalentes :

! Configuration 1 (implicit deny)
access-list 10 permit 192.168.1.0 0.0.0.255

! Configuration 2 (explicit deny)
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 deny any
```

**Recommandation :** Ajouter un `deny any log` explicite pour le troubleshooting.

### Logging et monitoring

```cisco
! Activer le logging sur les regles critiques
access-list 110 deny tcp any any eq 23 log
access-list 110 deny tcp any any eq 21 log
access-list 110 permit ip any any

! Configurer le logging
logging buffered 64000
logging trap informational
```

### Tests en environnement lab

Toujours tester les ACLs avant deploiement en production :

1. Creer un environnement de test (GNS3, EVE-NG)
2. Appliquer l'ACL
3. Tester le trafic legitime (doit passer)
4. Tester le trafic bloque (doit etre rejete)
5. Verifier les logs

### Commandes de verification

```cisco
! Afficher les ACLs configurees
show access-lists
show ip access-lists

! Voir les statistiques de match
show access-lists 110

! Verifier l'application sur les interfaces
show ip interface GigabitEthernet0/0

! Effacer les compteurs
clear access-list counters
```

### Exemple de sortie show access-lists

```
Extended IP access list 110
    10 permit tcp any host 10.0.0.5 eq www (1250 matches)
    20 permit tcp any host 10.0.0.5 eq 443 (3420 matches)
    30 deny ip any any log (15 matches)
```

---

## Lab pratique : ACLs dans GNS3

### Objectif

Configurer des ACLs standard et etendues pour contrôler l'acces a un serveur web interne.

### Topologie

```
Internet                    DMZ                      LAN
   │                         │                        │
   │                    ┌────┴────┐                   │
   └────────────────────┤  R1     ├──────────────────┘
                        │ (ACLs)  │
                        └────┬────┘
                             │
                        Web Server
                        10.0.0.5
```

### Configuration du routeur R1

```cisco
! Configuration des interfaces
interface GigabitEthernet0/0
 description Vers Internet
 ip address 203.0.113.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/1
 description Vers LAN
 ip address 192.168.1.1 255.255.255.0
 no shutdown

interface GigabitEthernet0/2
 description Vers DMZ (Web Server)
 ip address 10.0.0.1 255.255.255.0
 no shutdown

! ACL pour proteger le serveur web
ip access-list extended PROTECT-WEBSERVER
 remark Autoriser HTTP/HTTPS depuis Internet
 permit tcp any host 10.0.0.5 eq 80
 permit tcp any host 10.0.0.5 eq 443
 remark Autoriser tout depuis le LAN
 permit ip 192.168.1.0 0.0.0.255 any
 remark Bloquer tout le reste
 deny ip any any log

! Application de l'ACL
interface GigabitEthernet0/2
 ip access-group PROTECT-WEBSERVER out
```

### Tests

1. **Depuis Internet :** HTTP vers 10.0.0.5 doit fonctionner
2. **Depuis Internet :** SSH vers 10.0.0.5 doit etre bloque
3. **Depuis le LAN :** Tout trafic vers 10.0.0.5 doit fonctionner

---

## Securite et implications cyber

### Vulnerabilites liees aux ACLs

| Vulnerabilite | Description | Impact |
|---------------|-------------|--------|
| **ACL Bypass** | Contournement via fragmentation | Trafic non filtre |
| **IP Spoofing** | Usurpation d'adresse source | Acces non autorise |
| **Ordre incorrect** | Regles mal ordonnees | Politique inefficace |
| **Implicit Deny oublie** | Aucune regle finale | Trafic inattendu autorise |

### Attaques contournant le filtrage Stateless

| Attaque | Technique | Contre-mesure |
|---------|-----------|---------------|
| **ACK Scan** | Envoyer ACK sans SYN | Filtrage stateful |
| **IP Fragmentation** | Fragmenter pour cacher les ports | `ip verify fragment` |
| **Source Routing** | Specifier le chemin dans le paquet | `no ip source-route` |
| **Spoofed Responses** | Forger des reponses | uRPF, filtrage stateful |

### Bonnes pratiques de sécurité

```cisco
! Anti-spoofing sur l'interface externe
interface GigabitEthernet0/0
 ip verify unicast source reachable-via rx

! Bloquer les adresses privees depuis Internet
ip access-list extended ANTISPOOFING
 deny ip 10.0.0.0 0.255.255.255 any
 deny ip 172.16.0.0 0.15.255.255 any
 deny ip 192.168.0.0 0.0.255.255 any
 deny ip 127.0.0.0 0.255.255.255 any
 permit ip any any

interface GigabitEthernet0/0
 ip access-group ANTISPOOFING in

! Desactiver le source routing
no ip source-route
```

### Checklist sécurité ACL

```
[ ] Regles ordonnees du plus spécifique au plus général
[ ] Implicit deny explicite avec logging
[ ] Commentaires sur chaque section
[ ] Anti-spoofing sur les interfaces externes
[ ] Filtrage des bogons (adresses invalides)
[ ] Tests en lab avant production
[ ] Documentation maintenue a jour
[ ] Revue periodique des regles
[ ] Monitoring des logs ACL
[ ] Plan de rollback en cas de problème
```

### Mapping MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Network Sniffing | T1040 | Capture de trafic si ACL mal configuree |
| Exploitation of Remote Services | T1210 | Acces via ports non filtres |
| Proxy | T1090 | Contournement via tunnel |

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [Cisco - Access Control Lists](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-16/sec-data-acl-xe-16-book.html) | Guide officiel Cisco ACL |
| [AWS - Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) | ACLs dans le cloud AWS |
| [Fortinet - Stateful vs Stateless](https://www.fortinet.com/resources/cyberglossary/stateful-vs-stateless-firewall) | Comparaison des firewalls |
| [NIST - Firewall Guidelines](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final) | Bonnes pratiques NIST |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Fondamentaux réseau | https://tryhackme.com/room/introtonetworking |
| **Network Services** | Services et protocoles réseau | https://tryhackme.com/room/networkservices |
| **Firewalls** | Introduction aux firewalls | https://tryhackme.com/room/dvwafirewalls |
| **Wireshark: The Basics** | Analyse de paquets | https://tryhackme.com/room/wiresharkthebasics |

> **Note** : Les ACLs sont pratiquees sur des environnements de lab comme GNS3, EVE-NG ou Packet Tracer. Pour tester le filtrage stateful, utilisez des firewalls virtuels comme pfSense, OPNsense ou Cisco ASA virtuel. Toujours tester dans un environnement isolé avant de deployer en production.
