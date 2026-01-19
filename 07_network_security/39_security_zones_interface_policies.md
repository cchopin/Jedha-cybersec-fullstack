# Zones de sécurité et politiques d'interface

## Objectifs du cours

Ce cours explore comment les firewalls et routeurs renforcent la sécurité en regroupant les interfaces dans des zones et en controlant le trafic entre elles via des politiques d'interface. Les zones de sécurité et les politiques d'interface definissent les regles d'engagement a travers votre réseau.

Competences visees :
- Comprendre le concept et l'objectif des zones de sécurité dans la configuration firewall
- Classifier les interfaces dans differentes zones comme inside, outside et DMZ
- Configurer des politiques au niveau interface pour le contrôle d'acces, le NAT et le logging
- Concevoir des regles de trafic inter-zones securisees avec pfSense et Cisco
- Comprendre les bonnes pratiques pour segmenter le trafic avec les Zone-Based Policy Firewalls

---

## Glossaire

### Concepts fondamentaux

| Terme | Description |
|-------|-------------|
| **Security Zone** | Groupement logique d'interfaces sur un firewall |
| **Interface Policy** | Regles appliquees a une interface ou entre zones |
| **Zone Pair** | Paire source-destination definissant le sens du trafic |
| **Trust Level** | Niveau de confiance associe a une zone |
| **Inter-zone Traffic** | Trafic circulant entre deux zones differentes |
| **Intra-zone Traffic** | Trafic au sein d'une meme zone |

### Zones courantes

| Zone | Description |
|------|-------------|
| **Inside/LAN** | Reseau interne, appareils d'entreprise |
| **Outside/WAN** | Internet, réseaux non fiables |
| **DMZ** | Serveurs publics exposes |
| **VPN** | Acces utilisateurs distants |
| **Guest** | BYOD, IoT, visiteurs |
| **Management** | Interfaces d'administration réseau |

### Termes Cisco ZBFW

| Terme | Description |
|-------|-------------|
| **ZBFW** | Zone-Based Firewall - Firewall base sur les zones |
| **Class Map** | Definition du type de trafic a matcher |
| **Policy Map** | Actions a appliquer au trafic matche |
| **Service Policy** | Application de la politique a une zone-pair |
| **Inspect** | Action d'inspection stateful |

### Termes pfSense

| Terme | Description |
|-------|-------------|
| **Interface** | Port réseau virtuel (LAN, WAN, OPT) |
| **Alias** | Groupe d'IPs, ports ou réseaux |
| **Floating Rules** | Regles s'appliquant a plusieurs interfaces |
| **Pass** | Action autorisant le trafic |
| **Block** | Action bloquant silencieusement |
| **Reject** | Action bloquant avec reponse |

### Actions de politique

| Action | Description |
|--------|-------------|
| **Allow/Permit** | Autorise le trafic |
| **Deny/Block** | Bloque le trafic |
| **Inspect** | Inspection stateful du trafic |
| **Log** | Journalise le trafic |
| **NAT** | Traduit les adresses |
| **Rate Limit** | Limite la bande passante |

---

## Qu'est-ce qu'une zone de sécurité ?

Les zones de sécurité sont des groupements logiques d'interfaces sur un firewall ou routeur. Au lieu d'appliquer des regles a chaque interface individuellement, vous assignez les interfaces a des zones comme "inside", "outside" ou "DMZ", puis definissez des politiques entre les zones.

```
┌─────────────────────────────────────────────────────────────┐
│                    CONCEPT DES ZONES                        │
│                                                              │
│   Pensez aux zones comme des quartiers d'une ville :        │
│   chaque quartier a ses propres regles pour qui peut        │
│   entrer, sortir, et comment les gens interagissent.        │
│                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│   │   INSIDE    │  │     DMZ     │  │   OUTSIDE   │        │
│   │  (Confiance │  │  (Confiance │  │  (Confiance │        │
│   │    Haute)   │  │   Moyenne)  │  │    Basse)   │        │
│   │             │  │             │  │             │        │
│   │  ┌───┐┌───┐ │  │   ┌─────┐   │  │   Internet  │        │
│   │  │PC ││PC │ │  │   │ Web │   │  │      ☁      │        │
│   │  └───┘└───┘ │  │   │ Srv │   │  │             │        │
│   │             │  │   └─────┘   │  │             │        │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│          │                │                │                │
│          └────────────────┼────────────────┘                │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │  FIREWALL   │                          │
│                    │  (Policies) │                          │
│                    └─────────────┘                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Pourquoi utiliser des zones ?

| Avantage | Description |
|----------|-------------|
| **Simplification** | Une regle entre zones au lieu de 50 regles par interface |
| **Securite** | Facilite l'application du moindre privilege |
| **Coherence** | Application uniforme des politiques |
| **Scalabilite** | Plus facile a gerer quand le réseau grandit |
| **Lisibilite** | Configurations plus claires et comprehensibles |

### Zones vs Segmentation Reseau

Il est courant de confondre zones de sécurité et segmentation réseau, mais ils servent des objectifs differents (bien que complementaires) :

| Aspect | Segmentation Reseau | Zones de Securite |
|--------|---------------------|-------------------|
| **Niveau** | Infrastructure | Politique |
| **Objectif** | Separer le trafic | Appliquer des regles |
| **Implementation** | VLANs, subnets, switches | Configuration firewall |
| **Focus** | Comment le réseau est divise | Comment les politiques s'appliquent |

**En resume :**
- **Segmentation** = "Comment votre réseau est physiquement/logiquement divise"
- **Zones** = "Comment vous appliquez les politiques de sécurité a ces divisions"

**Bonne pratique :** Combinez les deux - segmentez votre réseau pour le contrôle et la performance, puis superposez les zones de sécurité pour appliquer des politiques coherentes.

### Zones courantes et niveaux de confiance

| Zone | Description | Niveau de Confiance |
|------|-------------|---------------------|
| **Inside** | LAN interne, appareils corporate | Haut |
| **Outside** | Internet, réseaux non fiables | Bas |
| **DMZ** | Serveurs publics | Moyen |
| **VPN** | Acces utilisateurs distants | Variable |
| **Guest** | BYOD, IoT, visiteurs | Bas |
| **Management** | Interfaces d'administration | Haut |

---

## Zone-Based Firewalls vs ACLs Legacy

### Approche ACL traditionnelle

Dans les anciens systèmes, vous definiriez des ACLs pour chaque interface :

```cisco
! Interface A
access-list 101 permit tcp any any eq 80
access-list 101 deny ip any any

! Interface B
access-list 102 deny tcp any any eq 22
access-list 102 permit ip any any

! Interface C
access-list 103 permit icmp any any
access-list 103 deny ip any any
```

**Probleme :** Cela devient un cauchemar a gerer a grande echelle.

### Approche Zone-Based Firewall

Avec les ZBFW, vous dites simplement :

```
Autoriser HTTP de Zone A vers Zone B
Refuser SSH de Zone C vers Zone A
```

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   ACL TRADITIONNELLES              ZONE-BASED FIREWALL      │
│                                                              │
│   ┌─────┐ ACL1 ──────────          ┌─────┐                  │
│   │Intf1│ ACL pour HTTP            │Zone │                  │
│   └─────┘                          │  A  │ ════════╗        │
│   ┌─────┐ ACL2 ──────────          └─────┘         ║        │
│   │Intf2│ ACL pour SSH                             ║        │
│   └─────┘                                    ┌─────╨─────┐  │
│   ┌─────┐ ACL3 ──────────          ┌─────┐  │  POLICY   │  │
│   │Intf3│ ACL pour ICMP            │Zone │  │ A → B     │  │
│   └─────┘                          │  B  │  │ HTTP: OK  │  │
│   ┌─────┐ ACL4 ──────────          └─────┘  └───────────┘  │
│   │Intf4│ ACL pour FTP                                      │
│   └─────┘                                                   │
│                                                              │
│   Gestion complexe                 Gestion simple           │
│   Regles par interface            Regles par zone           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration des Zones sur Cisco

### Etape 1 : Definition des zones

```cisco
! Creer les zones de sécurité
zone security INSIDE
zone security OUTSIDE
zone security DMZ
```

### Etape 2 : Assignation des interfaces

```cisco
! Assigner les interfaces aux zones
interface GigabitEthernet0/1
 description LAN Interface
 ip address 192.168.1.1 255.255.255.0
 zone-member security INSIDE

interface GigabitEthernet0/2
 description WAN Interface
 ip address dhcp
 zone-member security OUTSIDE

interface GigabitEthernet0/3
 description DMZ Interface
 ip address 192.168.2.1 255.255.255.0
 zone-member security DMZ
```

### Etape 3 : Creation des Zone Pairs

Les zone pairs definissent la direction du flux de trafic :

```cisco
! Definir les paires de zones
zone-pair security IN-TO-OUT source INSIDE destination OUTSIDE
zone-pair security IN-TO-DMZ source INSIDE destination DMZ
zone-pair security OUT-TO-DMZ source OUTSIDE destination DMZ
zone-pair security DMZ-TO-OUT source DMZ destination OUTSIDE
```

### Etape 4 : Definition des Class Maps

Les class maps specifient quel type de trafic matcher :

```cisco
! Class map pour le trafic web
class-map type inspect match-any WEB-TRAFFIC
 match protocol http
 match protocol https
 match protocol dns

! Class map pour le trafic email
class-map type inspect match-any EMAIL-TRAFFIC
 match protocol smtp
 match protocol pop3
 match protocol imap

! Class map pour le trafic SSH
class-map type inspect match-any MGMT-TRAFFIC
 match protocol ssh
 match protocol telnet
```

### Etape 5 : Definition des Policy Maps

Les policy maps definissent les actions a appliquer :

```cisco
! Politique pour le trafic INSIDE vers OUTSIDE
policy-map type inspect INSIDE-TO-OUTSIDE-POLICY
 class type inspect WEB-TRAFFIC
  inspect
 class type inspect EMAIL-TRAFFIC
  inspect
 class class-default
  drop log

! Politique pour le trafic OUTSIDE vers DMZ
policy-map type inspect OUTSIDE-TO-DMZ-POLICY
 class type inspect WEB-TRAFFIC
  inspect
 class class-default
  drop log
```

### Etape 6 : Application des Service Policies

```cisco
! Appliquer les politiques aux zone pairs
zone-pair security IN-TO-OUT
 service-policy type inspect INSIDE-TO-OUTSIDE-POLICY

zone-pair security OUT-TO-DMZ
 service-policy type inspect OUTSIDE-TO-DMZ-POLICY
```

### Configuration complete exemple

```cisco
! ============================================
! CONFIGURATION ZONE-BASED FIREWALL COMPLETE
! ============================================

! 1. Definition des zones
zone security INSIDE
zone security OUTSIDE
zone security DMZ

! 2. Assignation des interfaces
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 zone-member security INSIDE

interface GigabitEthernet0/2
 ip address dhcp
 zone-member security OUTSIDE

interface GigabitEthernet0/3
 ip address 192.168.2.1 255.255.255.0
 zone-member security DMZ

! 3. Zone pairs
zone-pair security IN-TO-OUT source INSIDE destination OUTSIDE
zone-pair security IN-TO-DMZ source INSIDE destination DMZ
zone-pair security OUT-TO-DMZ source OUTSIDE destination DMZ

! 4. Class maps
class-map type inspect match-any WEB-TRAFFIC
 match protocol http
 match protocol https

class-map type inspect match-any DNS-TRAFFIC
 match protocol dns

! 5. Policy maps
policy-map type inspect IN-OUT-POLICY
 class type inspect WEB-TRAFFIC
  inspect
 class type inspect DNS-TRAFFIC
  inspect
 class class-default
  drop log

policy-map type inspect OUT-DMZ-POLICY
 class type inspect WEB-TRAFFIC
  inspect
 class class-default
  drop log

! 6. Service policies
zone-pair security IN-TO-OUT
 service-policy type inspect IN-OUT-POLICY

zone-pair security OUT-TO-DMZ
 service-policy type inspect OUT-DMZ-POLICY
```

---

## Politiques d'interface expliquées

Une fois vos zones creees, l'étape suivante est de configurer les politiques d'interface (regles firewall). Ces politiques definissent qui peut communiquer avec qui, sous quelles conditions, et ce qui doit arriver au trafic.

### Composants des politiques d'interface

| Composant | Description |
|-----------|-------------|
| **Firewall Rules** | Autoriser/refuser selon source, destination, port, protocole |
| **NAT Rules** | Traduire les IPs internes vers publiques |
| **Routing Logic** | Decider quelle interface forward le paquet |
| **QoS/Rate Limiting** | Controler la bande passante et la priorite |
| **Logging** | Monitorer et auditer le trafic |

### Flux de traitement

```
┌─────────────────────────────────────────────────────────────┐
│              TRAITEMENT D'UNE POLITIQUE                     │
│                                                              │
│   Paquet arrive                                              │
│       │                                                      │
│       ▼                                                      │
│   ┌───────────────────┐                                     │
│   │ Identification    │                                     │
│   │ Zone Source       │                                     │
│   └─────────┬─────────┘                                     │
│             │                                                │
│             ▼                                                │
│   ┌───────────────────┐                                     │
│   │ Identification    │                                     │
│   │ Zone Destination  │                                     │
│   └─────────┬─────────┘                                     │
│             │                                                │
│             ▼                                                │
│   ┌───────────────────┐                                     │
│   │ Lookup Zone-Pair  │                                     │
│   │ Policy            │                                     │
│   └─────────┬─────────┘                                     │
│             │                                                │
│             ▼                                                │
│   ┌───────────────────┐                                     │
│   │ Match Class Map   │                                     │
│   │ (Type de trafic)  │                                     │
│   └─────────┬─────────┘                                     │
│             │                                                │
│       ┌─────┴─────┐                                         │
│       │           │                                         │
│       ▼           ▼                                         │
│   MATCH        NO MATCH                                     │
│       │           │                                         │
│       ▼           ▼                                         │
│   Action      Default Action                                │
│   (inspect,   (drop)                                        │
│    pass,                                                    │
│    drop)                                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Politiques d'Interface dans pfSense

pfSense gère les politiques d'interface avec un modèle simple et élégant.

### Assignation des interfaces

1. **Interfaces > Assignments**
2. Assigner les interfaces physiques (em0, em1...) aux interfaces logiques (LAN, WAN, OPT1...)
3. Chaque interface logique represente une zone

### Creation des regles firewall

**Navigation :** Firewall > Rules > [Interface]

#### Exemple 1 : Autoriser HTTP du LAN vers la DMZ

| Parametre | Valeur |
|-----------|--------|
| **Interface** | LAN |
| **Action** | Pass |
| **Protocol** | TCP |
| **Source** | LAN net |
| **Destination** | DMZ server (alias ou IP) |
| **Destination Port** | 80 (HTTP) |
| **Description** | Allow LAN to DMZ HTTP |

#### Exemple 2 : Bloquer la DMZ vers le LAN

| Parametre | Valeur |
|-----------|--------|
| **Interface** | DMZ |
| **Action** | Block |
| **Protocol** | Any |
| **Source** | DMZ net |
| **Destination** | LAN net |
| **Description** | Block DMZ to LAN |

### Ordre des regles

pfSense traite les regles de **haut en bas** et s'arrete au premier match.

```
┌─────────────────────────────────────────────────────────────┐
│                 ORDRE DES REGLES PFSENSE                    │
│                                                              │
│   Regle 1: Block specific bad IP     ← Priorite haute      │
│   Regle 2: Allow HTTP to web server                        │
│   Regle 3: Allow HTTPS to web server                       │
│   Regle 4: Allow DNS to DNS servers                        │
│   Regle 5: Block all else            ← Priorite basse      │
│                                                              │
│   Le paquet est compare a chaque regle dans l'ordre.       │
│   Des que ca matche, l'action est executee.                │
│   Les regles en-dessous ne sont pas evaluees.              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### NAT dans pfSense

**Navigation :** Firewall > NAT

#### Port Forwarding : Exposer un serveur DMZ

| Parametre | Valeur |
|-----------|--------|
| **Interface** | WAN |
| **Protocol** | TCP |
| **Destination** | WAN Address |
| **Destination Port Range** | 80 |
| **Redirect Target IP** | 192.168.2.10 |
| **Redirect Target Port** | 80 |
| **Description** | HTTP to DMZ Web Server |

Cela permet aux utilisateurs externes d'acceder au serveur web dans la DMZ sans exposer les appareils internes.

### Utilisation des Aliases

Les aliases simplifient la gestion des regles :

```
Alias: Web_Servers
  - 192.168.2.10
  - 192.168.2.11

Alias: Web_Ports
  - 80
  - 443

Alias: Admin_IPs
  - 192.168.1.10
  - 192.168.1.11

Alias: Blocked_Countries
  - (Liste d'IPs geobloquees)
```

---

## Construire une architecture de zones sécurisée

### Topologie exemple

```
┌─────────────────────────────────────────────────────────────┐
│                  ARCHITECTURE 4 ZONES                       │
│                                                              │
│                        Internet                              │
│                            │                                 │
│                            │                                 │
│                     ┌──────┴──────┐                         │
│                     │    WAN      │                         │
│                     │  (OUTSIDE)  │                         │
│                     └──────┬──────┘                         │
│                            │                                 │
│                     ┌──────┴──────┐                         │
│                     │  FIREWALL   │                         │
│                     │   pfSense   │                         │
│                     └──┬───┬───┬──┘                         │
│                        │   │   │                            │
│         ┌──────────────┘   │   └──────────────┐             │
│         │                  │                  │             │
│   ┌─────┴─────┐     ┌──────┴──────┐    ┌─────┴─────┐       │
│   │    LAN    │     │     DMZ     │    │   MGMT    │       │
│   │  (INSIDE) │     │             │    │           │       │
│   │           │     │  ┌───────┐  │    │  ┌─────┐  │       │
│   │ ┌───┐┌───┐│     │  │  Web  │  │    │  │Admin│  │       │
│   │ │PC ││PC ││     │  │ Server│  │    │  │ Box │  │       │
│   │ └───┘└───┘│     │  └───────┘  │    │  └─────┘  │       │
│   │           │     │  ┌───────┐  │    │           │       │
│   │ 192.168.1 │     │  │ Mail  │  │    │ 192.168.99│       │
│   │   .0/24   │     │  │ Server│  │    │   .0/24   │       │
│   └───────────┘     │  └───────┘  │    └───────────┘       │
│                     │             │                         │
│                     │ 192.168.2   │                         │
│                     │   .0/24     │                         │
│                     └─────────────┘                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Matrice des regles inter-zones

| Zone Source | Zone Dest | Service | Action | Notes |
|-------------|-----------|---------|--------|-------|
| LAN | DMZ | HTTP, HTTPS | Allow | Acces aux serveurs web |
| LAN | WAN | All | Allow | Navigation Internet |
| LAN | MGMT | Any | Deny | Isolation management |
| DMZ | LAN | Any | Deny | Protection LAN |
| DMZ | WAN | HTTP, HTTPS, DNS | Allow | Updates, DNS |
| DMZ | MGMT | Any | Deny | Isolation management |
| WAN | DMZ | HTTP (NAT) | Allow | Acces public au web |
| WAN | LAN | Any | Deny | Protection LAN |
| WAN | MGMT | Any | Deny | Protection admin |
| MGMT | LAN | SSH, HTTPS | Allow | Administration |
| MGMT | DMZ | SSH, HTTPS | Allow | Administration |
| MGMT | WAN | Any | Deny | Pas d'acces Internet |

### Caracteristiques de cette architecture

| Feature | Implementation |
|---------|----------------|
| **Least Privilege** | Chaque zone a acces uniquement a ce qui est nécessaire |
| **Defense in Depth** | Plusieurs couches de protection |
| **Controlled Exposure** | Seule la DMZ est exposee a Internet |
| **Admin Isolation** | Zone management separee |
| **Logging** | Active sur toutes les regles deny |
| **NAT** | Utilise pour l'acces au serveur web |

---

## Gestion du trafic inter-zones

### Elements a considerer

| Element | Description |
|---------|-------------|
| **Source/Destination** | Toujours definir les deux - etre specifique |
| **Services/Ports** | Limiter aux services requis uniquement |
| **Protocole** | TCP, UDP, ICMP - specifier precisement |
| **Direction** | Inbound, outbound, ou les deux |
| **Logging** | Activer sur les regles critiques |

### Regles basees sur le temps

Vous pouvez ajouter des conditions temporelles :

```
Regle: Autoriser l'acces a Facebook
  - Heures: 12:00 - 13:00 (pause dejeuner)
  - Jours: Lundi - Vendredi
```

**pfSense :** Firewall > Schedules

### Logging recommande

Activer le logging pour :

| Type de trafic | Raison |
|----------------|--------|
| Connexions refusees | Detection d'intrusion |
| Trafic entrant | Audit de sécurité |
| Ports critiques (SSH, RDP) | Surveillance des acces |
| Regles NAT | Traçabilite |

### Outils d'analyse des logs

| Outil | Description |
|-------|-------------|
| **Syslog** | Centralisation des logs |
| **ELK Stack** | Elasticsearch, Logstash, Kibana |
| **Splunk** | Analyse enterprise |
| **Graylog** | Alternative open-source |
| **pfSense Logs** | Viewer integre |

---

## Erreurs courantes à éviter

| Erreur | Consequence | Solution |
|--------|-------------|----------|
| **Regles "Allow All"** | Annule l'utilite du firewall | Etre specifique |
| **Pas de blocage inter-zone** | Trafic non desire autorise | Toujours deny explicite |
| **Mauvais ordre des regles** | Allow au-dessus de deny | Verifier l'ordre |
| **NAT oublie pour DMZ** | IPs internes exposees | Configurer le NAT |
| **Pas de documentation** | Maintenance difficile | Documenter tout |
| **Regles expirées non supprimees** | Configuration polluee | Revue réguliere |
| **Logging desactive** | Pas de visibilite | Activer sur deny |

---

## Bonnes pratiques

### Conventions de nommage

```
Format: [SOURCE]_to_[DEST]_[SERVICE]

Exemples:
  LAN_to_DMZ_HTTP
  WAN_to_DMZ_HTTPS
  MGMT_to_ALL_SSH
  BLOCK_DMZ_to_LAN
```

### Organisation des regles

```
┌─────────────────────────────────────────────────────────────┐
│                  ORDRE RECOMMANDE DES REGLES                │
│                                                              │
│   1. Regles de blocage specifiques (IPs bannies, etc.)     │
│   2. Regles d'autorisation specifiques (serveurs)          │
│   3. Regles d'autorisation générales (LAN to Internet)     │
│   4. Regle de deny par defaut avec logging                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Checklist bonnes pratiques

```
[ ] Utiliser des conventions de nommage coherentes
[ ] Grouper les services (HTTP + HTTPS) dans des aliases
[ ] Activer l'inspection stateful
[ ] Creer des regles avec expiration pour acces temporaires
[ ] Utiliser des aliases pour simplifier la gestion
[ ] Garder le deny par defaut en bas de chaque interface
[ ] Documenter chaque regle avec une description
[ ] Reviser les regles régulierement (mensuel)
[ ] Tester les regles dans un environnement lab
[ ] Activer le logging sur les regles critiques
```

---

## Concepts avancés

### Detection d'intrusion inter-zones

Utilisez des systèmes IDS/IPS comme Suricata ou Snort entre les zones :

```
┌─────────────────────────────────────────────────────────────┐
│                    IDS/IPS INTER-ZONES                      │
│                                                              │
│                     ┌───────────┐                           │
│                     │  Suricata │                           │
│                     │    IPS    │                           │
│                     └─────┬─────┘                           │
│                           │                                  │
│         ┌─────────────────┼─────────────────┐               │
│         │                 │                 │               │
│         ▼                 ▼                 ▼               │
│   ┌───────────┐    ┌───────────┐    ┌───────────┐          │
│   │  DMZ→WAN  │    │  LAN→DMZ  │    │  WAN→DMZ  │          │
│   │ Inspection│    │ Inspection│    │ Inspection│          │
│   └───────────┘    └───────────┘    └───────────┘          │
│                                                              │
│   Bloquer le trafic malveillant entre zones                │
│   Alerter sur les comportements suspects                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Regles dynamiques via authentification

Certains firewalls permettent des politiques basees sur l'utilisateur :

| Methode | Description |
|---------|-------------|
| **Captive Portal** | Authentification web avant acces |
| **RADIUS** | Integration avec Active Directory |
| **802.1X** | Authentification au niveau port |

### Filtrage applicatif (Layer 7)

Les firewalls modernes supportent le filtrage Layer 7 :

```
Exemples:
  - Bloquer Facebook depuis la zone Guest
  - Autoriser YouTube uniquement dans la zone Education
  - Bloquer les applications P2P partout
  - Limiter la bande passante pour le streaming
```

---

## Vérification et dépannage

### Commandes Cisco ZBFW

```cisco
! Voir les zones configurees
show zone security

! Voir les zone-pairs
show zone-pair security

! Voir les politiques
show policy-map type inspect

! Statistiques des sessions
show policy-firewall sessions

! Debug (attention en production)
debug zone security
```

### Verification pfSense

```
! Status > System Logs > Firewall
  - Voir les paquets bloques/autorises

! Diagnostics > States
  - Voir les connexions actives

! Diagnostics > Packet Capture
  - Capturer le trafic pour analyse

! Status > Filter Reload
  - Forcer le rechargement des regles
```

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [Cisco - Zone-Based Firewall Design](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/98628-zone-design-guide.html) | Guide de conception ZBFW |
| [pfSense - Security Policies](https://docs.netgate.com/pfsense/en/latest/firewall/index.html) | Documentation firewall pfSense |
| [Cisco - ZBFW Configuration](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_zbf/configuration/xe-16/sec-data-zbf-xe-16-book.html) | Guide configuration Cisco |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Intro to Networking** | Fondamentaux réseau | https://tryhackme.com/room/introtonetworking |
| **Firewalls** | Introduction aux firewalls | https://tryhackme.com/room/dvwafirewalls |
| **Network Services** | Services réseau | https://tryhackme.com/room/networkservices |
| **Network Security** | Securite réseau | https://tryhackme.com/room/introtonetwwork |

> **Note** : Les zones de sécurité peuvent etre pratiquees sur GNS3 avec des routeurs Cisco (IOSv avec licence Security) ou sur pfSense virtuel. Pour les labs, creez une topologie avec au moins 3 zones (Inside, Outside, DMZ) et experimentez avec differentes politiques. Testez toujours vos regles en generant du trafic de test (ping, curl, nmap) pour verifier que les politiques fonctionnent comme prevu.
