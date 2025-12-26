# Domain Name System

## Introduction

Le DNS (Domain Name System) est l'annuaire d'Internet.   
Il traduit les noms de domaine lisibles par les humains (exemple.com) en adresses IP utilisables par les machines (93.184.216.34).   
Sans DNS, il faudrait mémoriser des suites de chiffres pour accéder aux sites web.

Ce cours couvre :
- La hiérarchie DNS (racine, TLD, domaines, sous-domaines)
- Le fonctionnement de la résolution DNS (récursive vs itérative)
- Les principaux types d'enregistrements DNS
- Les outils de diagnostic DNS
- La sécurité DNS (DNSSEC, DoH, DoT)

---

## Glossaire

| Sigle/Terme | Nom complet | Description |
|-------------|-------------|-------------|
| **DNS** | Domain Name System | Système de résolution de noms de domaine en adresses IP |
| **TLD** | Top-Level Domain | Domaine de premier niveau (.com, .fr, .org) |
| **SLD** | Second-Level Domain | Domaine de second niveau (exemple dans exemple.com) |
| **FQDN** | Fully Qualified Domain Name | Nom de domaine complet incluant tous les niveaux jusqu'à la racine |
| **TTL** | Time To Live | Durée de mise en cache d'un enregistrement DNS |
| **SOA** | Start Of Authority | Enregistrement définissant les paramètres de la zone DNS |
| **NS** | Name Server | Serveur de noms faisant autorité pour une zone |
| **A** | Address Record | Enregistrement associant un nom à une adresse IPv4 |
| **AAAA** | IPv6 Address Record | Enregistrement associant un nom à une adresse IPv6 |
| **MX** | Mail Exchange | Enregistrement indiquant les serveurs de messagerie |
| **CNAME** | Canonical Name | Alias pointant vers un autre nom de domaine |
| **PTR** | Pointer Record | Enregistrement de résolution inverse (IP → nom) |
| **TXT** | Text Record | Enregistrement contenant du texte arbitraire (SPF, DKIM, etc.) |
| **SRV** | Service Record | Enregistrement définissant l'emplacement de services |
| **DNSSEC** | DNS Security Extensions | Extensions de sécurité pour authentifier les réponses DNS |
| **DoH** | DNS over HTTPS | DNS chiffré via HTTPS |
| **DoT** | DNS over TLS | DNS chiffré via TLS |
| **ICANN** | Internet Corporation for Assigned Names and Numbers | Organisation gérant les noms de domaine et adresses IP |
| **Registrar** | Bureau d'enregistrement | Entité accréditée pour enregistrer des noms de domaine |
| **Registry** | Registre | Gestionnaire d'un TLD (ex: Verisign pour .com) |

---

## Hiérarchie DNS

### Structure arborescente

Le DNS est organisé en arborescence inversée, de la racine vers les feuilles :

```
                        . (racine)
                        │
        ┌───────────────┼───────────────┐
        │               │               │
       com             org             fr        ← TLD (Top-Level Domain)
        │               │               │
    ┌───┴───┐       ┌───┴───┐       ┌───┴───┐
 google   amazon  wikipedia jedha  gouv   example  ← SLD (Second-Level Domain)
    │               │               │
   www            mail            www              ← Sous-domaines
```

### Les niveaux de la hiérarchie

#### 1. La racine (Root Zone)

Le sommet de la hiérarchie, représenté par un point (.).

- 13 clusters de serveurs racine (A à M)
- Distribués mondialement via Anycast
- Connaissent l'emplacement de tous les serveurs TLD

Techniquement, le FQDN de google.com est `google.com.` (avec le point final représentant la racine).

#### 2. TLD (Top-Level Domain)

Le premier niveau sous la racine. Deux catégories principales :

| Type | Description | Exemples |
|------|-------------|----------|
| **gTLD** (Generic) | Domaines génériques, non liés à un pays | .com, .org, .net, .info, .edu |
| **ccTLD** (Country Code) | Domaines nationaux (2 lettres) | .fr, .uk, .de, .jp, .us |

Autres TLD notables :
- **sTLD** (Sponsored) : .gov, .mil, .edu (accès restreint)
- **New gTLD** : .blog, .shop, .tech, .xyz (créés depuis 2012)

Chaque TLD est géré par un **registry** (registre) :
- .com/.net : Verisign
- .fr : AFNIC
- .org : Public Interest Registry

#### 3. SLD (Second-Level Domain)

Le nom choisi par le propriétaire du domaine :

```
       exemple.com
       └──┬──┘ └┬┘
         SLD   TLD
```

C'est la partie "identité" du domaine, celle qu'on enregistre auprès d'un **registrar** (bureau d'enregistrement comme OVH, Gandi, GoDaddy).

#### 4. Sous-domaines

Niveaux supplémentaires créés par le propriétaire du domaine :

```
blog.exemple.com      → sous-domaine "blog"
api.v2.exemple.com    → sous-domaine "api" dans "v2"
mail.exemple.com      → sous-domaine pour le serveur mail
```

Le propriétaire d'un SLD peut créer autant de sous-domaines qu'il le souhaite.

### Lecture d'un FQDN

```
     mail.support.exemple.com.
     └─┬─┘└──┬───┘└──┬───┘└┬┘└┘
       │     │       │     │  │
       │     │       │     │  └─ Racine (implicite)
       │     │       │     └──── TLD
       │     │       └────────── SLD
       │     └────────────────── Sous-domaine niveau 1
       └──────────────────────── Sous-domaine niveau 2
```

La lecture se fait **de droite à gauche** (du plus général au plus spécifique).

---

## Résolution DNS

### Le processus de résolution

Quand un utilisateur saisit `www.exemple.com` dans son navigateur :

```
                 ①                     ②
┌─────────────┐      ┌────────────┐         ┌─────────────┐
│ Client      │─────►│ Résolveur  │────────►│ Serveur     │
│ (navigateur)│      │ récursif   │         │ racine      │
└─────────────┘      │ (ISP/local)│◄────────│             │
     ▲               └────────────┘         └─────────────┘
     │                     │           ③
     │                     │ ④        ┌─────────────┐
     │                     └──────────►│ Serveur     │
     │               ⑤      ◄──────── │ TLD (.com)  │
     │                                 └─────────────┘
     │                    │
     │                    │          ┌─────────────┐
     │                 ⑥ └──────────►│ Serveur     │
     │                    ◄───────────│ exemple.com │
     │                           ⑦    └─────────────┘
     │               ┌────────────┐
     └───────────────│ Réponse    │
            ⑧       │ IP finale  │
                     └────────────┘
```

### Requête récursive vs itérative

| Aspect | Récursive | Itérative |
|--------|-----------|-----------|
| **Qui fait le travail** | Le résolveur fait tout | Le client fait chaque étape |
| **Nombre de requêtes client** | 1 seule | Plusieurs |
| **Usage typique** | Client → Résolveur ISP | Résolveur → Serveurs DNS |
| **Analogie** | "Trouve-moi la réponse" | "Donne-moi un indice" |

#### Résolution récursive (la plus courante)

Le client demande au résolveur de trouver la réponse complète. Le résolveur interroge successivement les serveurs nécessaires et retourne la réponse finale.

```
Client ──────► Résolveur récursif
               (fait tout le travail)
       ◄────── Réponse complète
```

#### Résolution itérative

Le serveur interrogé renvoie soit la réponse, soit une référence vers un autre serveur. Le demandeur doit poursuivre lui-même.

```
Client ──────► Serveur racine
       ◄────── "Demande au serveur .com"

Client ──────► Serveur .com
       ◄────── "Demande au serveur exemple.com"

Client ──────► Serveur exemple.com
       ◄────── Réponse finale
```

### Le cache DNS

Pour éviter de répéter ce processus à chaque requête, les réponses sont mises en cache :

| Niveau de cache | Emplacement | Durée |
|-----------------|-------------|-------|
| Navigateur | Local sur le poste | Quelques minutes |
| Système d'exploitation | Local sur le poste | Variable |
| Résolveur récursif | Serveur DNS de l'ISP | Selon le TTL |

Le **TTL** (Time To Live) définit combien de temps un enregistrement reste en cache.

---

## Enregistrements DNS

### Les enregistrements principaux

#### A (Address Record)

Associe un nom de domaine à une adresse **IPv4**.

```
exemple.com.    IN    A    93.184.216.34
```

| Champ | Signification |
|-------|---------------|
| exemple.com. | Nom de domaine (FQDN avec point final) |
| IN | Classe Internet (standard) |
| A | Type d'enregistrement |
| 93.184.216.34 | Adresse IPv4 |

Un domaine peut avoir plusieurs enregistrements A (load balancing, redondance).

#### AAAA (IPv6 Address Record)

Associe un nom de domaine à une adresse **IPv6**.

```
exemple.com.    IN    AAAA    2606:2800:220:1:248:1893:25c8:1946
```

Le nom "AAAA" vient du fait qu'une adresse IPv6 (128 bits) est 4 fois plus grande qu'une IPv4 (32 bits).

#### MX (Mail Exchange)

Indique les serveurs responsables de la réception des emails pour un domaine.

```
exemple.com.    IN    MX    10 mail1.exemple.com.
exemple.com.    IN    MX    20 mail2.exemple.com.
```

| Champ | Signification |
|-------|---------------|
| 10, 20 | Priorité (plus petit = priorité plus haute) |
| mail1, mail2 | Serveurs de messagerie |

Si mail1 est indisponible, les emails sont envoyés à mail2.

#### CNAME (Canonical Name)

Crée un **alias** pointant vers un autre nom de domaine.

```
www.exemple.com.    IN    CNAME    exemple.com.
blog.exemple.com.   IN    CNAME    exemple.github.io.
```

**Règles importantes** :
- Un CNAME ne peut pas coexister avec d'autres enregistrements pour le même nom
- Un CNAME ne peut pas être créé à la racine du domaine (exemple.com)
- La cible d'un CNAME doit être un nom de domaine, pas une IP

#### NS (Name Server)

Indique les serveurs DNS faisant autorité pour une zone.

```
exemple.com.    IN    NS    ns1.exemple.com.
exemple.com.    IN    NS    ns2.exemple.com.
```

Ces serveurs contiennent les enregistrements officiels de la zone.

#### PTR (Pointer Record)

Utilisé pour la **résolution inverse** : associe une IP à un nom de domaine.

```
34.216.184.93.in-addr.arpa.    IN    PTR    exemple.com.
```

L'adresse IP est écrite **à l'envers** suivie de `.in-addr.arpa` (IPv4) ou `.ip6.arpa` (IPv6).

**Usages** :
- Validation des serveurs mail (anti-spam)
- Logs et forensics
- Vérification de légitimité

#### TXT (Text Record)

Contient du texte arbitraire, souvent utilisé pour la sécurité email et la vérification de propriété.

```
exemple.com.    IN    TXT    "v=spf1 include:_spf.google.com ~all"
```

**Usages courants** :

| Usage | Description |
|-------|-------------|
| SPF | Liste des serveurs autorisés à envoyer des emails pour le domaine |
| DKIM | Clé publique pour vérifier la signature des emails |
| DMARC | Politique de traitement des emails non conformes SPF/DKIM |
| Vérification | Prouver la propriété d'un domaine (Google, Microsoft, etc.) |

#### SOA (Start Of Authority)

Définit les paramètres de la zone DNS.

```
exemple.com.    IN    SOA    ns1.exemple.com. admin.exemple.com. (
                            2024010101 ; Serial
                            7200       ; Refresh
                            3600       ; Retry
                            1209600    ; Expire
                            86400 )    ; Minimum TTL
```

| Champ | Description |
|-------|-------------|
| ns1.exemple.com | Serveur DNS primaire |
| admin.exemple.com | Email de l'admin (@ remplacé par .) |
| Serial | Numéro de version de la zone |
| Refresh | Intervalle de synchronisation des secondaires |
| Retry | Délai avant nouvelle tentative si échec |
| Expire | Durée max sans contact avec le primaire |
| Minimum TTL | TTL par défaut pour les réponses négatives |

#### SRV (Service Record)

Localise des services spécifiques (VoIP, LDAP, XMPP, etc.).

```
_sip._tcp.exemple.com.    IN    SRV    10 5 5060 sipserver.exemple.com.
```

Format : `_service._protocole.domaine`

| Champ | Signification |
|-------|---------------|
| 10 | Priorité |
| 5 | Poids (pour le load balancing) |
| 5060 | Port du service |
| sipserver... | Serveur hébergeant le service |

### Tableau récapitulatif

| Type | Fonction | Exemple de valeur |
|------|----------|-------------------|
| A | Nom → IPv4 | 93.184.216.34 |
| AAAA | Nom → IPv6 | 2606:2800:220:1::1 |
| MX | Serveurs mail | 10 mail.exemple.com |
| CNAME | Alias | www → exemple.com |
| NS | Serveurs DNS | ns1.exemple.com |
| PTR | IPv4 → Nom | exemple.com |
| TXT | Texte (SPF, DKIM) | "v=spf1 ..." |
| SOA | Paramètres zone | (voir ci-dessus) |
| SRV | Localisation service | 10 5 5060 sip.exemple.com |

---

## TTL (Time To Live)

### Définition

Le TTL indique **combien de temps** (en secondes) un enregistrement DNS peut rester en cache avant d'être rafraîchi.

```
exemple.com.    3600    IN    A    93.184.216.34
                └─┬─┘
                  └── TTL : 3600 secondes = 1 heure
```

### Impact du TTL

| TTL | Avantages | Inconvénients |
|-----|-----------|---------------|
| **Court** (60-300s) | Changements propagés rapidement | Plus de requêtes, charge serveur |
| **Long** (86400s+) | Moins de requêtes, résolution plus rapide | Changements lents à propager |

### Recommandations

| Situation | TTL recommandé |
|-----------|----------------|
| Fonctionnement normal | 3600 - 86400 (1h - 24h) |
| Avant une migration | Réduire à 300 (5 min) quelques jours avant |
| Pendant une migration | Garder bas jusqu'à stabilisation |
| Enregistrements critiques | 300 - 900 (5-15 min) |

---

## Outils DNS

### dig (Domain Information Groper)

Outil le plus complet pour interroger le DNS.

#### Requête basique (enregistrement A)

```bash
dig exemple.com
```

#### Requête pour un type spécifique

```bash
dig MX exemple.com      # Serveurs mail
dig NS exemple.com      # Serveurs DNS
dig TXT exemple.com     # Enregistrements TXT
dig AAAA exemple.com    # Adresse IPv6
dig ANY exemple.com     # Tous les enregistrements (souvent bloqué)
```

#### Options utiles

```bash
dig +short exemple.com           # Réponse concise (IP seulement)
dig +trace exemple.com           # Trace complète de la résolution
dig @8.8.8.8 exemple.com         # Interroger un serveur DNS spécifique
dig -x 93.184.216.34             # Résolution inverse (PTR)
```

#### Lecture d'une réponse dig

```
;; QUESTION SECTION:
;exemple.com.                   IN      A

;; ANSWER SECTION:
exemple.com.            3600    IN      A       93.184.216.34

;; AUTHORITY SECTION:
exemple.com.            86400   IN      NS      ns1.exemple.com.

;; Query time: 45 msec
;; SERVER: 192.168.1.1#53
```

| Section | Contenu |
|---------|---------|
| QUESTION | Ce qui a été demandé |
| ANSWER | La réponse à la requête |
| AUTHORITY | Serveurs faisant autorité |
| ADDITIONAL | Informations supplémentaires (IPs des NS) |

### nslookup

Outil plus simple, disponible sur tous les systèmes.

```bash
nslookup exemple.com                    # Requête basique
nslookup -query=MX exemple.com          # Type spécifique
nslookup exemple.com 8.8.8.8            # Serveur DNS spécifique
```

### host

Outil léger pour des requêtes rapides.

```bash
host exemple.com                # Requête basique
host -t MX exemple.com          # Type spécifique
host -t NS exemple.com          # Serveurs DNS
host 93.184.216.34              # Résolution inverse
```

### Comparaison des outils

| Outil | Détail | Simplicité | Disponibilité |
|-------|--------|------------|---------------|
| dig | Très détaillé | Moyenne | Linux, macOS |
| nslookup | Moyen | Simple | Tous OS |
| host | Concis | Très simple | Linux, macOS |

---

## Sécurité DNS

### Menaces DNS

| Menace | Description | Impact |
|--------|-------------|--------|
| **DNS Spoofing** | Réponses DNS falsifiées | Redirection vers sites malveillants |
| **DNS Cache Poisoning** | Injection de faux enregistrements dans le cache | Redirection persistante |
| **DNS Hijacking** | Modification des paramètres DNS du client | Contrôle total de la résolution |
| **DNS Tunneling** | Exfiltration de données via requêtes DNS | Fuite de données, C2 |
| **DNS Amplification DDoS** | Utilisation de DNS pour amplifier une attaque | Déni de service |
| **Typosquatting** | Enregistrement de domaines similaires (gooogle.com) | Phishing, malware |
| **Domain Shadowing** | Création de sous-domaines sur des domaines compromis | Phishing, C2 |

### DNSSEC (DNS Security Extensions)

DNSSEC ajoute une **signature cryptographique** aux enregistrements DNS pour garantir leur authenticité.

#### Principe

```
                    Sans DNSSEC                 Avec DNSSEC
                    ────────────                ───────────
Serveur DNS ───────► Réponse ──────────► Réponse + Signature
                         │                        │
                         ▼                        ▼
                    Pas de                   Vérification
                    vérification             de la signature
                         │                        │
                         ▼                        ▼
                    Réponse                  Réponse validée
                    (peut être               OU rejetée si
                    falsifiée)               falsifiée
```

#### Ce que DNSSEC fait et ne fait pas

| DNSSEC fait | DNSSEC ne fait pas |
|-------------|-------------------|
| Authentifie l'origine des données | Ne chiffre pas les requêtes |
| Garantit l'intégrité des données | Ne protège pas la confidentialité |
| Protège contre le cache poisoning | Ne protège pas contre le tracking |

#### Enregistrements DNSSEC

| Type | Rôle |
|------|------|
| RRSIG | Signature d'un enregistrement |
| DNSKEY | Clé publique de la zone |
| DS | Hash de la clé, stocké dans la zone parente |
| NSEC/NSEC3 | Preuve de non-existence d'un enregistrement |

### DNS chiffré : DoH et DoT

Les requêtes DNS traditionnelles sont en **clair** (port 53 UDP/TCP). Elles peuvent être interceptées, modifiées ou surveillées.

#### DoT (DNS over TLS)

- Port 853
- Chiffrement TLS
- Identifiable par le port utilisé

#### DoH (DNS over HTTPS)

- Port 443
- Chiffrement HTTPS
- Indistinguable du trafic web normal

#### Comparaison

| Aspect | DNS classique | DoT | DoH |
|--------|--------------|-----|-----|
| Port | 53 | 853 | 443 |
| Chiffrement | Non | Oui (TLS) | Oui (HTTPS) |
| Détectable | Oui | Oui (port) | Difficilement |
| Blocable | Facilement | Facilement | Difficilement |

#### Serveurs DNS publics supportant DoH/DoT

| Fournisseur | Adresse | DoH | DoT |
|-------------|---------|-----|-----|
| Cloudflare | 1.1.1.1 | Oui | Oui |
| Google | 8.8.8.8 | Oui | Oui |
| Quad9 | 9.9.9.9 | Oui | Oui |

### Implications cybersécurité

#### Pour la défense

| Pratique | Objectif |
|----------|----------|
| Surveiller les requêtes DNS | Détecter tunneling, C2, exfiltration |
| Bloquer les domaines malveillants | Filtrage DNS (Pi-hole, etc.) |
| Activer DNSSEC | Prévenir le spoofing |
| Configurer SPF/DKIM/DMARC | Protéger contre le phishing email |
| Journaliser les requêtes | Forensics et détection d'incidents |

#### Pour l'attaque (pentest)

| Technique | Usage |
|-----------|-------|
| Énumération DNS | Découvrir sous-domaines, serveurs |
| Zone transfer (AXFR) | Récupérer toute la zone si mal configuré |
| Reverse DNS | Identifier les services sur une plage IP |
| DNS bruteforce | Trouver des sous-domaines cachés |

#### Commandes d'énumération

```bash
# Tentative de transfert de zone
dig axfr exemple.com @ns1.exemple.com

# Énumération de sous-domaines
host -l exemple.com ns1.exemple.com

# Bruteforce de sous-domaines (avec wordlist)
# Outils : dnsenum, dnsrecon, subfinder, amass
```

---

## CDN et DNS intelligent

### Principe

Les CDN (Content Delivery Networks) utilisent le DNS pour diriger les utilisateurs vers le serveur le plus proche ou le plus performant.

```
Utilisateur en France ──► DNS ──► Serveur CDN en Europe
Utilisateur au Japon  ──► DNS ──► Serveur CDN en Asie
```

### Techniques

| Technique | Description |
|-----------|-------------|
| GeoDNS | Réponse basée sur la localisation du client |
| Anycast | Même IP, plusieurs serveurs (le plus proche répond) |
| Load balancing | Répartition de charge entre serveurs |
| Health checks | Retrait automatique des serveurs défaillants |

### Implications sécurité

| Avantage | Risque |
|----------|--------|
| Protection DDoS | Complexité d'analyse |
| Masquage de l'origine | Contournement possible |
| Haute disponibilité | Dépendance au CDN |

---

## Commandes récapitulatives

```bash
# Résolution basique
dig exemple.com
nslookup exemple.com
host exemple.com

# Type d'enregistrement spécifique
dig MX exemple.com
dig NS exemple.com
dig TXT exemple.com
dig AAAA exemple.com

# Résolution inverse
dig -x 93.184.216.34
host 93.184.216.34

# Utiliser un serveur DNS spécifique
dig @8.8.8.8 exemple.com
nslookup exemple.com 1.1.1.1

# Trace complète de résolution
dig +trace exemple.com

# Réponse courte
dig +short exemple.com

# Vérifier DNSSEC
dig +dnssec exemple.com

# Tentative de transfert de zone
dig axfr exemple.com @ns1.exemple.com

# Vider le cache DNS local (Linux)
sudo systemd-resolve --flush-caches

# Vider le cache DNS local (Windows)
ipconfig /flushdns

# Afficher le cache DNS (Windows)
ipconfig /displaydns
```

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| https://www.icann.org | Organisation gérant les noms de domaine |
| https://www.iana.org/domains/root/db | Base de données des TLD |
| https://dnsviz.net | Visualisation et diagnostic DNSSEC |
| https://mxtoolbox.com | Outils DNS en ligne |
| https://securitytrails.com | Historique DNS et reconnaissance |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **DNS in Detail** | Fonctionnement complet du DNS et types d'enregistrements | https://tryhackme.com/room/dnsindetail |
| **Passive Reconnaissance** | Reconnaissance DNS passive (dig, nslookup, whois) | https://tryhackme.com/room/passiverecon |
| **Active Reconnaissance** | Techniques actives de reconnaissance DNS | https://tryhackme.com/room/activerecon |
| **Content Discovery** | Enumeration de sous-domaines et découverte de contenu | https://tryhackme.com/room/contentdiscovery |
