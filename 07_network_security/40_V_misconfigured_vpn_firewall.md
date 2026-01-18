# VPN et Firewalls Mal Configurés - Version Simplifiée

## L'idée en une phrase

Les VPN et firewalls mal configurés sont comme des portes blindées laissées ouvertes : inutiles contre les attaquants qui entrent sans effort.

---

## Pourquoi les misconfigurations sont dangereuses

```
Firewall bien configuré :           Firewall mal configuré :

    ┌─────────────────────┐           ┌─────────────────────┐
    │  Toutes les portes  │           │  Porte ouverte !    │
    │  sont verrouillées  │           │                     │
    │                     │           │       ┌───┐         │
    │  Attaquant doit     │           │       │   │ Entrez !│
    │  trouver une faille │           │       └───┘         │
    └─────────────────────┘           └─────────────────────┘

Pour un attaquant, une misconfiguration = porte non verrouillée
Pas besoin de crocheter, on entre !
```

---

## Misconfigurations VPN courantes

### 1. Pas de MFA (authentification multi-facteurs)

```
Sans MFA :                          Avec MFA :

Attaquant trouve le mot de passe    Attaquant trouve le mot de passe
         ↓                                   ↓
   "SecretPassword123"              "SecretPassword123" + Code SMS
         ↓                                   ↓
   ACCÈS ACCORDÉ !                   "Entrer le code..."
                                             ↓
                                     Attaquant BLOQUÉ !
```

**Cas réel : Colonial Pipeline (2021)**
- Compte VPN sans MFA
- Mot de passe trouvé sur le dark web
- Résultat : 4.4 millions de rançon, 6 jours d'arrêt

### 2. Chiffrement obsolète

| À éviter | À utiliser |
|----------|------------|
| PPTP | WireGuard |
| 3DES | AES-256 |
| TLS 1.0/1.1 | TLS 1.3 |
| MD5 | SHA-256 |

### 3. Split Tunneling risqué

```
Split Tunneling :

    Laptop
      │
      ├──→ VPN ──→ Réseau entreprise
      │
      └──→ Internet direct ──→ Site malveillant
                                    │
                                    ↓
                              Malware infecte le laptop
                                    │
                                    ↓
                              Pivot vers réseau entreprise
                              via le tunnel VPN !
```

---

## Misconfigurations Firewall courantes

### 1. La pire règle possible

```cisco
access-list 100 permit ip any any

Conséquence :
- Tout le trafic autorisé
- ZÉRO protection
- Autant ne pas avoir de firewall
```

### 2. Services dangereux exposés

```
MAUVAIS :

Internet ──→ Firewall ──→ RDP (3389) OUVERT
                    └──→ SSH (22) OUVERT
                    └──→ SMB (445) OUVERT

= Attaques brute-force constantes
= Exploitation de vulnérabilités

BON :

Internet ──→ Firewall ──→ VPN uniquement
                    └──→ RDP/SSH via VPN seulement
```

### 3. Shadow Rules (règles éclipsées)

```cisco
! MAUVAIS :
access-list 100 permit ip 192.168.1.0/24 any     ! Autorise tout le subnet
access-list 100 deny ip host 192.168.1.50 any    ! JAMAIS ATTEINT !

! BON :
access-list 100 deny ip host 192.168.1.50 any    ! Spécifique d'abord
access-list 100 permit ip 192.168.1.0/24 any     ! Général ensuite
```

### 4. Confiance aveugle au LAN

```
Hypothèse dangereuse :              Réalité :

"Le LAN est sûr"                    Un seul PC compromis
"Pas besoin de segmenter"           = Mouvement latéral libre
                                    = Compromission totale

    ┌─────────────────────────┐
    │         LAN             │
    │  PC ── PC ── PC ── DB   │
    │         │               │
    │    PC infecté           │
    │         │               │
    │    Accès libre à tout ! │
    └─────────────────────────┘
```

---

## Chaîne d'attaque typique

```
1. RECONNAISSANCE
   $ shodan search "OpenVPN"
   → VPN trouvé sur Internet

2. BRUTE-FORCE
   $ hydra -l admin -P passwords.txt vpn.target.com
   → Credential trouvé (pas de rate limiting)

3. ACCÈS VPN
   → Connexion réussie (pas de MFA)

4. SCAN INTERNE
   $ nmap -sV 192.168.1.0/24
   → Serveurs découverts (pas de segmentation)

5. MOUVEMENT LATÉRAL
   $ smbexec.py domain/user:pass@target
   → Accès aux serveurs (SMB ouvert partout)

6. EXFILTRATION
   → Vol de données via le tunnel VPN (chiffré !)
   → Aucune alerte déclenchée
```

---

## Protections essentielles

### Pour les VPN

| Mesure | Pourquoi |
|--------|----------|
| **MFA obligatoire** | Mot de passe seul ne suffit pas |
| **Chiffrement fort** | AES-256, TLS 1.3 |
| **Géo-restriction** | Bloquer les pays non nécessaires |
| **Rate limiting** | Bloquer le brute-force |
| **Timeout sessions** | Déconnexion après inactivité |
| **Logging complet** | Détecter les intrusions |

### Pour les Firewalls

| Mesure | Pourquoi |
|--------|----------|
| **Deny par défaut** | Bloquer tout, autoriser spécifiquement |
| **Pas de "any any"** | Chaque règle doit être spécifique |
| **Segmentation** | Limiter le mouvement latéral |
| **Egress filtering** | Contrôler le trafic sortant |
| **Logger les deny** | Voir ce qui est bloqué |
| **Review régulière** | Nettoyer les règles obsolètes |

---

## Checklist sécurité

### VPN

```
□ MFA activé pour TOUS les utilisateurs
□ Chiffrement AES-256 / TLS 1.3
□ Géo-restriction configurée
□ Rate limiting actif
□ Comptes legacy désactivés
□ Split tunneling désactivé ou contrôlé
□ Logging et alerting en place
```

### Firewall

```
□ Pas de règles "any any"
□ Services admin non exposés à Internet
□ Segmentation interne en place
□ Egress filtering configuré
□ Port forwarding avec restriction source
□ Logging sur toutes les règles deny
□ Review mensuelle des règles
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Misconfiguration** | Erreur de configuration = vulnérabilité |
| **MFA** | Multi-Factor Authentication |
| **Split Tunneling** | VPN + Internet direct en même temps |
| **Shadow Rule** | Règle rendue inefficace par une autre |
| **Lateral Movement** | Mouvement latéral = Déplacement d'un attaquant de machine en machine dans le réseau |
| **Brute Force** | Essayer tous les mots de passe |
| **Egress Filtering** | Filtrage de sortie = Contrôler le trafic qui sort du réseau vers Internet |

---

## Résumé en 30 secondes

1. **Misconfigurations** = portes ouvertes pour les attaquants
2. **VPN sans MFA** = 1 mot de passe volé = accès total
3. **"any any"** = pas de firewall du tout
4. **Split tunneling** = risque de pivot via malware
5. **Confiance au LAN** = mouvement latéral facile
6. **MFA + Segmentation + Logging** = protections essentielles

---

## Schéma récapitulatif

```
ATTAQUE TYPIQUE :

    1. Recon                 2. Brute-force          3. Accès
    ┌──────────────┐         ┌──────────────┐        ┌──────────────┐
    │ Shodan       │   →     │ Hydra        │   →    │ VPN Connect  │
    │ "OpenVPN"    │         │ password.txt │        │ (Pas de MFA) │
    └──────────────┘         └──────────────┘        └──────────────┘
                                                            │
                                                            ▼
    6. Exfiltration          5. Lateral Move         4. Scan interne
    ┌──────────────┐         ┌──────────────┐        ┌──────────────┐
    │ Vol données  │   ←     │ SMB ouvert   │   ←    │ Nmap         │
    │ Via VPN      │         │ partout      │        │ 192.168.1.0  │
    └──────────────┘         └──────────────┘        └──────────────┘


COLONIAL PIPELINE (2021) :

    Compte VPN legacy
         │
         ↓
    Mot de passe sur dark web
         │
         ↓
    Pas de MFA ← ERREUR FATALE
         │
         ↓
    Accès au réseau
         │
         ↓
    Ransomware déployé
         │
         ↓
    $4.4 millions de rançon
    6 jours d'arrêt


PROTECTION ESSENTIELLE :

    ┌─────────────────────────────────────────────┐
    │                                             │
    │   VPN :           Firewall :                │
    │   □ MFA           □ Deny par défaut         │
    │   □ AES-256       □ Pas de "any any"        │
    │   □ Géo-restrict  □ Segmentation            │
    │   □ Rate limit    □ Egress filtering        │
    │   □ Logging       □ Logging deny            │
    │                                             │
    └─────────────────────────────────────────────┘
```
