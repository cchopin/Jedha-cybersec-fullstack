# VPN, IPSec, WireGuard et ZTNA - version simplifiée

## L'idée en une phrase

Un VPN crée un tunnel chiffré pour protéger les communications sur Internet, comme un tube opaque où personne ne peut voir ce qui passe.

---

## Pourquoi utiliser un VPN ?

```
Sans VPN :                              Avec VPN :

Internet (public)                       Internet (public)
     │                                       │
     │  Données en clair                     │  ┌─────────────────┐
     │  Tout le monde peut voir              │  │ TUNNEL CHIFFRÉ  │
     ▼                                       │  │  (Invisible)    │
┌─────────┐                                  │  └─────────────────┘
│Attaquant│ ← Peut intercepter               │
└─────────┘                                  ▼
                                       Données protégées !
```

### Objectifs d'un VPN

| Objectif | Explication |
|----------|-------------|
| **Confidentialité** | Chiffrement → personne ne peut lire |
| **Intégrité** | Personne ne peut modifier les données |
| **Authentification** | On sait à qui on parle |

---

## IPSec : le classique robuste

### Qu'est-ce qu'IPSec ?

IPSec est une suite de protocoles pour sécuriser les communications IP. C'est le VPN "classique" utilisé depuis des années.

### Les deux phases

```
Phase 1 : On se met d'accord
┌────────────────────────────────────────────┐
│ "Quel chiffrement utiliser ?"              │
│ "Comment on s'authentifie ?"               │
│ "Voici ma clé publique"                    │
│                                            │
│ → Création du tunnel de contrôle           │
└────────────────────────────────────────────┘
                    │
                    ▼
Phase 2 : On crée le tunnel
┌────────────────────────────────────────────┐
│ "Quel trafic on chiffre ?"                 │
│ "Voici les clés de session"                │
│                                            │
│ → Tunnel de données opérationnel !         │
└────────────────────────────────────────────┘
```

### Mode Tunnel vs Transport

```
Mode Tunnel (VPN Site-to-Site) :

┌──────────┬──────────────────────────────┐
│ Nouveau  │  Paquet original ENTIER      │
│ Header   │       (chiffré)              │
└──────────┴──────────────────────────────┘
                    ↑
            Tout est caché !


Mode Transport (Host-to-Host) :

┌──────────┬──────────┬───────────────────┐
│ Header   │ IPSec    │  Payload chiffrée │
│ Original │ Header   │                   │
└──────────┴──────────┴───────────────────┘
```

---

## WireGuard : le moderne et rapide

### Pourquoi WireGuard ?

| IPSec | WireGuard |
|-------|-----------|
| 400,000 lignes de code | 4,000 lignes |
| Complexe à configurer | Très simple |
| Performances moyennes | Excellentes |

### Configuration ultra-simple

```ini
[Interface]
PrivateKey = ma_cle_privee
Address = 10.0.0.2/24

[Peer]
PublicKey = cle_publique_du_serveur
AllowedIPs = 10.0.0.0/24
Endpoint = serveur.com:51820
```

C'est tout ! Comparer avec les dizaines de lignes pour IPSec...

---

## Site-to-site vs remote access

### VPN site-to-site

Connecte deux réseaux entiers :

```
    Siège (Paris)                    Filiale (Lyon)
    ┌───────────┐                    ┌───────────┐
    │ 192.168.1 │                    │ 192.168.2 │
    │  ┌───┐    │                    │    ┌───┐  │
    │  │PC │    │                    │    │PC │  │
    │  └───┘    │                    │    └───┘  │
    └─────┬─────┘                    └─────┬─────┘
          │        TUNNEL IPSec            │
          └════════════════════════════════┘

Les deux LANs communiquent comme s'ils étaient connectés
```

### VPN remote access

Connecte un utilisateur au réseau :

```
    ┌─────────────────────────┐
    │   Réseau Entreprise     │
    │  ┌────┐  ┌────┐ ┌────┐  │
    │  │App │  │ DB │ │File│  │
    │  └────┘  └────┘ └────┘  │
    └───────────┬─────────────┘
                │
           VPN Gateway
                │
        ┌───────┼───────┐
        │       │       │
    Laptop  Mobile   Maison
    (Hôtel) (Voyage) (Télétravail)
```

---

## ZTNA : le Zero Trust

### Le problème du VPN classique

```
VPN Traditionnel :

    Utilisateur ──→ VPN ──→ ACCÈS À TOUT LE RÉSEAU !
                              │
                     App1, App2, DB, Serveurs...
                              │
                     = Surface d'attaque énorme
```

### La solution ZTNA

```
ZTNA (Zero Trust) :

    Utilisateur ──→ ZTNA Broker ──→ UNIQUEMENT App1
                        │
              "Qui est-ce ?"
              "Quel appareil ?"
              "D'où la connexion ?"
              "À quelle heure ?"
                        │
              Vérification continue
```

### VPN vs ZTNA

| Aspect | VPN | ZTNA |
|--------|-----|------|
| **Accès** | Tout le réseau | Application par application |
| **Confiance** | Après login, confiance totale | Vérification continue |
| **Principe** | Castle-and-moat (château-douves : une fois dedans, accès libre) | Never trust, always verify (ne jamais faire confiance, toujours vérifier) |
| **Surface d'attaque** | Large | Réduite |

---

## Comparaison des protocoles VPN

| Critère | IPSec | WireGuard | OpenVPN |
|---------|-------|-----------|---------|
| **Performance** | Moyenne | Excellente | Basse |
| **Complexité** | Haute | Très basse | Moyenne |
| **Maturité** | Très mature | Nouveau | Mature |
| **Usage** | Entreprise | Moderne | Polyvalent |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **VPN** | Tunnel chiffré sur Internet |
| **IPSec** | Suite de protocoles VPN classique |
| **WireGuard** | VPN moderne, léger et rapide |
| **Site-to-Site** | VPN entre deux réseaux |
| **Remote Access** | VPN pour utilisateurs distants |
| **ZTNA** | Accès Zero Trust par application |
| **PSK** | Pre-Shared Key = Clé partagée pour l'authentification (comme un mot de passe commun) |
| **Tunnel Mode** | Chiffre le paquet entier |

---

## Résumé en 30 secondes

1. **VPN** = tunnel chiffré pour sécuriser les communications
2. **IPSec** = classique, robuste, mais complexe
3. **WireGuard** = moderne, simple, très rapide
4. **Site-to-Site** = connecte des réseaux
5. **Remote Access** = connecte des utilisateurs
6. **ZTNA** = accès granulaire par application, pas tout le réseau

---

## Schéma récapitulatif

```
TYPES DE VPN :

    Site-to-Site :                  Remote Access :

    Siège ════════ Filiale          User ──→ VPN Gateway
                                        ──→ Réseau
    2 réseaux connectés             1 utilisateur connecté


VPN vs ZTNA :

    VPN Classique :                 ZTNA :

    User ──→ VPN ──→ TOUT           User ──→ ZTNA ──→ App1 seulement
                     │                       │
             App1, App2, DB...               Vérification :
                     │                       - Identité
             Accès total                     - Appareil
             (dangereux)                     - Contexte


PROTOCOLES :

    IPSec :                         WireGuard :

    400,000 lignes de code          4,000 lignes
    Complex to configure            Super simple
    Enterprise standard             Modern & fast


WORKFLOW ZTNA :

    1. Demande d'accès
           │
           ▼
    2. ZTNA vérifie :
       - Identité (MFA)
       - Appareil (posture)
       - Contexte (lieu, heure)
           │
           ▼
    3. Accès accordé
       UNIQUEMENT à l'application demandée
       Pas à tout le réseau !
```
