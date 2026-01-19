# Manipulation des protocoles de routage - version simplifiée

## L'idée en une phrase

Les protocoles de routage sont basés sur la confiance : un attaquant qui s'infiltre peut injecter de fausses routes pour intercepter, modifier ou bloquer le trafic.

---

## Pourquoi les protocoles de routage sont vulnérables ?

Les protocoles ont été conçus à une époque où tous les participants étaient de confiance :

| Protocole | Problème |
|-----------|----------|
| **OSPF** | N'importe quel routeur peut rejoindre une aire |
| **BGP** | Toute annonce est acceptée par défaut |
| **RIP** | Aucune authentification native |

**Analogie** : c'est comme si n'importe qui pouvait ajouter des panneaux de signalisation sur l'autoroute. Les conducteurs suivraient les faux panneaux sans se méfier.

---

## Types d'attaques

### 1. Route Injection

L'attaquant **injecte de fausses routes** pour rediriger le trafic :

```
Situation normale :
PC → Routeur légitime → Serveur

Après injection :
PC → Routeur légitime → Attaquant → Serveur (ou nulle part)
                            ↑
                   Intercepte tout !
```

### 2. Blackhole

L'attaquant injecte une route vers une destination inexistante :

```
Route injectée : 10.0.0.0/8 → NULL

Résultat : tout le trafic vers 10.x.x.x disparaît
         = Déni de service
```

### 3. Man-in-the-Middle

L'attaquant se place au milieu du chemin :

```
Normal : PC ──────────────────────────→ Serveur

MitM :   PC ──→ Attaquant ──→ Serveur
              (lit et modifie tout !)
```

---

## Attaque OSPF : Rogue Router

### Le scénario

```
1. Attaquant branche son routeur au réseau
2. Configure OSPF avec les mêmes paramètres
3. Établit des adjacences avec les vrais routeurs
4. Injecte des routes avec des métriques faibles
5. Le trafic est redirigé vers lui !
```

### Exemple avec Scapy (Python)

```python
# Envoi d'un paquet OSPF Hello malveillant
from scapy.all import *

ospf_hello = IP(dst="224.0.0.5") / OSPF_Hdr() / OSPF_Hello()
send(ospf_hello)
```

### Détection

```cisco
! Vérifier les voisins OSPF
show ip ospf neighbor

! Si un voisin inconnu apparaît = ALERTE !
```

---

## Attaque BGP : Prefix Hijacking

### Le scénario

```
Normal :
AS 65001 (banque) annonce 203.0.113.0/24
→ Tout le monde route vers la vraie banque

Attaque :
AS 65999 (attaquant) annonce 203.0.113.0/25
→ Route plus spécifique = préférée
→ Trafic redirigé vers l'attaquant
```

### Cas réels

| Année | Victime | Impact |
|-------|---------|--------|
| 2008 | YouTube | 2h d'indisponibilité mondiale |
| 2018 | MyEtherWallet | Vol de $150,000 en crypto |
| 2022 | KLAYswap | Vol de $1.9 million |

---

## Outils d'attaque (Red Team)

| Outil | Usage |
|-------|-------|
| **Scapy** | Créer des paquets OSPF/BGP personnalisés |
| **ExaBGP** | Injecter des routes BGP |
| **Loki** | Attaques sur protocoles de routage |
| **Yersinia** | Attaques Layer 2/3 |

---

## Protections (Blue Team)

### Protection OSPF

#### 1. Authentification

```cisco
interface GigabitEthernet0/0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 SecretKey123
```

Sans le mot de passe, impossible de devenir voisin.

#### 2. Passive Interface

```cisco
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/0
```

OSPF n'écoute que sur les interfaces explicitement activées.

### Protection BGP

#### 1. RPKI

```cisco
router bgp 65001
 bgp rpki server tcp 10.0.0.100

! Rejeter les routes invalides
route-map RPKI-FILTER deny 10
 match rpki invalid
route-map RPKI-FILTER permit 20
```

#### 2. Filtrage de préfixes

```cisco
ip prefix-list BOGON deny 10.0.0.0/8 le 32
ip prefix-list BOGON deny 192.168.0.0/16 le 32
ip prefix-list BOGON permit 0.0.0.0/0 le 24

router bgp 65001
 neighbor 10.0.0.2 prefix-list BOGON in
```

---

## Détection des attaques

### Indicateurs de compromission

| Indicateur | Signification |
|------------|---------------|
| Nouveau voisin OSPF inattendu | Possible rogue router |
| Changement de route soudain | Possible injection |
| Trafic vers des IPs inhabituelles | Possible redirection |

### Outils de monitoring

| Outil | Usage |
|-------|-------|
| **BGPStream** | Détecter les anomalies BGP |
| **Wireshark** | Analyser le trafic OSPF/BGP |
| **RIPE RIS** | Historique des routes BGP |

### Script de détection

```python
# Alerter si nouveau voisin OSPF
known_routers = ["10.0.0.1", "10.0.0.2"]

def detect_rogue(pkt):
    if OSPF_Hdr in pkt:
        src = pkt[OSPF_Hdr].src
        if src not in known_routers:
            print(f"ALERTE: Rogue router {src}")

sniff(filter="proto ospf", prn=detect_rogue)
```

---

## Checklist sécurité routage

### OSPF

```
□ Authentification MD5 sur toutes les interfaces
□ Passive-interface par défaut
□ Router ID configuré manuellement
□ Monitoring des voisins
```

### BGP

```
□ RPKI déployé
□ Filtrage bogon
□ Maximum-prefix configuré
□ Authentification MD5
□ Monitoring des annonces
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Route Injection** | Injecter de fausses routes |
| **Rogue Router** | Routeur pirate infiltré dans le réseau |
| **Blackhole** | Route vers nulle part (le trafic disparaît = déni de service) |
| **Prefix Hijacking** | Annoncer des IPs non possédées |
| **LSA** | Message OSPF décrivant la topologie |
| **RPKI** | Validation cryptographique BGP |

---

## Résumé en 30 secondes

1. Les protocoles de routage font **confiance** par défaut
2. Un attaquant peut **injecter de fausses routes**
3. Conséquences : **interception, modification, blocage** du trafic
4. **OSPF** : protéger avec authentification MD5 + passive-interface
5. **BGP** : protéger avec RPKI + filtrage de préfixes
6. Toujours **monitorer** les changements de routes

---

## Schéma récapitulatif

```
ATTAQUE OSPF - ROGUE ROUTER :

         Réseau légitime
    ┌───────────────────────┐
    │  R1 ──── R2 ──── R3   │
    │         │              │
    │    ┌────┴────┐        │
    │    │ ROGUE   │ Attaquant s'infiltre
    │    │ ROUTER  │ et injecte des routes
    │    └─────────┘        │
    └───────────────────────┘

1. Rogue router établit adjacences
2. Annonce des routes avec coût faible
3. Le trafic est redirigé vers lui !


ATTAQUE BGP - PREFIX HIJACKING :

    Normal :
    AS légitime ────→ 203.0.113.0/24

    Attaque :
    AS légitime ────→ 203.0.113.0/24
    AS attaquant ───→ 203.0.113.0/25 (plus spécifique!)
                           ↓
            Tout le monde préfère /25
                           ↓
            Trafic détourné !


PROTECTION :

    ┌──────────────────────────────────────┐
    │  Authentification MD5/SHA            │
    │  Passive-interface                   │
    │  RPKI pour BGP                       │
    │  Filtrage de préfixes                │
    │  Monitoring des changements          │
    └──────────────────────────────────────┘
           = Attaques bloquées !
```
