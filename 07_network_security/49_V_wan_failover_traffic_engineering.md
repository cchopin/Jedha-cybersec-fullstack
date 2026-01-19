# WAN failover et traffic engineering - version simplifiée

## L'idée en une phrase

Le WAN failover, c'est avoir un plan B automatique quand la connexion Internet tombe : **BFD** détecte la panne en 50ms, **IP SLA** vérifie que tout marche, **HSRP/VRRP** bascule la gateway, et **PBR** envoie le bon trafic sur le bon lien.

---

## Les 4 piliers du WAN failover

```
┌─────────────────────────────────────────────────────────────┐
│                  LES 4 PILIERS                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. BFD        → Détection ultra-rapide (<50ms)              │
│  2. IP SLA     → Monitoring proactif (ping, HTTP, etc.)      │
│  3. HSRP/VRRP  → Redondance de gateway                       │
│  4. PBR        → Routage intelligent par type de trafic      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## BFD : le détecteur ultra-rapide

### C'est quoi BFD ?

BFD (Bidirectional Forwarding Detection) détecte les pannes en **moins de 50 millisecondes**.

```
SANS BFD :
──────────

[Router A] ══════════════════════X═════════════════ [Router B]
                                 │
                            Lien coupé
                                 │
    Temps de détection : 180 secondes (BGP hold timer)
    → 3 minutes sans Internet !


AVEC BFD :
──────────

[Router A] ◄══ Hello ══► [Router B]
           ◄══ Hello ══►
           ◄══ Hello ══X   ← Plus de réponse !
                 │
    Temps de détection : 50 millisecondes
    → Failover quasi-instantané !
```

### Comment ça marche ?

```
1. Les routeurs s'envoient des "Hello" très fréquemment (toutes les 10-50ms)
2. Si 3 Hello consécutifs sont manqués → Lien déclaré DOWN
3. BFD prévient immédiatement BGP/OSPF
4. Le protocole de routage bascule sur le lien backup
```

---

## IP SLA : le moniteur de santé

### C'est quoi IP SLA ?

IP SLA surveille la santé des liens en envoyant des tests (ping, HTTP, etc.).

```
┌─────────────────────────────────────────────────────────────┐
│                    IP SLA EN ACTION                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   CONFIGURATION :                                            │
│   ───────────────                                            │
│                                                              │
│   "Ping 8.8.8.8 toutes les 5 secondes via le lien primaire"  │
│                                                              │
│                                                              │
│   NORMAL :                                                   │
│   ────────                                                   │
│                                                              │
│   [Routeur] ──ping──► [8.8.8.8] ──► "OK" ✓                   │
│       │                                                      │
│       └─► Route primaire ACTIVE                              │
│                                                              │
│                                                              │
│   PANNE :                                                    │
│   ───────                                                    │
│                                                              │
│   [Routeur] ──ping──X [8.8.8.8] ──► "ÉCHEC" ✗                │
│       │                                                      │
│       └─► Track DOWN                                         │
│           └─► Route primaire RETIRÉE                         │
│               └─► Route backup ACTIVÉE                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Types de tests IP SLA

| Test | Ce qu'il vérifie |
|------|------------------|
| **ICMP echo** | Le lien répond-il ? (ping) |
| **TCP connect** | Le service est-il joignable ? |
| **HTTP GET** | Le serveur web répond-il ? |
| **UDP jitter** | La qualité VoIP est-elle bonne ? |

---

## HSRP/VRRP : la gateway qui ne meurt jamais

### C'est quoi HSRP/VRRP ?

Plusieurs routeurs partagent une **IP virtuelle**. Si le routeur actif tombe, un autre prend le relais automatiquement.

```
┌─────────────────────────────────────────────────────────────┐
│                      HSRP / VRRP                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Les PCs ont comme gateway : 192.168.1.1 (IP virtuelle)     │
│                                                              │
│                  ┌─────────────────┐                         │
│                  │  IP Virtuelle   │                         │
│                  │  192.168.1.1    │                         │
│                  └────────┬────────┘                         │
│                           │                                  │
│              ┌────────────┼────────────┐                     │
│              │            │            │                     │
│         ┌────┴────┐  ┌────┴────┐  ┌────┴────┐               │
│         │Router A │  │Router B │  │Router C │               │
│         │ ACTIVE  │  │ STANDBY │  │ STANDBY │               │
│         │.2       │  │.3       │  │.4       │               │
│         └─────────┘  └─────────┘  └─────────┘               │
│                                                              │
│                                                              │
│   NORMAL :                                                   │
│   [PC] ──► 192.168.1.1 ──► Router A (Active) ──► Internet    │
│                                                              │
│   PANNE ROUTER A :                                           │
│   [PC] ──► 192.168.1.1 ──► Router B (nouveau Active) ──► OK  │
│                                                              │
│   Le PC ne voit RIEN, même gateway !                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### HSRP vs VRRP

| | HSRP | VRRP |
|---|------|------|
| **Créateur** | Cisco | Standard ouvert |
| **Support** | Cisco only | Tous vendeurs |
| **Fonctionnement** | Identique | Identique |

---

## PBR : le routage intelligent

### C'est quoi PBR ?

**Policy-Based Routing** = Router le trafic selon des règles personnalisées, pas la table de routage.

```
ROUTAGE NORMAL :
────────────────

Tout le trafic ──► Table de routage ──► Meilleur chemin


PBR :
─────

Trafic VoIP     ──► [Match] ──► ISP-A (faible latence)
Trafic Backup   ──► [Match] ──► ISP-B (haute bande passante)
Reste           ──► Table de routage ──► Normal
```

### Exemple concret

```
┌─────────────────────────────────────────────────────────────┐
│                    PBR PAR DÉPARTEMENT                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│                        INTERNET                              │
│                           │                                  │
│              ┌────────────┼────────────┐                     │
│              │            │            │                     │
│          [ISP-A]          │        [ISP-B]                   │
│          Sécurisé         │        Rapide                    │
│              │            │            │                     │
│              └────────────┼────────────┘                     │
│                           │                                  │
│                    ┌──────┴──────┐                           │
│                    │   ROUTEUR   │                           │
│                    │    + PBR    │                           │
│                    └──────┬──────┘                           │
│                           │                                  │
│           ┌───────────────┼───────────────┐                  │
│           │               │               │                  │
│        [RH]           [Ventes]        [IT]                   │
│           │               │               │                  │
│           ▼               ▼               ▼                  │
│       → ISP-A         → ISP-B        → Normal                │
│      (sécurisé)       (rapide)      (routage)                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Load balancing : utiliser tous les liens

### Per-packet vs per-destination

```
PER-PACKET (chaque paquet sur un lien différent) :
──────────────────────────────────────────────────

Paquet 1 ──► ISP-A ──┐
Paquet 2 ──► ISP-B ──┼──► Destination
Paquet 3 ──► ISP-A ──┤
Paquet 4 ──► ISP-B ──┘

✓ Utilisation maximale
✗ Paquets peuvent arriver désordonnés (mauvais pour VoIP)


PER-DESTINATION (par IP de destination) :
─────────────────────────────────────────

Vers Google    ──► ISP-A ──► Google
Vers Amazon    ──► ISP-B ──► Amazon
Vers Microsoft ──► ISP-A ──► Microsoft

✓ Ordre préservé
✓ Sessions stables
✗ Distribution peut être inégale
```

### Recommandation

| Type de trafic | Méthode |
|----------------|---------|
| VoIP, Vidéo | Per-destination |
| Gros fichiers | Per-packet |
| Navigation web | Per-destination |

---

## Scénario complet de failover

```
┌─────────────────────────────────────────────────────────────┐
│                 SCÉNARIO : PANNE ISP-A                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ÉTAT INITIAL :                                             │
│   ──────────────                                             │
│                                                              │
│   [LAN] ──► Router A (HSRP Active) ──► ISP-A ──► Internet    │
│             Router B (HSRP Standby) ──► ISP-B (backup)       │
│                                                              │
│   IP SLA : ping 8.8.8.8 via ISP-A = OK ✓                     │
│   BFD : session avec ISP-A = UP ✓                            │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   PANNE ISP-A :                                              │
│   ─────────────                                              │
│                                                              │
│   T+0ms    : Lien ISP-A tombe                                │
│   T+50ms   : BFD détecte la panne                            │
│   T+100ms  : BGP retire les routes via ISP-A                 │
│   T+500ms  : IP SLA ping échoue → Track DOWN                 │
│   T+1s     : HSRP bascule (Router B devient Active)          │
│                                                              │
│   [LAN] ──► Router B (HSRP Active) ──► ISP-B ──► Internet    │
│                                                              │
│   Temps total de coupure : ~1 seconde                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Résumé : quand utiliser quoi ?

```
┌────────────────┬─────────────────────────────────────────────┐
│ TECHNOLOGIE    │ UTILISATION                                 │
├────────────────┼─────────────────────────────────────────────┤
│ BFD            │ Détection ultra-rapide (<50ms)              │
│                │ → Avec BGP, OSPF pour accélérer le failover │
├────────────────┼─────────────────────────────────────────────┤
│ IP SLA         │ Monitoring applicatif                       │
│                │ → Vérifier que 8.8.8.8 répond               │
│                │ → Contrôler les routes statiques            │
├────────────────┼─────────────────────────────────────────────┤
│ HSRP/VRRP      │ Redondance de gateway                       │
│                │ → 2 routeurs, 1 IP virtuelle                │
├────────────────┼─────────────────────────────────────────────┤
│ PBR            │ Routage par politique                       │
│                │ → VoIP sur lien A, backup sur lien B        │
├────────────────┼─────────────────────────────────────────────┤
│ ECMP           │ Load balancing                              │
│                │ → Utiliser plusieurs liens en même temps    │
└────────────────┴─────────────────────────────────────────────┘
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **BFD** | Détection de panne en millisecondes |
| **IP SLA** | Tests automatiques (ping, HTTP, etc.) |
| **Track** | Objet qui surveille l'état d'un lien |
| **HSRP** | Redondance gateway (Cisco) |
| **VRRP** | Redondance gateway (standard) |
| **Virtual IP** | IP partagée entre plusieurs routeurs |
| **Active/Standby** | Rôles des routeurs HSRP/VRRP |
| **PBR** | Policy-Based Routing |
| **Route-map** | Règles "si-alors" pour le routage |
| **ECMP** | Load balancing sur chemins égaux |
| **CEF** | Forwarding optimisé Cisco |

---

## Résumé en 30 secondes

```
DÉTECTION DE PANNE :
════════════════════

BFD        = Détection en 50ms (ultra-rapide)
IP SLA     = Ping/test régulier (monitoring)


REDONDANCE GATEWAY :
════════════════════

HSRP/VRRP  = IP virtuelle partagée
             Si Active tombe → Standby prend le relais


ROUTAGE INTELLIGENT :
═════════════════════

PBR        = Trafic VoIP → Lien A
             Trafic Backup → Lien B

ECMP       = Utiliser tous les liens en même temps


COMBINAISON GAGNANTE :
══════════════════════

BFD + BGP + HSRP + IP SLA = Failover en ~1 seconde
```

---

## Schéma récapitulatif

```
BFD - DÉTECTION RAPIDE :
════════════════════════

[Router A] ◄══ Hello ══► [Router B]
                 X
           ← 50ms → DOWN détecté !


IP SLA - MONITORING :
═════════════════════

[Routeur] ──ping──► [8.8.8.8]
     │                  │
     │     OK ✓         │     FAIL ✗
     ▼                  ▼
Route active       Route retirée
                   Backup activée


HSRP/VRRP - GATEWAY REDONDANTE :
════════════════════════════════

         [IP Virtuelle]
              │
    ┌─────────┼─────────┐
    │         │         │
[Active]  [Standby]  [Standby]
    │
Si Active tombe → Standby devient Active


PBR - ROUTAGE INTELLIGENT :
═══════════════════════════

[VoIP]   ──► ISP-A (faible latence)
[Backup] ──► ISP-B (haute bande passante)
[Reste]  ──► Routage normal


ARCHITECTURE COMPLÈTE :
═══════════════════════

                    INTERNET
                       │
           ┌───────────┼───────────┐
           │           │           │
       [ISP-A]         │       [ISP-B]
       BGP+BFD         │       BGP+BFD
           │           │           │
           └───────────┼───────────┘
                       │
              ┌────────┴────────┐
              │    HSRP/VRRP    │
              │   Virtual IP    │
              ├─────────────────┤
              │  Router A │ B   │
              │  (Active) │(Stb)│
              └────────┬────────┘
                       │
                   [LAN]
                       │
         PBR : VoIP → A, Backup → B
```
