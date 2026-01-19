# SD-WAN basics - version simplifiée

## L'idée en une phrase

Le **SD-WAN**, c'est comme avoir un chef d'orchestre intelligent pour le réseau : il utilise n'importe quel lien disponible (MPLS, Internet, 4G), choisit automatiquement le meilleur chemin pour chaque application, et se gère depuis un seul écran.

---

## Avant/Après : Le Problème que SD-WAN Résout

```
AVANT (WAN Traditionnel) :
══════════════════════════

                    INTERNET
                        │
                   [Firewall]
                        │
                 SIÈGE SOCIAL
                        │
            ════════════╪════════════  MPLS (cher!)
            │           │           │
        [Branch 1] [Branch 2] [Branch 3]


Problèmes :
• Tout passe par le siège (même pour aller sur Office 365)
• MPLS coûte une fortune
• Déployer un nouveau site = des semaines
• Un lien tombe = plus rien


APRÈS (SD-WAN) :
════════════════

                 ┌──────────────┐
                 │  CONTRÔLEUR  │ ← Gestion centralisée
                 │   SD-WAN     │
                 └──────┬───────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
    [Branch 1]    [Branch 2]    [Branch 3]
         │              │              │
    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
    │         │    │         │    │         │
   MPLS   Internet MPLS   Internet  LTE   Internet
         │              │              │
         └──────────────┴──────────────┘
                   │    │
              [Cloud] [Siège]


Avantages :
• Accès direct au cloud (pas de détour par le siège)
• Utilise MPLS + Internet + 4G (moins cher)
• Nouveau site en heures, pas en semaines
• Un lien tombe = bascule automatique sur l'autre
```

---

## Les 3 Composants Clés

```
┌─────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE SD-WAN                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. CONTRÔLEUR (le cerveau)                                 │
│      ────────────────────────                                │
│      • vManage, FortiManager, etc.                           │
│      • Gère TOUTES les branches depuis un écran              │
│      • Pousse les configs et politiques                      │
│                                                              │
│   2. CPE (les bras)                                          │
│      ─────────────────                                       │
│      • Boîtier SD-WAN dans chaque site                       │
│      • Exécute les politiques du contrôleur                  │
│      • Fait le routage intelligent                           │
│                                                              │
│   3. OVERLAY (le réseau virtuel)                             │
│      ──────────────────────────                              │
│      • Tunnels chiffrés entre tous les sites                 │
│      • Fonctionne sur n'importe quel transport               │
│      • MPLS, Internet, 4G... tout marche                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## La magie : routage applicatif

### Comment ça marche ?

Le SD-WAN **reconnaît les applications** et les envoie sur le meilleur lien :

```
┌─────────────────────────────────────────────────────────────┐
│                   ROUTAGE PAR APPLICATION                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   APPLICATION          DÉCISION              LIEN            │
│   ───────────          ────────              ────            │
│                                                              │
│   Zoom/Teams    ──►    "Besoin faible      ──►  MPLS         │
│                        latence"                 (fiable)     │
│                                                              │
│   Office 365    ──►    "C'est du cloud"    ──►  Internet     │
│                                                 (direct)     │
│                                                              │
│   Backup        ──►    "Pas urgent"        ──►  LTE          │
│                                                 (économique) │
│                                                              │
│   SAP           ──►    "Critique interne"  ──►  MPLS         │
│                                                 (garanti)    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Détection et Adaptation

```
NORMAL :
────────

[Branch] ══► MPLS (latence 20ms) ══► VoIP OK ✓
         ──► Internet (latence 50ms)


PROBLÈME SUR MPLS :
───────────────────

[Branch] ══► MPLS (latence 200ms, perte 5%) ══► DÉGRADÉ !
         ──► Internet (latence 50ms) ◄── MEILLEUR

         → SD-WAN bascule automatiquement la VoIP sur Internet
         → En moins d'une seconde
         → L'utilisateur ne voit rien
```

---

## Local breakout : fini le détour !

### Le problème du backhaul

```
AVANT :
───────

[Branch Paris] ──► MPLS ──► [Siège Lyon] ──► Internet ──► Office 365
                                  │
                            1000 km de détour !
                            Latence: 150ms


AVEC SD-WAN (Local Breakout) :
──────────────────────────────

[Branch Paris] ──► Internet ──► Office 365
                       │
                 Accès direct !
                 Latence: 20ms
```

### Ce qui va où

| Destination | Chemin | Pourquoi |
|-------------|--------|----------|
| Office 365, Google | Internet direct | Cloud = proche |
| SAP, ERP interne | MPLS vers siège | Données internes |
| Backup | Lien le moins cher | Pas critique |

---

## Sécurité intégrée

### Tout est chiffré

```
TOUS les tunnels SD-WAN sont chiffrés (IPsec AES-256)

IPsec = Internet Protocol Security
      = Protocole qui chiffre les données entre deux points
      = Comme une enveloppe scellée que seul le destinataire peut ouvrir

AES-256 = Le type de chiffrement utilisé
        = Quasi-impossible à casser (standard militaire)

[Branch A] ═══════════════════════════════ [Branch B]
              │                       │
              └── Tunnel IPsec ───────┘
                  (chiffré de bout en bout)

Même sur Internet public = sécurisé
(les hackers voient passer des données, mais ne peuvent pas les lire)
```

### Sécurité à l'Edge

```
┌─────────────────────────────────────────────────────────────┐
│              SÉCURITÉ DANS LE CPE SD-WAN                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   • Firewall intégré (filtrage par zone)                     │
│   • Filtrage URL (bloquer les sites malveillants)            │
│   • IDS/IPS (détection d'intrusions)                         │
│   • Antimalware (certains modèles)                           │
│                                                              │
│   = Pas besoin de tout renvoyer au siège pour filtrer        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## SD-WAN vs MPLS : Comparaison

```
RAPPEL : MPLS c'est quoi ?
──────────────────────────
MPLS = MultiProtocol Label Switching
     = Réseau privé fourni par un opérateur télécom
     = Connexion dédiée entre les sites (pas via Internet public)
     = Fiable mais CHER !

┌────────────────────┬─────────────────────┬─────────────────────┐
│                    │       MPLS          │      SD-WAN         │
├────────────────────┼─────────────────────┼─────────────────────┤
│ Nouveau site       │ 4-8 semaines        │ Quelques heures     │
│ Coût               │ Élevé               │ 50-70% moins cher   │
│ Accès cloud        │ Via le siège        │ Direct (local)      │
│ Failover           │ Minutes             │ Sous-seconde        │
│ Gestion            │ Manuelle par site   │ Centralisée         │
│ Sécurité           │ Optionnelle         │ Intégrée            │
│ Multi-transport    │ Non                 │ Oui (MPLS+Net+4G)   │
└────────────────────┴─────────────────────┴─────────────────────┘
```

---

## SASE : SD-WAN + Sécurité Cloud

### C'est Quoi SASE ?

**SASE** = SD-WAN + toute la sécurité dans le cloud

```
┌─────────────────────────────────────────────────────────────┐
│                         SASE                                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   SD-WAN          +        SÉCURITÉ CLOUD                    │
│   ──────                   ───────────────                   │
│   • Connectivité           • Firewall cloud                  │
│   • Routage intelligent    • CASB (sécurité SaaS)            │
│   • Multi-transport        • ZTNA (Zero Trust)               │
│                            • Filtrage web                    │
│                                                              │
│                    = TOUT-EN-UN                              │
│                                                              │
│   Vendeurs : Zscaler, Palo Alto, Cisco, Fortinet             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Cas d'Usage Concrets

### 1. Nouvelles Branches (Zero-Touch)

```
AVANT :
Envoyer un technicien → Configurer le routeur → 2 semaines

AVEC SD-WAN :
1. Commander le CPE
2. Le brancher
3. Il se configure tout seul depuis le cloud
→ Quelques heures
```

### 2. Retail / Magasins

```
100 magasins avec :
• Pas d'IT sur place
• Besoin d'Internet pour les caisses
• Besoin de sécurité

SD-WAN :
• CPE avec 4G + Internet
• Gestion centralisée (1 admin pour 100 sites)
• Sécurité intégrée
• Failover automatique
```

### 3. Chantiers / Événements Temporaires

```
Besoin : Réseau pour un chantier de 6 mois

AVANT : Tirer de la fibre (impossible)

SD-WAN : CPE avec 4G/5G
         → Déployé en 1 heure
         → Récupéré à la fin
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **SD-WAN** | Software-Defined WAN = réseau étendu géré intelligemment par logiciel |
| **CPE** | Customer Premises Equipment = boîtier SD-WAN installé dans chaque site |
| **Overlay** | Réseau virtuel (tunnels chiffrés) construit au-dessus du réseau physique |
| **Underlay** | Réseau physique sous-jacent (MPLS, Internet, 4G) |
| **Local Breakout** | Accès direct à Internet depuis la branche (sans passer par le siège) |
| **DPI** | Deep Packet Inspection = analyse le contenu pour identifier l'application |
| **Zero-Touch** | Le boîtier se configure tout seul à la première connexion |
| **SASE** | Secure Access Service Edge = SD-WAN + sécurité dans le cloud |
| **ZTNA** | Zero Trust = "ne jamais faire confiance, toujours vérifier" |
| **IPsec** | Protocole de chiffrement des tunnels (enveloppe scellée pour les données) |
| **MPLS** | Réseau privé chez un opérateur (cher mais fiable) |

---

## Résumé en 30 Secondes

```
SD-WAN = WAN intelligent géré depuis le cloud

AVANT :
• MPLS uniquement (cher)
• Tout passe par le siège
• Config manuelle de chaque site
• Failover lent

APRÈS (SD-WAN) :
• MPLS + Internet + 4G (économique)
• Accès direct au cloud (local breakout)
• Gestion centralisée
• Failover en sous-seconde

BONUS :
• Sécurité intégrée
• Déploiement en heures
• Routage par application
```

---

## Schéma récapitulatif

```
ARCHITECTURE SD-WAN :
═════════════════════

         ┌──────────────┐
         │  CONTRÔLEUR  │ ← 1 écran pour tout gérer
         │   (cloud)    │
         └──────┬───────┘
                │
    ┌───────────┼───────────┐
    │           │           │
[Branch A]  [Branch B]  [Branch C]
    │           │           │
┌───┴───┐   ┌───┴───┐   ┌───┴───┐
│  CPE  │   │  CPE  │   │  CPE  │
└───┬───┘   └───┬───┘   └───┬───┘
    │           │           │
 MPLS+Net    MPLS+Net    4G+Net
    │           │           │
    └───────────┴───────────┘
            │
    ════════╪════════  OVERLAY (tunnels chiffrés)
            │
    ┌───────┴───────┐
    │               │
 [Cloud]         [Siège]


ROUTAGE APPLICATIF :
════════════════════

[Zoom]       ──► "Faible latence"   ──► MPLS
[Office 365] ──► "C'est du cloud"   ──► Internet (direct)
[Backup]     ──► "Pas urgent"       ──► Lien le moins cher


FAILOVER AUTOMATIQUE :
══════════════════════

Normal:
[Branch] ══► MPLS ══► OK

Panne MPLS:
[Branch] ══► MPLS ══X
         ──► Internet ──► OK (bascule auto)

Temps de bascule: < 1 seconde


TRANSITION MPLS → SD-WAN :
══════════════════════════

Phase 1: MPLS + Internet (hybride)
Phase 2: Local breakout pour le cloud
Phase 3: Réduction MPLS
Phase 4: 100% Internet (optionnel)

= Économies progressives sans risque
```
