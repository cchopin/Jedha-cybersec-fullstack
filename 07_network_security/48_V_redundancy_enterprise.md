# Redondance en entreprise - version simplifiée

## L'idée en une phrase

La redondance WAN repose sur deux piliers : **MPLS** pour connecter les sites avec des chemins garantis, et **BGP multihoming** pour avoir plusieurs ISPs Internet qui prennent le relais automatiquement.

---

## Pourquoi la redondance ?

```
SANS REDONDANCE :

   Site A ────────────► [ISP] ────────────► Internet
                           │
                           X  Panne !
                           │
                        [PLUS RIEN]


AVEC REDONDANCE :

   Site A ────┬────────► [ISP-A] ──┬──────► Internet
              │              X     │
              │                    │
              └────────► [ISP-B] ──┘
                         (backup)

   ISP-A tombe → Trafic bascule sur ISP-B automatiquement
```

---

## MPLS : le réseau privé du provider

### C'est quoi MPLS ?

MPLS utilise des **labels** (étiquettes) au lieu des adresses IP pour router les paquets. C'est plus rapide et permet de créer des chemins garantis.

```
ROUTAGE IP CLASSIQUE :
──────────────────────

[Paquet] → Routeur → "Hmm, où va 10.1.2.3 ?"
                     → Cherche dans la table...
                     → Trouve le next-hop
                     → Envoie

= Lookup complet à chaque routeur (lent)


ROUTAGE MPLS :
──────────────

[Paquet] → Routeur → "Label 42 ? Facile !"
                     → Regarde juste le label
                     → Envoie vers le bon port

= Lookup ultra-rapide basé sur un simple numéro
```

### Les composants MPLS

```
┌──────────────────────────────────────────────────────────────┐
│                     RÉSEAU MPLS                               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   Le            Provider                          Le         │
│   Site A                                          Site B     │
│                                                               │
│   [CE] ──► [PE] ──► [P] ──► [P] ──► [PE] ──► [CE]            │
│    │        │        │       │       │        │              │
│  Client   Entrée   Core    Core   Sortie   Client            │
│  Edge     MPLS     MPLS    MPLS   MPLS     Edge              │
│                                                               │
│   CE = Customer Edge = le routeur du client                   │
│   PE = Provider Edge = routeur d'ENTRÉE chez le provider      │
│   P  = Provider = routeurs INTERNES du provider (le "coeur")  │
│                                                               │
│   Analogie : La maison du client → Péage → Autoroute → Péage → Destination│
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Pourquoi MPLS pour la redondance ?

```
1. CHEMINS GARANTIS (LSP = Label Switched Path)
   ─────────────────────────────────────────────

   LSP = C'est comme une autoroute réservée dans le réseau MPLS
         Le chemin est décidé à l'avance, pas de surprise !

   Site A ══════► LSP Primaire ══════► Site B
          └─────► LSP Backup ─────────┘

   Exemple concret :
   → LSP Primaire : Paris → Lyon → Marseille (rapide)
   → LSP Backup   : Paris → Bordeaux → Marseille (secours)

   Si le chemin primaire tombe → bascule automatique


2. QoS GARANTIE
   ─────────────

   VoIP    ──► [Priorité Haute] ──► Jamais de coupure
   Backup  ──► [Priorité Basse] ──► Passe quand il y a de la place


3. ISOLATION (VRF)
   ────────────────

   Les données sont isolées des autres clients du provider
   (comme avoir un réseau privé dédié)
```

---

## BGP Multihoming : Plusieurs ISPs

### C'est quoi le Multihoming ?

Se connecter à **plusieurs ISPs** et utiliser **BGP** pour gérer le routage entre eux.

```
┌──────────────────────────────────────────────────────────────┐
│                    BGP MULTIHOMING                            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│                        INTERNET                               │
│                           │                                   │
│              ┌────────────┼────────────┐                      │
│              │            │            │                      │
│              ▼            │            ▼                      │
│          [ISP-A]          │        [ISP-B]                    │
│              │            │            │                      │
│              │   BGP      │    BGP     │                      │
│              │            │            │                      │
│              └────────────┼────────────┘                      │
│                           │                                   │
│                    ┌──────┴──────┐                            │
│                    │  ROUTEUR    │                            │
│                    │   LOCAL     │                            │
│                    │   BGP       │                            │
│                    └─────────────┘                            │
│                                                               │
│   Le routeur annonce les adresses IP aux DEUX ISPs            │
│   → Internet peut joindre le réseau via l'un ou l'autre       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Comment BGP choisit le chemin ?

BGP utilise des **attributs** pour décider quel chemin prendre :

```
LES 3 ATTRIBUTS CLÉS :
──────────────────────

1. LOCAL_PREF (Préférence Locale)
   → "Par où je SORS ?"
   → Plus c'est haut, plus c'est préféré

   ISP-A : LOCAL_PREF = 200  ← PRÉFÉRÉ (je sors par là)
   ISP-B : LOCAL_PREF = 100  ← Backup


2. AS_PATH (Chemin d'AS)
   → "Combien de réseaux je traverse ?"
   → Moins c'est long, mieux c'est

   Route A : AS 100 → AS 200 → Destination  (2 sauts) ← PRÉFÉRÉ
   Route B : AS 100 → AS 300 → AS 400 → Destination  (3 sauts)


3. MED (Multi-Exit Discriminator)
   → "Par où les autres ENTRENT chez moi ?"
   → Suggère le chemin préféré aux voisins
```

### Exemple : ISP-A Primaire, ISP-B Backup

```
CONFIGURATION :
───────────────

Pour le trafic SORTANT (du réseau local vers Internet) :

   route-map PREFER-ISP-A
     set local-preference 200     ← Haute priorité

   route-map PREFER-ISP-B
     set local-preference 100     ← Basse priorité

RÉSULTAT :
──────────

   Normal:     Trafic ──► ISP-A ──► Internet
   ISP-A down: Trafic ──► ISP-B ──► Internet (auto)
```

---

## Filtrage de Routes : Ne Pas Tout Accepter

```
POURQUOI FILTRER ?
──────────────────

Sans filtre, un ISP pourrait envoyer :
• Des routes vers des IP privées (10.x.x.x) → DANGER
• Des millions de routes inutiles → Surcharge
• Des routes vers le propre réseau de l'entreprise → Boucle !


QUOI FILTRER :
──────────────

ENTRANT (ce qu'on accepte) :
✗ Bloquer les IP privées (RFC1918)
  → RFC1918 = les plages d'adresses privées :
    • 10.0.0.0 à 10.255.255.255
    • 172.16.0.0 à 172.31.255.255
    • 192.168.0.0 à 192.168.255.255
  → Ces adresses ne doivent JAMAIS être routées sur Internet !
✗ Bloquer les préfixes trop petits (/25 et plus)
✓ Accepter les routes légitimes

SORTANT (ce qu'on annonce) :
✓ Uniquement les préfixes IP de l'entreprise
✗ Jamais les réseaux internes
✗ Jamais les préfixes des autres
```

---

## Load Sharing : Utiliser les Deux ISPs

```
OPTION 1 : Split Géographique
─────────────────────────────

   Trafic vers USA    ──► ISP-A (bon peering US)
   Trafic vers Europe ──► ISP-B (bon peering EU)


OPTION 2 : 50/50
────────────────

                    ┌──► ISP-A ──┐
   Tout le trafic ──┤            ├──► Internet
                    └──► ISP-B ──┘

   = Répartition automatique


OPTION 3 : Proportionnel
────────────────────────

   ISP-A (100 Mbps) : 70% du trafic
   ISP-B (50 Mbps)  : 30% du trafic
```

---

## Failover : Quand Ça Casse

### Déclencheurs de Basculement

```
QU'EST-CE QUI DÉCLENCHE UN FAILOVER ?
─────────────────────────────────────

1. Lien physique down
   [Interface] ──X──  → Détecté immédiatement

2. Session BGP perdue
   [Peer] ne répond plus → Détecté en ~90 secondes (par défaut)

3. IP SLA tracking
   Ping 8.8.8.8 échoue → Détecté en quelques secondes
```

### Scénario complet de failover

```
┌──────────────────────────────────────────────────────────────┐
│                   FAILOVER EN ACTION                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   ÉTAT NORMAL :                                               │
│   ─────────────                                               │
│                                                               │
│   [LAN] ──► Router 1 ──► ISP-A ──► Internet                   │
│             (Active)                                          │
│             Router 2 ──► ISP-B                                │
│             (Standby)                                         │
│                                                               │
│   IP SLA ping 8.8.8.8 via ISP-A : OK ✓                        │
│                                                               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   PANNE ISP-A :                                               │
│   ─────────────                                               │
│                                                               │
│   1. IP SLA ping 8.8.8.8 : ÉCHEC ✗                            │
│   2. Track passe à DOWN                                       │
│   3. HSRP bascule : Router 2 devient Active                   │
│   4. Trafic redirigé automatiquement                          │
│                                                               │
│   [LAN] ──► Router 2 ──► ISP-B ──► Internet                   │
│             (Active)                                          │
│                                                               │
│   Temps de basculement : quelques secondes                    │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## MPLS vs BGP : Quand Utiliser Quoi ?

```
┌─────────────────────┬─────────────────────┬─────────────────────┐
│                     │       MPLS          │   BGP MULTIHOMING   │
├─────────────────────┼─────────────────────┼─────────────────────┤
│ C'est pour quoi ?   │ Connecter les sites │ Accès Internet      │
│ Qui gère ?          │ Le provider         │ L'entreprise        │
│ QoS garantie ?      │ Oui (SLA)           │ Non (best effort)   │
│ Coût                │ Plus cher           │ Variable            │
│ Contrôle            │ Limité              │ Total               │
└─────────────────────┴─────────────────────┴─────────────────────┘


UTILISATION TYPIQUE :
─────────────────────

   Sites ══════► MPLS ══════► Datacenter ════► BGP ════► Internet
   distants      (WAN privé)                   (multihoming)
```

---

## Les Termes à Retenir

| Terme | Définition simple |
|-------|-------------------|
| **MPLS** | Routage par labels (étiquettes) au lieu d'adresses IP - plus rapide |
| **LSP** | Label Switched Path = autoroute réservée dans le réseau MPLS |
| **CE** | Customer Edge = routeur du client |
| **PE** | Provider Edge = routeur d'entrée chez le fournisseur |
| **P** | Provider = routeurs au coeur du réseau MPLS |
| **VRF** | Isolation virtuelle - les données séparées des autres clients |
| **RFC1918** | Standard définissant les IP privées (10.x, 172.16.x, 192.168.x) |
| **BGP** | Border Gateway Protocol = le protocole de routage d'Internet |
| **Multihoming** | Se connecter à plusieurs ISPs pour la redondance |
| **AS** | Système Autonome = un réseau géré par une seule organisation |
| **LOCAL_PREF** | Préférence locale = par où JE SORS vers Internet |
| **AS_PATH** | Liste des réseaux traversés (plus court = meilleur) |
| **MED** | Suggestion aux voisins : "entrez chez moi par ici" |
| **IP SLA** | Test automatique (ping) pour vérifier si un lien fonctionne |

---

## Résumé en 30 secondes

```
MPLS = Réseau privé via le provider
───────────────────────────────────────
• Labels au lieu d'adresses IP
• Chemins garantis (LSP)
• QoS et SLA
• Idéal pour : Site-à-site


BGP MULTIHOMING = Plusieurs ISPs Internet
─────────────────────────────────────────
• Annonce des IP aux deux ISPs
• BGP choisit le meilleur chemin
• Si un ISP tombe → l'autre prend le relais
• Idéal pour : Redondance Internet


ENSEMBLE = La combo gagnante
────────────────────────────
• MPLS pour le WAN interne
• BGP pour l'accès Internet
• Redondance à tous les niveaux
```

---

## Schéma récapitulatif

```
MPLS - LE RÉSEAU PRIVÉ :
════════════════════════

   Site A                                          Site B
   [CE] ──► [PE] ═══► [P] ═══► [P] ═══► [PE] ──► [CE]
              │                           │
              └─── Chemin garanti (LSP) ──┘
                   QoS, SLA, isolation


BGP MULTIHOMING - PLUSIEURS ISPS :
══════════════════════════════════

              INTERNET
                 │
        ┌────────┼────────┐
        │        │        │
    [ISP-A]      │    [ISP-B]
        │        │        │
        └────────┼────────┘
                 │
            [Routeur BGP]
                 │
         Annonce: 203.0.113.0/24

   ISP-A down → Trafic bascule sur ISP-B


FAILOVER AUTOMATIQUE :
══════════════════════

   Normal:
   [LAN] → Router 1 (Active) → ISP-A → Internet
           Router 2 (Standby)

   Panne ISP-A:
   1. IP SLA détecte l'échec
   2. HSRP bascule
   3. Router 2 devient Active

   [LAN] → Router 2 (Active) → ISP-B → Internet


ARCHITECTURE COMPLÈTE :
═══════════════════════

   Sites distants          Datacenter           Internet
   ┌────────┐
   │ Site 1 │═══╗
   └────────┘   ║
                ║  MPLS    ┌──────────┐  BGP   ┌────────┐
   ┌────────┐   ╠═════════►│          │═══════►│ ISP-A  │
   │ Site 2 │═══╣          │Datacenter│        └────────┘
   └────────┘   ║          │          │  BGP   ┌────────┐
                ║          │          │═══════►│ ISP-B  │
   ┌────────┐   ║          └──────────┘        └────────┘
   │ Site 3 │═══╝
   └────────┘

   MPLS = Redondance WAN (sites → datacenter)
   BGP  = Redondance Internet (datacenter → Internet)
```
