# NAC (network access control) - version simplifiée

## L'idée en une phrase

Le **NAC** est le videur du réseau : il vérifie l'identité des utilisateurs (authentification), si l'équipement est "propre" (posture), et décide où chacun peut aller (VLAN/ACL).

---

## Le problème : qui se connecte ?

```
SANS NAC :
══════════

[Laptop corporate]  ──┐
[Téléphone perso]   ──┤
[Laptop infecté]    ──┼──► [Switch] ──► RÉSEAU ──► Tout accessible !
[Caméra IoT]        ──┤
[Attaquant ???]     ──┘

= Aucun contrôle, aucune visibilité


AVEC NAC :
══════════

[Laptop corporate]  ──┐                    ┌──► VLAN Corporate
[Téléphone perso]   ──┤                    │
[Laptop infecté]    ──┼──► [NAC] vérifie ──┼──► VLAN Quarantine
[Caméra IoT]        ──┤                    │
[Attaquant ???]     ──┘                    └──► REFUSÉ

= Contrôle à l'entrée, segmentation automatique
```

---

## Les 4 Étapes du NAC

```
┌─────────────────────────────────────────────────────────────┐
│                  LES 4 ÉTAPES NAC                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. IDENTIFICATION                                          │
│   ═════════════════                                          │
│   "Qui est-ce ?" → Adresse MAC, certificat, username         │
│                                                              │
│   2. AUTHENTIFICATION                                        │
│   ════════════════════                                       │
│   "Preuve d'identité" → 802.1X, login/password, certificat   │
│                                                              │
│   3. POSTURE                                                 │
│   ═════════════                                              │
│   "L'équipement est-il sain ?"                               │
│   → Antivirus à jour ? OS patché ? Firewall activé ?         │
│                                                              │
│   4. AUTORISATION                                            │
│   ════════════════                                           │
│   "Voici les accès autorisés"                                │
│   → VLAN assigné, ACL appliqué, ou refusé                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Méthodes d'authentification

```
┌─────────────────────────────────────────────────────────────┐
│              MÉTHODES D'AUTHENTIFICATION                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   802.1X (le standard)                                       │
│   ════════════════════                                       │
│                                                              │
│   802.1X = Protocole standard IEEE pour l'authentification   │
│            sur les ports réseau. Avant de laisser passer     │
│            le trafic, le switch vérifie l'identité.          │
│                                                              │
│   [Laptop] ──► [Switch] ──► [NAC/RADIUS] ──► [Active Dir]    │
│                                                              │
│   • Authentification par username/password ou certificat     │
│   • Le plus sécurisé                                         │
│   • Pour : laptops, postes de travail                        │
│                                                              │
│   MAB (MAC Authentication Bypass)                            │
│   ═══════════════════════════════                            │
│                                                              │
│   MAC = Media Access Control = adresse physique unique       │
│         de chaque carte réseau (ex: AA:BB:CC:DD:EE:FF)       │
│         C'est comme le "numéro de série" de la carte réseau  │
│                                                              │
│   [Imprimante] ──► [Switch] ──► [NAC] vérifie l'adresse MAC  │
│                                                              │
│   • Authentification par adresse MAC (moins sécurisé)        │
│   • Pour équipements qui ne supportent pas 802.1X            │
│   • Pour : imprimantes, téléphones IP, caméras, IoT          │
│                                                              │
│   Web Auth (portail captif)                                  │
│   ═════════════════════════                                  │
│   [Invité] ──► WiFi ──► Redirigé vers page login             │
│                                                              │
│   • L'utilisateur entre ses credentials manuellement         │
│   • Pour : invités, BYOD                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## La posture : l'équipement est-il sain ?

### Ce que le NAC vérifie

| Critère | Question | Explication |
|---------|----------|-------------|
| **Antivirus** | Installé et à jour ? | Protection contre les virus |
| **Patches OS** | Windows/macOS à jour ? | Corrections de sécurité installées |
| **Firewall** | Activé et conforme ? | Pare-feu du PC actif |
| **Chiffrement** | BitLocker/FileVault présent ? | BitLocker (Windows) et FileVault (Mac) = chiffrement du disque dur. Si le PC est volé, les données sont illisibles |
| **Logiciels interdits** | Pas de P2P, crack, etc. ? | Pas de logiciels dangereux |

### Les 3 résultats possibles

```
CONFORME ✓
══════════
Tout est OK → VLAN Corporate (accès complet)


NON-CONFORME ✗
══════════════
Antivirus obsolète → VLAN Quarantine
                     (accès aux serveurs de mise à jour seulement)


INCONNU ?
═════════
Pas d'agent NAC → VLAN Guest (Internet seulement)
```

---

## L'enforcement : accès accordé

### Assignation dynamique de VLAN

```
┌─────────────────────────────────────────────────────────────┐
│              VLAN DYNAMIQUE PAR IDENTITÉ                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   MÊME PORT PHYSIQUE, VLAN DIFFÉRENT :                       │
│                                                              │
│   [Employé RH]      ──► 802.1X ──► NAC ──► VLAN 20 (RH)      │
│   [Employé IT]      ──► 802.1X ──► NAC ──► VLAN 30 (IT)      │
│   [Invité]          ──► Web Auth ──► NAC ──► VLAN 100 (Guest)│
│   [Imprimante]      ──► MAB ──► NAC ──► VLAN 50 (IoT)        │
│   [Laptop infecté]  ──► Posture fail ──► VLAN 999 (Quarantine)│
│                                                              │
│   = Segmentation automatique basée sur l'identité !          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### La quarantaine

```
ÉQUIPEMENT NON-CONFORME :
═════════════════════════

[Laptop] ──► Posture check ──► ÉCHEC (antivirus obsolète)
     │
     ▼
QUARANTINE VLAN
     │
     ├──► Accès autorisé :
     │    • Serveur de patches
     │    • Serveur antivirus
     │    • Portail "Comment réparer"
     │
     └──► Accès bloqué :
          • Serveurs internes
          • Internet
          • Autres VLANs

     │
     ▼
APRÈS MISE À JOUR :
[Laptop] ──► Re-check ──► CONFORME ──► VLAN Corporate
```

---

## Les outils NAC

### Cisco ISE

```
CISCO ISE (Identity Services Engine)
════════════════════════════════════

• Leader du marché
• S'intègre parfaitement avec équipements Cisco
• 802.1X, MAB, posture via AnyConnect
• Portails guest et BYOD
• TrustSec pour segmentation avancée

Pour : Environnements majoritairement Cisco
```

### Aruba ClearPass

```
ARUBA CLEARPASS
═══════════════

• Vendor-agnostic (fonctionne avec tout)
• Très flexible
• Device Insight (fingerprinting)
  → Fingerprinting = identifier automatiquement le type d'appareil
    (iPhone, imprimante HP, caméra Axis...) par son "empreinte"
    réseau, sans rien installer dessus
• Bon pour environnements multi-vendeurs

Pour : Environnements hétérogènes
```

### Autres Options

| Outil | Point fort |
|-------|------------|
| **FortiNAC** | Détection IoT |
| **Portnox** | Cloud-native, simple |
| **Forescout** | OT/industriel |

---

## Déploiement : les phases

```
PHASE 1 : MONITOR (2-4 semaines)
════════════════════════════════
• NAC observe, ne bloque rien
• Identifier tous les équipements
• Comprendre les patterns de connexion

PHASE 2 : LOW-RISK (2-4 semaines)
═════════════════════════════════
• Enforcement sur invités seulement
• Test avec groupe pilote
• Ajuster les politiques

PHASE 3 : ROLLOUT (1-3 mois)
════════════════════════════
• Département par département
• Exceptions documentées
• Support utilisateur

PHASE 4 : FULL (ongoing)
════════════════════════
• Tout le réseau protégé
• Monitoring continu
• Amélioration continue
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **NAC** | Network Access Control = le videur du réseau |
| **802.1X** | Protocole standard : le switch vérifie l'identité avant de laisser passer |
| **MAC** | Adresse physique unique de chaque carte réseau (comme un numéro de série) |
| **MAB** | Authentification par adresse MAC (pour équipements simples) |
| **Posture** | "Le PC est-il sain ?" - antivirus, patches, firewall... |
| **Compliant** | Conforme = tout est OK, accès autorisé |
| **Quarantine** | VLAN d'isolation = l'appareil reste isolé jusqu'à mise à jour |
| **Remediation** | Processus pour devenir conforme (installer les mises à jour) |
| **RADIUS** | Serveur central qui vérifie les identités |
| **Fingerprinting** | Identifier un appareil par son "empreinte" réseau |
| **ISE** | Cisco Identity Services Engine = solution NAC de Cisco |
| **ClearPass** | Solution NAC de Aruba/HPE |

---

## Résumé en 30 secondes

```
NAC = Le videur du réseau
══════════════════════════

IDENTIFICATION :
→ 802.1X, MAB, ou Web Auth

L'ÉQUIPEMENT EST-IL SAIN ?
→ Antivirus ? Patches ? Firewall ?

QUELS ACCÈS SONT ACCORDÉS ?
→ VLAN Corporate, Guest, ou Quarantine

OUTILS :
• Cisco ISE (environnement Cisco)
• Aruba ClearPass (multi-vendeur)
• FortiNAC, Forescout, Portnox...

DÉPLOIEMENT :
1. Monitor (observer)
2. Low-risk (tester)
3. Rollout (déployer)
4. Full enforcement (tout protéger)
```

---

## Schéma récapitulatif

```
FLUX NAC :
══════════

[Utilisateur] ──► Connexion au réseau
                      │
                      ▼
               ┌─────────────┐
               │   SWITCH    │
               │    ou AP    │
               └──────┬──────┘
                      │
                      ▼
               ┌─────────────┐
               │    NAC      │
               │   SERVER    │
               └──────┬──────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
    IDENTIFICATION  POSTURE    POLITIQUE
    (qui est-ce ?) (sain ?)   (que faire ?)
         │            │            │
         └────────────┼────────────┘
                      │
                      ▼
               ┌─────────────┐
               │  DÉCISION   │
               └──────┬──────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
     VLAN 10      VLAN 100     VLAN 999
    Corporate      Guest      Quarantine


POSTURE CHECK :
═══════════════

[Agent NAC sur le PC]
         │
         ├──► Antivirus OK ?      ✓/✗
         ├──► OS patché ?         ✓/✗
         ├──► Firewall activé ?   ✓/✗
         └──► Chiffrement OK ?    ✓/✗
                   │
         ┌────────┴────────┐
         │                 │
    Tout OK ✓         Problème ✗
         │                 │
         ▼                 ▼
   VLAN Corporate    VLAN Quarantine
                           │
                           ▼
                    Remediation
                    (mise à jour)
                           │
                           ▼
                    Re-check ──► OK ──► VLAN Corporate
```
