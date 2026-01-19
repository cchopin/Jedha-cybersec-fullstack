# Optimisation des performances réseau - version simplifiée

## L'idée en une phrase

L'optimisation réseau, c'est comme gérer la circulation : on donne la priorité aux ambulances (VoIP), on régule le flux (shaping), et on évite les embouteillages (WRED).

---

## QoS : Donner la priorité à ce qui compte

### Le problème sans QoS

```
Sans QoS :
   Backup 5GB ─────┐
   VoIP Call ──────┼───> [Tout mélangé] ───> Sortie
   Email ──────────┘

   Résultat: L'appel VoIP est saccadé !
```

### La solution avec QoS

```
Avec QoS :
   VoIP Call ───────> [PRIORITÉ] ───────────> Sortie (premier)
   Email ───────────> [Normal] ─────────────> Sortie (ensuite)
   Backup ──────────> [Basse priorité] ─────> Sortie (quand possible)
```

### Les types de trafic

| Type | Priorité | Pourquoi |
|------|----------|----------|
| Voix (VoIP) | Très haute | Sensible au délai |
| Vidéo | Haute | Gros débit, temps réel |
| Web/Email | Normale | Peut attendre un peu |
| Backups | Basse | Pas urgent |

---

## DSCP et CoS : Étiqueter le trafic

### DSCP (Couche 3 - IP)

Une valeur dans l'en-tête IP qui dit "je suis prioritaire".

| Valeur | Nom | Usage |
|--------|-----|-------|
| **EF (46)** | Expedited Forwarding | Voix |
| **AF41 (34)** | Assured Forwarding | Vidéo |
| **BE (0)** | Best Effort | Tout le reste |

### CoS (Couche 2 - Ethernet)

Même idée mais dans les trames Ethernet (VLAN).

```
0 = Plus basse priorité
...
5 = Voix
6-7 = Contrôle réseau (plus haute)
```

### Comment ça marche ensemble

```
LAN (CoS)                          WAN (DSCP)
──────────                         ──────────
Frame avec ────> Routeur ────> Paquet avec
CoS = 5          convertit      DSCP = EF
```

---

## Shaping vs Policing

### Policing : Le radar

```
Trafic ──────> [Limite 10 Mbps] ──────> Sortie
                    │
                 Excès ? → DROP !
```

- **Strict** : Ce qui dépasse est supprimé
- Usage : Faire respecter un contrat (SLA)

### Shaping : Le feu de régulation

```
Trafic ──────> [Buffer] ──────> [Régulateur] ──────> Sortie
                  │                   │
              Stockage            10 Mbps
              temporaire          régulier
```

- **Doux** : Ce qui dépasse attend
- Usage : Éviter les pertes

### Quelle différence ?

| Aspect | Policing | Shaping |
|--------|----------|---------|
| Excès | Supprimé | Retardé |
| Pertes | Oui | Non |
| Latence | Non | Oui (file d'attente) |

---

## Gestion de la congestion

### Le problème du buffer

```
Paquets ──────> [Buffer limité] ──────> Sortie

Si trop de paquets arrivent...
Buffer plein → Nouveaux paquets supprimés !
```

### Tail Drop (basique)

```
Buffer: [1|2|3|4|5] PLEIN !

Paquet 6 → DROP
Paquet 7 → DROP
```

Problème : Pas de distinction entre VoIP et backup.

### WRED (intelligent)

```
Buffer se remplit...
  ↓
WRED commence à supprimer des paquets AVANT d'être plein
  ↓
Paquets basse priorité supprimés en premier
  ↓
Paquets haute priorité préservés
```

Avantage : Évite la congestion brutale.

---

## TCP et la congestion

### Comment TCP réagit

```
1. SLOW START (début prudent)
   Envoie peu → augmente vite

2. CONGESTION AVOIDANCE (stable)
   Augmente lentement

3. PERTE DÉTECTÉE
   Réduit → recommence
```

### Le cycle

```
Débit TCP
    │
    │    /\      /\      /\
    │   /  \    /  \    /
    │  /    \  /    \  /
    │ /      \/      \/
    │/
    └────────────────────────> Temps
         Perte  Perte  Perte
```

TCP ralentit quand il détecte des pertes (WRED ou autre).

---

## Optimisation WAN

### Le problème du WAN

```
Site A ────────── 50ms latence ────────── Site B
           Bande passante limitée
```

### Les solutions

| Technique | Ce que ça fait |
|-----------|----------------|
| **Compression** | Réduit la taille (50% de gain possible) |
| **Déduplication** | N'envoie pas deux fois la même chose |
| **Caching** | Garde une copie locale |
| **Accélération TCP** | Optimise pour la haute latence |

### Exemple de déduplication

```
Sans déduplication :
  Fichier 100 MB → 50 sites = 5 GB transférés

Avec déduplication :
  Fichier 100 MB → Site 1 (100 MB)
                 → Sites 2-50 : "Déjà en cache !"
  Total : ~100 MB !
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **QoS** | Prioriser le trafic important |
| **DSCP** | Étiquette de priorité dans l'IP |
| **CoS** | Étiquette de priorité dans Ethernet |
| **Policing** | Limiter en supprimant l'excès |
| **Shaping** | Limiter en retardant l'excès |
| **WRED** | Drop intelligent avant congestion |
| **Tail Drop** | Drop quand buffer plein |
| **Déduplication** | Ne pas envoyer deux fois pareil |
| **Caching** | Garder une copie locale |

---

## Résumé en 30 secondes

```
QoS         = Prioriser (VoIP > Backup)
DSCP/CoS    = Étiqueter le trafic
Policing    = Strict, drop l'excès
Shaping     = Doux, retarde l'excès
WRED        = Drop intelligent avant congestion
WAN Optim.  = Compression + Cache + Dédup
```

---

## Schéma récapitulatif

```
FLUX QoS SIMPLIFIÉ :

    Trafic
       │
       ▼
   Classification ──> "C'est quoi ?"
       │
       ▼
     Marquage ──────> "DSCP = EF"
       │
       ▼
    ┌──┴──┐
    │Queue│ ────────> Prioritaire ou pas ?
    └──┬──┘
       │
       ▼
    Sortie


POLICING VS SHAPING :

    POLICING               SHAPING
    ────────               ───────
       │                      │
       ▼                      ▼
    ┌─────┐               ┌─────┐
    │Radar│               │ Feu │
    └─────┘               └─────┘
       │                      │
    Trop vite?            Trop vite?
       │                      │
      DROP                 Attendre
       │                      │
    Pertes !              Délai


OPTIMISATION WAN :

    Données               WAN              Données
    originales          Optimizer        optimisées
    ──────────          ─────────        ──────────

    ┌────────┐         ┌────────┐        ┌────────┐
    │ 1 GB   │ ──────> │Compress│ ─────> │ 50 MB  │
    │        │         │Déduplic│        │        │
    │        │         │ Cache  │        │        │
    └────────┘         └────────┘        └────────┘

    95% de bande passante économisée !


QUAND UTILISER QUOI :

    Problème                    Solution
    ────────                    ────────
    VoIP saccadé         →      QoS + DSCP EF
    Backup qui sature    →      Shaping
    Congestion fréquente →      WRED
    WAN lent             →      Optimisation WAN
    Trafic non conforme  →      Policing
```
