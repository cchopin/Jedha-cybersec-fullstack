# Zones de Sécurité et Politiques d'Interface - Version Simplifiée

## L'idée en une phrase

Les zones de sécurité regroupent les interfaces du firewall par niveau de confiance, permettant de définir des règles simples entre zones au lieu de règles complexes par interface.

---

## Pourquoi utiliser des zones ?

### Le problème sans zones

```
Sans zones (ACL par interface) :

Interface 1 : 50 règles
Interface 2 : 50 règles
Interface 3 : 50 règles
Interface 4 : 50 règles
...
= 200+ règles à gérer = CAUCHEMAR !
```

### La solution avec zones

```
Avec zones :

Zone INSIDE : contient Interface 1, 2
Zone OUTSIDE : contient Interface 3
Zone DMZ : contient Interface 4

Règles entre zones :
- INSIDE → OUTSIDE : Autoriser web
- OUTSIDE → DMZ : Autoriser HTTP
- DMZ → INSIDE : BLOQUER

= Quelques règles claires !
```

**Analogie** : au lieu de dire "Dupont, Durand, Martin peuvent aller au parking", on dit "Le service RH peut aller au parking".

---

## Les zones classiques

| Zone | Description | Niveau de confiance |
|------|-------------|---------------------|
| **INSIDE (LAN)** | Réseau interne, employés | Haut (100) |
| **OUTSIDE (WAN)** | Internet | Bas (0) |
| **DMZ** | Serveurs publics | Moyen (50) |
| **MGMT** | Administration | Haut (100) |
| **GUEST** | Visiteurs, BYOD | Bas (10) |

```
                    ┌─────────────┐
                    │   INSIDE    │ Confiance HAUTE
                    │  (LAN)      │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │  FIREWALL   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
   │   DMZ   │        │ OUTSIDE │        │  GUEST  │
   │  Moyen  │        │   Bas   │        │   Bas   │
   └─────────┘        └─────────┘        └─────────┘
```

---

## Zone Pairs : définir le sens du trafic

Une **Zone Pair** définit la direction du flux :

```
Zone Pair : INSIDE → OUTSIDE
   = Trafic DU LAN VERS Internet
   = Navigation web des employés

Zone Pair : OUTSIDE → DMZ
   = Trafic D'Internet VERS la DMZ
   = Accès aux serveurs publics

Zone Pair : DMZ → INSIDE
   = Trafic DE la DMZ VERS le LAN
   = DOIT ÊTRE BLOQUÉ !
```

---

## Ordre des règles

Les règles sont traitées de **haut en bas** :

```
1. Block specific bad IP     ← Priorité haute
2. Allow HTTP to web server
3. Allow HTTPS to web server
4. Allow DNS
5. Block all else (deny)     ← Priorité basse

Premier match = action exécutée
Règles suivantes ignorées
```

**Erreur classique :**

```
MAUVAIS :
1. Allow any any     ← Tout passe, règles 2 et 3 jamais utilisées !
2. Block bad IP
3. Block SSH

BON :
1. Block bad IP
2. Block SSH
3. Allow any any     ← En dernier
```

---

## Configuration Cisco ZBFW

### Étapes

```
1. Créer les zones
   zone security INSIDE
   zone security OUTSIDE

2. Assigner les interfaces
   interface Gi0/1
     zone-member security INSIDE

3. Créer les Zone Pairs
   zone-pair security IN-TO-OUT source INSIDE destination OUTSIDE

4. Définir les politiques
   policy-map type inspect IN-OUT-POLICY
     class WEB-TRAFFIC
       inspect

5. Appliquer les politiques
   zone-pair security IN-TO-OUT
     service-policy type inspect IN-OUT-POLICY
```

---

## Configuration pfSense

Dans pfSense, les interfaces sont les "zones" :

```
1. Interfaces > Assignments
   - WAN = em0
   - LAN = em1
   - DMZ = em2 (OPT1)

2. Firewall > Rules > [Interface]
   - Créer les règles pour chaque interface
   - Règles traitées de haut en bas
```

### Exemple de règles LAN

| # | Action | Source | Destination | Port | Description |
|---|--------|--------|-------------|------|-------------|
| 1 | Block | Banned IPs | any | any | Block bad actors |
| 2 | Pass | LAN net | any | 80,443 | Web browsing |
| 3 | Pass | LAN net | DNS servers | 53 | DNS |
| 4 | Block | any | any | any | Default deny |

---

## Matrice des règles inter-zones

| Source | Destination | Autorisé | Pourquoi |
|--------|-------------|----------|----------|
| LAN | Internet | Oui | Navigation |
| LAN | DMZ | Oui (limité) | Accès serveurs |
| LAN | MGMT | Non | Séparation admin |
| DMZ | LAN | **NON** | Protection critique |
| DMZ | Internet | Oui (limité) | Updates |
| Internet | DMZ | Oui (ports spécifiques) | Services publics |
| Internet | LAN | **NON** | Protection |
| MGMT | Tout | Oui | Administration |

---

## Erreurs courantes

| Erreur | Conséquence | Solution |
|--------|-------------|----------|
| Règle "Allow All" | Zéro protection | Être spécifique |
| Mauvais ordre | Règles ignorées | Spécifique avant général |
| DMZ → LAN autorisé | Backdoor | Toujours bloquer |
| Pas de logging | Aucune visibilité | Logger les deny |
| Règles non documentées | Maintenance difficile | Décrire chaque règle |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Zone** | Groupe d'interfaces avec même niveau de confiance |
| **Zone Pair** | Direction du flux (source → destination) |
| **Trust Level** | Niveau de confiance (0-100) |
| **Class Map** | Définit quel trafic identifier (les critères de correspondance) |
| **Policy Map** | Définit les actions à appliquer |
| **Inspect** | Inspection stateful du trafic (avec suivi des connexions) |
| **Pass/Block** | Autoriser/Bloquer |

---

## Résumé en 30 secondes

1. **Zones** = regrouper les interfaces par confiance
2. **Zone Pair** = direction du trafic (source → destination)
3. Règles traitées de **haut en bas**
4. **Premier match** = action exécutée
5. Toujours **deny par défaut** en fin de liste
6. **DMZ → LAN** = toujours bloquer !

---

## Schéma récapitulatif

```
CONCEPT DES ZONES :

   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │   INSIDE    │  │     DMZ     │  │   OUTSIDE   │
   │  (Trust 100)│  │  (Trust 50) │  │  (Trust 0)  │
   │             │  │             │  │             │
   │  ┌───┐┌───┐ │  │   ┌─────┐   │  │   Internet  │
   │  │PC ││PC │ │  │   │ Web │   │  │      ☁      │
   │  └───┘└───┘ │  │   │ Srv │   │  │             │
   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────┴──────┐
                    │  FIREWALL   │
                    │  (Policies) │
                    └─────────────┘


ZONE PAIRS :

    INSIDE ──────→ OUTSIDE    (Navigation)      ✓
    INSIDE ──────→ DMZ        (Accès serveurs)  ✓
    OUTSIDE ─────→ DMZ        (Services publics) ✓
    DMZ ─────────→ INSIDE     (BLOQUÉ !)        ✗


ORDRE DES RÈGLES :

    Règle 1: Block bad IP     ← Évaluée en premier
    Règle 2: Allow HTTP
    Règle 3: Allow HTTPS
    Règle 4: Default Deny     ← Évaluée en dernier

    Paquet arrive
         │
         ▼
    Match Règle 1 ? ──Non──→ Match Règle 2 ? ──Non──→ ...
         │                         │
        Oui                       Oui
         │                         │
         ▼                         ▼
      ACTION                    ACTION
```
