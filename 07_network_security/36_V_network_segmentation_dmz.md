# Segmentation réseau et DMZ - version simplifiée

## L'idée en une phrase

La segmentation réseau divise le réseau en zones isolées pour limiter les dégâts si un attaquant s'infiltre, et la DMZ est une zone spéciale pour les serveurs exposés à Internet.

---

## Pourquoi segmenter le réseau ?

### Le problème sans segmentation

```
Réseau à plat (pas de segmentation) :

    ┌─────────────────────────────────────────────┐
    │                 TOUT EST CONNECTÉ           │
    │                                             │
    │  PC ── PC ── PC ── Serveur ── DB ── Web    │
    │                                             │
    └─────────────────────────────────────────────┘

Si un PC est compromis → l'attaquant accède à TOUT !
```

### La solution : segmentation

```
Réseau segmenté :

    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │   LAN    │    │   DMZ    │    │  Serveurs │
    │ Employés │    │   Web    │    │   DB     │
    │ PC, PC   │    │ Serveur  │    │ Critiques│
    └────┬─────┘    └────┬─────┘    └────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
                    FIREWALL
                    (contrôle les accès)

Si un PC est compromis → l'attaquant est bloqué dans sa zone
```

**Analogie** : les compartiments étanches d'un sous-marin. Si un compartiment est inondé, les autres restent secs.

---

## La DMZ : la zone tampon

### Qu'est-ce qu'une DMZ ?

La **DMZ** (Demilitarized Zone) est une zone entre Internet et le réseau interne. Elle contient les serveurs qui doivent être accessibles depuis Internet (web, mail, DNS).

```
                    Internet
                        │
                        │ (Zone très hostile)
                        ▼
                   ┌─────────┐
                   │FIREWALL │
                   │ (Front) │
                   └────┬────┘
                        │
                  ┌─────┴─────┐
                  │    DMZ    │ ← Zone semi-protégée
                  │ Web, Mail │
                  └─────┬─────┘
                        │
                   ┌────┴────┐
                   │FIREWALL │
                   │ (Back)  │
                   └────┬────┘
                        │
                  ┌─────┴─────┐
                  │   LAN     │ ← Zone protégée
                  │ Données   │
                  └───────────┘
```

### Pourquoi mettre les serveurs web en DMZ ?

| Situation | Conséquence |
|-----------|-------------|
| **Serveur web sur LAN** | Si hacké → accès direct aux données |
| **Serveur web en DMZ** | Si hacké → toujours un firewall à franchir |

---

## Architecture classique à 3 zones

```
                         Internet
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │                OUTSIDE                  │
        │           (Zone hostile)                │
        │         Niveau de confiance: 0          │
        └────────────────┬───────────────────────┘
                         │
                    ┌────┴────┐
                    │FIREWALL │
                    └────┬────┘
                         │
        ┌────────────────┼────────────────────┐
        │                │                    │
   ┌────┴────┐      ┌────┴────┐         ┌────┴────┐
   │  INSIDE │      │   DMZ   │         │  MGMT   │
   │  (LAN)  │      │(Serveurs│         │ (Admin) │
   │         │      │publics) │         │         │
   │Trust: 100│     │Trust: 50│         │Trust: 100│
   └─────────┘      └─────────┘         └─────────┘

Trust = Niveau de confiance (plus élevé = plus sûr)
```

---

## Règles de base inter-zones

| Source | Destination | Autorisé ? | Raison |
|--------|-------------|------------|--------|
| LAN | Internet | Oui | Navigation web |
| LAN | DMZ | Oui (limité) | Accès aux serveurs |
| DMZ | LAN | **NON** | Protection critique |
| DMZ | Internet | Oui (limité) | Updates, DNS |
| Internet | DMZ | Oui (ports spécifiques) | Services publics |
| Internet | LAN | **NON** | Protection |

**Règle d'or** : La DMZ ne doit JAMAIS pouvoir initier de connexion vers le LAN.

---

## Techniques de segmentation

### 1. VLANs

Séparation logique au niveau du switch :

```
Switch
  │
  ├── VLAN 10 : RH
  ├── VLAN 20 : Finance
  ├── VLAN 30 : IT
  └── VLAN 40 : Guest

Chaque VLAN est isolé des autres
```

### 2. Subnets

Séparation par adresses IP :

```
192.168.10.0/24 → LAN Employés
192.168.20.0/24 → DMZ
192.168.30.0/24 → Serveurs internes
10.0.0.0/24     → Management
```

### 3. Firewall / ACLs

Règles qui contrôlent le trafic entre zones :

```cisco
! Autoriser LAN vers DMZ sur HTTP
permit tcp 192.168.10.0/24 192.168.20.0/24 eq 80

! Bloquer DMZ vers LAN
deny ip 192.168.20.0/24 192.168.10.0/24
```

---

## Microsegmentation (zero trust)

La microsegmentation va plus loin : chaque système est sa propre zone.

```
Segmentation classique :          Microsegmentation :

    ┌───────────────────┐         ┌───────────────────┐
    │      ZONE         │         │  ┌───┐ ┌───┐ ┌───┐│
    │                   │         │  │PC1│ │PC2│ │PC3││
    │  PC ── PC ── PC   │         │  └─┬─┘ └─┬─┘ └─┬─┘│
    │                   │         │    │     │     │  │
    └───────────────────┘         │  ┌─┴─────┴─────┴─┐│
                                  │  │   FIREWALL    ││
    Mouvement latéral             │  └───────────────┘│
    facile entre PCs              └───────────────────┘

                                  Chaque PC est isolé !
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Segmentation** | Diviser le réseau en zones isolées |
| **DMZ** | Zone tampon entre Internet et le LAN |
| **Zone** | Groupe de systèmes avec même niveau de confiance |
| **Trust Level** | Niveau de confiance d'une zone |
| **Microsegmentation** | Chaque système est sa propre zone |
| **Defense in Depth** | Défense en profondeur = plusieurs couches de protection successives (comme les murailles d'un château) |

---

## Résumé en 30 secondes

1. **Segmentation** = diviser le réseau en zones isolées
2. **DMZ** = zone tampon pour les serveurs publics
3. **Règle d'or** : DMZ ne peut PAS initier vers le LAN
4. **VLAN + Firewall** = combo pour segmenter
5. **Microsegmentation** = Zero Trust, chaque système isolé
6. Si une zone est compromise, les autres sont protégées

---

## Schéma récapitulatif

```
ARCHITECTURE DMZ :

                    Internet
                        │
                        ▼
                   ┌─────────┐
                   │FIREWALL │
                   └────┬────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
   ┌────┴────┐     ┌────┴────┐    ┌────┴────┐
   │   LAN   │     │   DMZ   │    │  MGMT   │
   │  ┌───┐  │     │ ┌─────┐ │    │ ┌─────┐ │
   │  │PC │  │     │ │ Web │ │    │ │Admin│ │
   │  └───┘  │     │ └─────┘ │    │ └─────┘ │
   └─────────┘     └─────────┘    └─────────┘


RÈGLES INTER-ZONES :

   LAN ────────→ DMZ    ✓ (accès aux serveurs)
   LAN ────────→ Internet    ✓ (navigation)
   DMZ ────────→ LAN    ✗ (BLOQUÉ !)
   DMZ ────────→ Internet    ✓ (updates)
   Internet ──→ DMZ (ports spécifiques)    ✓
   Internet ──→ LAN    ✗ (BLOQUÉ !)


POURQUOI LA DMZ ?

   Sans DMZ :                    Avec DMZ :

   Internet ──→ Web ──→ DB       Internet ──→ Web
                                             │
   Si Web hacké                      ┌───────┴───────┐
   = Accès direct DB                 │   FIREWALL    │
                                     └───────┬───────┘
                                             │
                                          ┌──┴──┐
                                          │ DB  │
                                          └─────┘

                                Si Web hacké
                                = Firewall protège DB
```
