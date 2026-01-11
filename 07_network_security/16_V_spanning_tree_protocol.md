# Spanning Tree Protocol (STP) - Version Simplifiée

## L'idée en une phrase

STP est le protocole qui empêche les boucles réseau en désactivant automatiquement certains liens redondants, tout en les gardant en réserve en cas de panne.

---

## Pourquoi les boucles sont-elles dangereuses ?

### Le problème sans STP

Un réseau avec plusieurs chemins entre switches :

```
Sans STP - CATASTROPHE :

   Switch A ←────────────→ Switch B
       ↑                        ↑
       │      Deux chemins      │
       └────────────────────────┘

1. Un PC envoie un broadcast
2. Le broadcast prend les DEUX chemins
3. Chaque switch le renvoie à l'autre
4. Les trames tournent en BOUCLE INFINIE
5. → Réseau saturé en quelques secondes !
```

**Analogie** : une rumeur qui circule indéfiniment dans un groupe. Si chacun la répète à tout le monde, elle explose en volume.

### Conséquences d'une boucle

| Effet | Description |
|-------|-----------------|
| **Broadcast Storm** | Les trames se multiplient à l'infini |
| **CPU à 100%** | Les switches sont complètement saturés |
| **Réseau DOWN** | Plus rien ne fonctionne |

---

## Comment STP résout-il le problème ?

### Le principe

STP **bloque certains liens** pour créer une topologie sans boucle :

```
Avec STP - STABLE :

   Switch A ←────────────→ Switch B
   (Root)       actif           ↑
       ↑                        │
       │       BLOQUÉ           │
       └────────╳───────────────┘

Un seul chemin actif entre chaque switch
Les liens bloqués sont prêts à prendre le relais
```

**Analogie** : dans une ville avec plusieurs routes entre deux points, certaines rues sont fermées pour éviter les embouteillages. Si une route principale est bloquée, une rue fermée est rouverte.

---

## Le Root Bridge : le chef du réseau

### Qu'est-ce que c'est ?

Le **Root Bridge** est le switch de référence. Tous les autres calculent leur meilleur chemin vers lui.

### Comment est-il choisi ?

Chaque switch a un identifiant unique (Bridge ID) composé de :
- **Priorité** (par défaut 32768)
- **Adresse MAC** (unique)

Le switch avec le **plus petit** Bridge ID devient Root Bridge.

```
Switch A : Priorité 32768, MAC ...44:55
Switch B : Priorité 32768, MAC ...CC:DD
Switch C : Priorité 32768, MAC ...11:22 ← Plus petite MAC = ROOT

Pour forcer un switch comme Root :
Switch(config)# spanning-tree vlan 1 priority 4096
```

**Analogie** : une élection. Celui avec le plus petit numéro de carte d'identité gagne (sauf si une priorité plus petite est attribuée).

---

## Les états des ports STP

### Les 5 états de STP classique

| État | Durée | Description |
|------|-------|-----------------|
| **Blocking** | - | Bloqué, ne transmet rien |
| **Listening** | 15s | Écoute les messages STP |
| **Learning** | 15s | Apprend les adresses MAC |
| **Forwarding** | - | Opérationnel, transmet |
| **Disabled** | - | Port éteint |

### Le problème de convergence

Quand un lien tombe, STP met **30 à 50 secondes** pour réagir. C'est très long !

```
Port activé → Blocking → Listening → Learning → Forwarding
                           ↓
               Temps total : ~50 secondes !
```

---

## Les rôles des ports

| Rôle | Description |
|------|-------------|
| **Root Port** | Le meilleur chemin vers le Root Bridge |
| **Designated Port** | Transmet le trafic vers un segment |
| **Blocked Port** | Désactivé pour éviter les boucles |

```
Exemple :

        [Root Bridge]
             │
     DP ─────┼───── DP
             │
Switch B ────┼──────── Switch C
    RP       BP           RP

DP = Designated Port
RP = Root Port
BP = Blocked Port (casse la boucle)
```

---

## RSTP : la version rapide

### Pourquoi RSTP ?

**RSTP** (Rapid STP) fait la même chose que STP, mais en **1 à 5 secondes** au lieu de 30-50 secondes.

### Comparaison STP vs RSTP

| Aspect | STP (802.1D) | RSTP (802.1w) |
|--------|--------------|---------------|
| **Convergence** | 30-50 secondes | 1-5 secondes |
| **États** | 5 | 3 (simplifié) |
| **À utiliser** | Jamais si possible | Toujours |

### Activation de RSTP

```cisco
Switch(config)# spanning-tree mode rapid-pvst
```

---

## Optimisations importantes

### PortFast : pour les PCs

Les ports connectés à des PCs n'ont pas besoin d'attendre 30 secondes. PortFast les passe directement en Forwarding :

```cisco
Switch(config-if)# spanning-tree portfast
```

**Attention** : JAMAIS sur un port connecté à un autre switch !

### BPDU Guard : protection

Désactive automatiquement un port PortFast si un switch y est connecté :

```cisco
Switch(config-if)# spanning-tree bpduguard enable
```

**Analogie** : un détecteur d'intrusion. Si quelqu'un branche un switch non autorisé, le port se coupe.

---

## Dépannage STP

### Commandes de vérification

| Commande | Affichage |
|----------|-------------------|
| `show spanning-tree` | Vue d'ensemble |
| `show spanning-tree root` | Qui est le Root Bridge |
| `show spanning-tree interface Gi0/1` | Détails d'un port |

### Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| Root Bridge mal placé | Élection automatique | Définir la priorité manuellement |
| Convergence lente | STP classique | Passer à RSTP |
| Port en err-disabled | Violation de sécurité | shutdown puis no shutdown |

---

## Checklist configuration STP

```
□ RSTP activé (pas STP classique)
□ Root Bridge défini explicitement
□ PortFast sur les ports access (PCs)
□ BPDU Guard sur les ports PortFast
□ Pas de PortFast vers un autre switch !
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **STP** | Protocole anti-boucle |
| **RSTP** | STP rapide (1-5 secondes) |
| **Root Bridge** | Switch de référence (chef) |
| **BPDU** | Messages échangés par STP |
| **Root Port** | Port vers le Root Bridge |
| **Designated Port** | Port qui transmet sur un segment |
| **Blocked Port** | Port désactivé pour éviter les boucles |
| **PortFast** | Bypass du délai STP pour les PCs |
| **BPDU Guard** | Protection contre les switches non autorisés |

---

## Résumé en 30 secondes

1. **STP** empêche les boucles en bloquant des liens redondants
2. Le **Root Bridge** est élu (plus petit Bridge ID gagne)
3. STP classique est **lent** (30-50s) → utiliser **RSTP** (1-5s)
4. **PortFast** pour les PCs, **BPDU Guard** pour la sécurité
5. Toujours **forcer** le Root Bridge, ne pas laisser l'élection au hasard
6. Vérifier avec `show spanning-tree`

---

## Schéma récapitulatif

```
                Sans STP                          Avec STP

   SW-A ←──────→ SW-B               SW-A ←──────→ SW-B
     ↑             ↑                  (Root)        ↑
     │  BOUCLE !   │                    ↑          │
     └─────────────┘                    │  BLOQUÉ  │
                                        └────╳─────┘

   Trames tournent                   Un seul chemin
   indéfiniment                      Backup prêt

   → CRASH                           → STABLE
```
