# Routage et Communication Inter-VLAN - Version Simplifiée

## L'idée en une phrase

Le routage permet aux paquets de trouver leur chemin entre réseaux différents, et le routage inter-VLAN permet à des VLANs normalement isolés de communiquer entre eux.

---

## Pourquoi c'est important ?

Par défaut, un PC dans le VLAN 10 (RH) ne peut pas parler à un PC dans le VLAN 20 (IT). C'est voulu pour la sécurité, mais parfois ils doivent quand même communiquer !

```
Sans routage inter-VLAN :

VLAN 10 (RH)          VLAN 20 (IT)
    │                      │
    X ────── Mur ────── X

Avec routage inter-VLAN :

VLAN 10 (RH)          VLAN 20 (IT)
    │                      │
    └────── Routeur ───────┘
           (fait le pont)
```

---

## Routage statique vs dynamique

### La différence en une image

```
STATIQUE :                    DYNAMIQUE :
"Prendre toujours             "Calculer le meilleur
 cette route"                  chemin automatiquement"

    GPS programmé               GPS temps réel
    sans mise à jour            avec mise à jour

Avantage : simple             Avantage : s'adapte
Inconvénient : rigide         Inconvénient : complexe
```

### Quand utiliser quoi ?

| Situation | Choix |
|-----------|-------|
| Petit réseau (< 10 routeurs) | Statique |
| Route vers Internet | Statique |
| Grand réseau | Dynamique |
| Réseau qui change souvent | Dynamique |

---

## Comment le routeur choisit une route ?

### 3 règles dans l'ordre

```
1. LONGEST PREFIX MATCH (le plus spécifique gagne)
   Destination : 192.168.1.50

   Route A : 192.168.0.0/16  ← moins spécifique
   Route B : 192.168.1.0/24  ← GAGNE (plus spécifique)

2. ADMINISTRATIVE DISTANCE (la source la plus fiable)
   Connected = 0 (directement branché)
   Static = 1
   OSPF = 110
   RIP = 120

   Plus bas = plus fiable

3. MÉTRIQUE (le chemin le moins coûteux)
   Si même AD, on prend la métrique la plus basse
```

**Analogie** : c'est comme choisir un restaurant :
1. D'abord le plus proche (spécifique)
2. Puis celui recommandé par une source de confiance (AD)
3. Enfin le moins cher (métrique)

---

## NAT : cacher les adresses privées

### Pourquoi le NAT existe ?

```
Problème : 4 milliards d'adresses IPv4 pour 15 milliards d'appareils !

Solution : NAT permet à de nombreux appareils de partager UNE adresse publique

                Adresses privées          Adresse publique
                192.168.1.10  ─┐
                192.168.1.11  ─┼──→ NAT ──→ 203.0.113.5 ──→ Internet
                192.168.1.12  ─┘

C'est comme un standard téléphonique : un numéro public,
plusieurs postes internes.
```

### Types de NAT

| Type | Comment ça marche | Usage |
|------|-------------------|-------|
| **Static NAT** | 1 IP privée = 1 IP publique | Serveurs web |
| **Dynamic NAT** | Pool d'IPs publiques | Entreprises |
| **PAT** | 1 IP publique + ports | Box internet (le plus courant) |

---

## Routage Inter-VLAN

### Méthode 1 : Router-on-a-Stick

Un seul câble entre le switch et le routeur, mais plusieurs "sous-interfaces" :

```
                    ┌─────────────────┐
                    │    Routeur      │
                    │                 │
                    │ .10 = VLAN 10   │
                    │ .20 = VLAN 20   │
                    └────────┬────────┘
                             │ 1 câble trunk
                             │ (transporte tous les VLANs)
                    ┌────────┴────────┐
                    │     Switch      │
                    │                 │
              ┌─────┴─────┐     ┌─────┴─────┐
              │  VLAN 10  │     │  VLAN 20  │
              │    RH     │     │    IT     │
              └───────────┘     └───────────┘

Avantage : peu coûteux (1 routeur, 1 câble)
Inconvénient : goulot d'étranglement (1 seul câble)
```

### Méthode 2 : SVI (Switch Layer 3)

Le switch fait le routage lui-même, sans passer par un routeur externe :

```
                    ┌─────────────────┐
                    │  Switch L3      │
                    │                 │
                    │ Route en interne│
                    │ (très rapide)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
         │ VLAN 10 │    │ VLAN 20 │    │ VLAN 30 │
         └─────────┘    └─────────┘    └─────────┘

Avantage : très rapide, pas de goulot
Inconvénient : plus cher (switch L3)
```

### Comparaison

| Critère | Router-on-a-Stick | SVI |
|---------|-------------------|-----|
| Coût | Bas | Élevé |
| Performance | Limitée | Excellente |
| Pour quel réseau ? | Petit | Moyen à grand |
| Complexité | Simple | Modérée |

---

## Protections de sécurité

### Risques

| Attaque | Description |
|---------|-------------|
| Route Injection | Injecter de fausses routes |
| NAT Slipstreaming | Bypass du NAT depuis le web |
| VLAN Hopping | Sauter d'un VLAN à l'autre |

### Protections

```cisco
! ACL entre VLANs (autoriser seulement HTTP/HTTPS)
ip access-list extended VLAN10-TO-VLAN20
 permit tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 80
 permit tcp 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255 eq 443
 deny ip any any

! Appliquer sur l'interface
interface vlan 10
 ip access-group VLAN10-TO-VLAN20 out
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Routage** | Trouver le chemin pour un paquet |
| **Route statique** | Route configurée à la main |
| **Route dynamique** | Route apprise automatiquement |
| **NAT** | Cacher les IPs privées derrière une IP publique |
| **PAT** | NAT avec ports (le plus courant) |
| **Router-on-a-Stick** | Routage inter-VLAN avec 1 câble trunk |
| **SVI** | Interface virtuelle sur switch L3 |
| **Longest Prefix Match** | La route la plus spécifique gagne |
| **Administrative Distance** | Fiabilité de la source de route |
| **Passerelle par défaut** | Routeur vers lequel envoyer le trafic inconnu |

---

## Résumé en 30 secondes

1. **Routage** = faire passer les paquets d'un réseau à l'autre
2. **Statique** = routes à la main, **Dynamique** = routes automatiques
3. **NAT** = partager une IP publique entre plusieurs appareils
4. **Inter-VLAN** = faire communiquer des VLANs isolés
5. **Router-on-a-Stick** = 1 routeur + trunk (petit réseau)
6. **SVI** = switch L3 qui route lui-même (grand réseau)

---

## Schéma récapitulatif

```
ROUTAGE INTER-VLAN - DEUX MÉTHODES :

ROUTER-ON-A-STICK :                    SVI (Switch L3) :

     Routeur                           Switch L3
        │                                  │
        │ trunk                     Route en interne
        │ (1 câble)                  (pas de câble)
        │                                  │
     Switch                         ┌──────┼──────┐
        │                           │      │      │
  ┌─────┼─────┐                   VLAN10 VLAN20 VLAN30
  │           │
VLAN10     VLAN20                  ↑ Rapide, pour grands réseaux

↑ Simple, pour petits réseaux


NAT - PRINCIPE :

    Réseau interne              Internet

    192.168.1.10 ─┐
    192.168.1.11 ─┼──→ NAT ──→ 203.0.113.5 ──→ Web
    192.168.1.12 ─┘     │
                        │
              Traduit les adresses
              et garde une table


SÉLECTION DE ROUTE :

1. Longest Prefix Match (le plus spécifique)
   /24 bat /16, /25 bat /24

2. Administrative Distance (la source fiable)
   Connected (0) > Static (1) > OSPF (110) > RIP (120)

3. Métrique (le moins coûteux)
   Plus bas = meilleur
```
