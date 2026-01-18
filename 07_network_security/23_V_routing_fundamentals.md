# Fondamentaux du Routage - Version Simplifiée

## L'idée en une phrase

Le routage est le GPS du réseau : il permet aux paquets de trouver leur chemin d'un réseau à un autre en passant par les bons routeurs.

---

## Pourquoi est-ce important ?

Sans routage, les paquets ne sauraient pas comment aller d'un réseau à l'autre. Le routage est le "système nerveux" de toute infrastructure réseau.

**Analogie** : une lettre qui doit traverser plusieurs pays. À chaque frontière, quelqu'un décide par quel pays passer ensuite pour arriver à destination. C'est exactement ce que font les routeurs.

---

## Routage Statique vs Dynamique

### Routage Statique

Routes configurées **à la main** par l'administrateur.

```
ip route 192.168.2.0 255.255.255.0 10.0.0.2
"Pour aller à 192.168.2.0, passer par 10.0.0.2"
```

| Avantages | Inconvénients |
|-----------|---------------|
| Simple et prévisible | Ne s'adapte pas aux pannes |
| Pas de protocole à pirater | Maintenance manuelle |
| Peu de ressources | Ne passe pas à l'échelle |

**Quand l'utiliser** : petits réseaux, routes de backup

### Routage Dynamique

Les routeurs **échangent des informations** et construisent leurs tables automatiquement.

| Protocole | Type | Usage |
|-----------|------|-------|
| **RIP** | Distance-vector | Obsolète, petits réseaux |
| **OSPF** | Link-state | Entreprise (standard ouvert) |
| **EIGRP** | Hybride | Entreprise (Cisco) |
| **BGP** | Path-vector | Internet, entre opérateurs |

**Analogie** : les routeurs sont comme des taxis qui se parlent entre eux pour connaître l'état du trafic en temps réel.

---

## Comment un routeur choisit-il sa route ?

### 1. Longest Prefix Match

Le routeur choisit la route **la plus spécifique** (masque le plus long).

```
Route A : 192.168.0.0/16 → Passe par R1
Route B : 192.168.1.0/24 → Passe par R2

Paquet vers 192.168.1.50 → Prend la route B (/24 est plus spécifique)
```

**Analogie** : "Aller à Paris" est moins précis que "Aller au 10 rue de la Paix, Paris". La direction la plus précise est privilégiée.

### 2. Administrative Distance (AD)

Si deux routes ont le même préfixe, la **confiance** accordée à la source est examinée.

| Source | AD | Confiance |
|--------|-----|-----------|
| Directly Connected | 0 | Maximum |
| Static | 1 | Très haute |
| BGP (externe) | 20 | Haute |
| OSPF | 110 | Moyenne |
| RIP | 120 | Faible |

**Plus l'AD est bas, plus la route est fiable.**

### 3. Métrique

Si l'AD est identique, le **coût** du chemin est examiné.

| Protocole | Métrique |
|-----------|----------|
| RIP | Nombre de sauts (max 15) |
| OSPF | Coût basé sur la bande passante |
| EIGRP | Combinaison (bande passante, délai...) |

---

## NAT : partager une adresse publique

### Le problème

Les adresses IPv4 publiques sont rares. Comment connecter des centaines de machines à Internet avec une seule IP publique ?

### La solution : NAT

Le NAT (Network Address Translation) traduit les adresses privées en adresses publiques.

```
Réseau interne                    NAT                    Internet
192.168.1.10 ───────────→ 175.25.124.83 ───────────→ google.com
192.168.1.11 ─────────┘   (même IP publique)
192.168.1.12 ─────────┘
```

### Types de NAT

| Type | Description | Exemple |
|------|-------------|---------|
| **Static NAT** | 1 IP privée = 1 IP publique | Serveur web |
| **PAT/Overload** | Plusieurs IPs privées = 1 IP publique | Box Internet |

### NAT n'est PAS un firewall !

**Mythe** : "Être derrière un NAT signifie être protégé"

**Réalité** : Le NAT cache les IPs internes mais :
- Ne bloque pas le trafic sortant (malware, exfiltration)
- Peut être contourné (reverse shell)

---

## Routage Inter-VLAN

### Le problème

Les VLANs sont isolés. Comment permettre à VLAN 10 de parler à VLAN 20 ?

### Solution 1 : Router-on-a-Stick

Un routeur avec des sous-interfaces pour chaque VLAN :

```
           ┌─────────────┐
           │   Routeur   │
           │  .10.1 .20.1│
           └──────┬──────┘
                  │ Trunk (tous les VLANs)
                  │
           ┌──────┴──────┐
           │   Switch    │
           │             │
      ─────┴─────   ─────┴─────
      VLAN 10       VLAN 20
```

### Solution 2 : Switch Layer 3 (SVI)

Le switch fait lui-même le routage via des interfaces virtuelles :

```cisco
ip routing

interface vlan 10
 ip address 192.168.10.1 255.255.255.0

interface vlan 20
 ip address 192.168.20.1 255.255.255.0
```

---

## Attaques sur le routage

### Route Injection

Un attaquant injecte de fausses routes pour :
- **Rediriger le trafic** vers lui (Man-in-the-Middle)
- **Créer un blackhole** (les paquets disparaissent)
- **Contourner les firewalls**

### BGP Hijacking

Sur Internet, un attaquant annonce qu'il possède une plage d'IPs qu'il ne possède pas :

```
Normal : bank.com → ISP A → banque réelle
Hijack : bank.com → ISP A → attaquant (faux site)
```

**Cas réel** : En 2018, vol de $150,000 en crypto via BGP hijacking.

### Protection

| Mesure | Ce qu'elle fait |
|--------|-----------------|
| Authentification MD5 | Signe les messages entre routeurs |
| Filtrage de routes | N'accepte que les routes valides |
| RPKI (pour BGP) | Validation cryptographique des annonces |
| Passive interfaces | Empêche OSPF sur les segments utilisateurs |

---

## Commandes utiles

### Voir la table de routage

```bash
# Linux
ip route

# Windows
route print

# Cisco
show ip route
```

### Tracer le chemin

```bash
# Linux/Mac
traceroute google.com

# Windows
tracert google.com
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Routage** | Trouver le chemin d'un réseau à l'autre |
| **Statique** | Routes configurées à la main |
| **Dynamique** | Routes apprises automatiquement |
| **NAT** | Traduction d'adresses privées en publiques |
| **AD** | Administrative Distance - niveau de confiance d'une source de route (plus bas = plus fiable) |
| **Métrique** | Coût d'un chemin |
| **Longest Prefix Match** | La route la plus spécifique gagne |
| **Inter-VLAN** | Routage entre VLANs |
| **Route Injection** | Attaque par injection de fausses routes |

---

## Résumé en 30 secondes

1. **Routage** = GPS du réseau pour trouver le bon chemin
2. **Statique** = manuel, simple mais ne s'adapte pas
3. **Dynamique** = automatique (RIP, OSPF, BGP)
4. Le routeur choisit : **préfixe le plus long** → **AD la plus basse** → **métrique**
5. **NAT** = partager une IP publique (mais pas un firewall !)
6. **Sécurité** : authentifier les protocoles, filtrer les routes

---

## Schéma récapitulatif

```
                    INTERNET
                        │
                   ┌────┴────┐
                   │ Routeur │ ← NAT (traduit les IPs)
                   │  BGP    │
                   └────┬────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
         ┌────┴────┐   ...   ┌────┴────┐
         │ Routeur │         │ Routeur │
         │  OSPF   │←──────→│  OSPF   │
         └────┬────┘         └────┬────┘
              │                   │
         ┌────┴────┐         ┌────┴────┐
         │ Switch  │         │ Switch  │
         │ L3/SVI  │         │ L3/SVI  │
         └────┬────┘         └────┬────┘
              │                   │
        ┌─────┴─────┐       ┌─────┴─────┐
       VLAN 10  VLAN 20   VLAN 10  VLAN 20


DÉCISION DE ROUTAGE :

Paquet vers 192.168.1.50

1. Cherche route la plus spécifique (longest prefix)
2. Si égalité → regarde l'AD
3. Si égalité → regarde la métrique
4. Envoie au next-hop
```
