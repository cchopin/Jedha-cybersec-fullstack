# Adresses IP publiques vs privées

## Introduction

La distinction entre adresses IP publiques et privées est fondamentale pour comprendre le fonctionnement des réseaux modernes. Cette séparation permet à des millions de réseaux internes de coexister tout en partageant l'accès à Internet.

Ce cours couvre :
- Les plages d'adresses privées définies par la RFC 1918
- Le fonctionnement du NAT (Network Address Translation)
- Les adresses ULA (Unique Local Address) en IPv6
- Les implications en cybersécurité

---

## Glossaire

| Sigle/Terme | Nom complet | Description |
|-------------|-------------|-------------|
| **IP** | Internet Protocol | Protocole d'adressage réseau |
| **RFC** | Request For Comments | Document définissant les standards Internet |
| **NAT** | Network Address Translation | Mécanisme de traduction d'adresses entre réseau privé et public |
| **PAT** | Port Address Translation | Variante du NAT utilisant les ports pour différencier les connexions |
| **ISP** | Internet Service Provider | Fournisseur d'accès à Internet |
| **RIR** | Regional Internet Registry | Organisme régional gérant l'attribution des adresses IP publiques |
| **LAN** | Local Area Network | Réseau local |
| **WAN** | Wide Area Network | Réseau étendu (Internet) |
| **ULA** | Unique Local Address | Équivalent IPv6 des adresses privées |
| **GUA** | Global Unicast Address | Adresse IPv6 publique routable sur Internet |
| **SNAT** | Source NAT | NAT modifiant l'adresse source des paquets sortants |
| **DNAT** | Destination NAT | NAT modifiant l'adresse destination des paquets entrants |
| **CGNAT** | Carrier-Grade NAT | NAT à grande échelle utilisé par les FAI |

---

## Adresses IP publiques vs privées : vue d'ensemble

### Le problème de base

IPv4 offre environ 4,3 milliards d'adresses (2^32). Avec des milliards d'appareils connectés dans le monde, ce nombre est insuffisant pour attribuer une adresse unique à chaque appareil.

**Solution** : réutiliser les mêmes plages d'adresses dans différents réseaux privés, et utiliser le NAT pour accéder à Internet.

### Comparaison

| Caractéristique | Adresse publique | Adresse privée |
|-----------------|------------------|----------------|
| Unicité | Unique au monde | Unique dans le réseau local seulement |
| Routage Internet | Routable | Non routable |
| Attribution | Par les RIR/ISP | Libre, par l'administrateur |
| Coût | Payant (via l'ISP) | Gratuit |
| Visibilité | Visible sur Internet | Cachée derrière le NAT |
| Exemple | 203.0.113.50 | 192.168.1.100 |

### Schéma simplifié

```
┌──────────────────────────────────────┐
│         RÉSEAU PRIVÉ (LAN)           │
│                                      │
│  PC1: 192.168.1.10                   │
│  PC2: 192.168.1.11       ┌─────────┐ │       ┌─────────────┐
│  Serveur: 192.168.1.50   │ Routeur │─┼───────│   INTERNET  │
│  Imprimante: 192.168.1.99│   NAT   │ │       │             │
│                          └─────────┘ │       │ IP publique │
│                               │      │       │ 203.0.113.5 │
│                          IP privée   │       └─────────────┘
│                         192.168.1.1  │
└──────────────────────────────────────┘
```

Tous les appareils du LAN partagent la même adresse publique (203.0.113.5) pour accéder à Internet.

---

## Adresses publiques

### Définition

Une adresse IP publique est une adresse **unique au niveau mondial**, attribuée par un fournisseur d'accès (ISP) et routable sur Internet.

Lorsqu'un appareil accède à un site web, c'est l'adresse publique (celle du routeur/NAT) que le serveur distant voit, pas l'adresse privée de l'appareil.

### Attribution des adresses publiques

Les adresses publiques sont gérées de manière hiérarchique :

```
IANA (Internet Assigned Numbers Authority)
         │
         ▼
┌─────────────────────────────────────────────────────┐
│              RIR (Regional Internet Registries)     │
├──────────┬──────────┬──────────┬──────────┬─────────┤
│  ARIN    │ RIPE NCC │  APNIC   │ AFRINIC  │ LACNIC  │
│ Amérique │ Europe   │ Asie-    │ Afrique  │ Amérique│
│ du Nord  │ Moyen-   │ Pacifique│          │ Latine  │
│          │ Orient   │          │          │         │
└──────────┴──────────┴──────────┴──────────┴─────────┘
         │
         ▼
    ISP (Fournisseurs d'accès)
         │
         ▼
    Clients (entreprises, particuliers)
```

**Important** : il est impossible de choisir arbitrairement une adresse publique. Toute adresse publique doit être attribuée officiellement.

### Plages d'adresses publiques

Toutes les adresses IPv4 qui ne sont **pas** dans les plages réservées sont publiques. Les principales plages réservées (non publiques) sont :

| Plage | Usage |
|-------|-------|
| 10.0.0.0/8 | Privé (RFC 1918) |
| 172.16.0.0/12 | Privé (RFC 1918) |
| 192.168.0.0/16 | Privé (RFC 1918) |
| 127.0.0.0/8 | Loopback |
| 169.254.0.0/16 | Link-local (APIPA) |
| 224.0.0.0/4 | Multicast |
| 240.0.0.0/4 | Réservé/Expérimental |

---

## Adresses privées (RFC 1918)

### Définition

La RFC 1918 définit trois plages d'adresses réservées pour un usage interne. Ces adresses :
- Peuvent être utilisées librement dans n'importe quel réseau privé
- Ne sont **jamais routées sur Internet**
- Peuvent être réutilisées par des millions d'organisations sans conflit

### Les trois plages RFC 1918

| Plage | Notation CIDR | Nombre d'adresses | Classe historique | Usage typique |
|-------|---------------|-------------------|-------------------|---------------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | 16 777 216 | Classe A | Grandes entreprises, datacenters |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | 1 048 576 | Classe B | Entreprises moyennes |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | 65 536 | Classe C | Réseaux domestiques, PME |

### Comment identifier une adresse privée

| Premier octet | Vérification | Privée ? |
|---------------|--------------|----------|
| 10 | Toujours | Oui |
| 172 | Si deuxième octet entre 16 et 31 | Oui |
| 192 | Si deuxième octet = 168 | Oui |
| Autre | - | Non (probablement publique) |

### Exemples

| Adresse | Privée ou publique ? | Explication |
|---------|---------------------|-------------|
| 10.0.5.200 | Privée | Commence par 10 |
| 172.20.1.1 | Privée | 172.x avec x entre 16-31 |
| 172.50.1.1 | Publique | 172.x mais x > 31 |
| 192.168.100.1 | Privée | 192.168.x.x |
| 192.169.1.1 | Publique | 192.x mais x ≠ 168 |
| 8.8.8.8 | Publique | Ne correspond à aucune plage privée |

---

## NAT : Network Address Translation

### Principe de fonctionnement

Le NAT permet à plusieurs appareils avec des adresses privées de partager une ou plusieurs adresses publiques pour accéder à Internet.

### Fonctionnement étape par étape

**Scénario** : un PC (192.168.1.100) veut accéder à un serveur web (93.184.216.34)

```
Étape 1 : Le PC envoie une requête
┌──────────────────────────────────────────────────┐
│ Paquet original                                  │
│ Source : 192.168.1.100:54321                     │
│ Destination : 93.184.216.34:443                  │
└──────────────────────────────────────────────────┘
                    │
                    ▼
Étape 2 : Le routeur NAT traduit l'adresse source
┌──────────────────────────────────────────────────┐
│ Paquet modifié (envoyé sur Internet)             │
│ Source : 203.0.113.5:12345  ← IP publique        │
│ Destination : 93.184.216.34:443                  │
└──────────────────────────────────────────────────┘
                    │
          Le routeur enregistre :
          192.168.1.100:54321 ↔ 203.0.113.5:12345
                    │
                    ▼
Étape 3 : Le serveur répond
┌──────────────────────────────────────────────────┐
│ Réponse du serveur                               │
│ Source : 93.184.216.34:443                       │
│ Destination : 203.0.113.5:12345                  │
└──────────────────────────────────────────────────┘
                    │
                    ▼
Étape 4 : Le routeur NAT traduit la destination
┌──────────────────────────────────────────────────┐
│ Paquet retraduit (envoyé au PC)                  │
│ Source : 93.184.216.34:443                       │
│ Destination : 192.168.1.100:54321 ← IP privée    │
└──────────────────────────────────────────────────┘
```

### Table de traduction NAT

Le routeur maintient une table pour faire correspondre les connexions :

| IP privée:port | IP publique:port | IP distante:port | Protocole |
|----------------|------------------|------------------|-----------|
| 192.168.1.100:54321 | 203.0.113.5:12345 | 93.184.216.34:443 | TCP |
| 192.168.1.100:54322 | 203.0.113.5:12346 | 142.250.74.110:443 | TCP |
| 192.168.1.50:60000 | 203.0.113.5:12347 | 151.101.1.140:443 | TCP |

### Types de NAT

| Type | Description | Ratio | Usage |
|------|-------------|-------|-------|
| **NAT statique** | Une IP privée = une IP publique fixe | 1:1 | Serveurs accessibles depuis Internet |
| **NAT dynamique** | Pool d'IPs publiques partagé | N:M | Entreprises avec plusieurs IPs publiques |
| **PAT / NAT Overload** | Une seule IP publique pour tous, différenciée par ports | N:1 | Box Internet domestiques, PME |

### PAT (Port Address Translation) en détail

PAT est le type de NAT le plus courant. Il permet à des centaines d'appareils de partager une seule IP publique en utilisant des numéros de port différents.

```
Réseau interne                    NAT                      Internet
                                  │
PC1 (192.168.1.10:50001) ────────►│                        
PC2 (192.168.1.11:50001) ────────►│ 203.0.113.5:10001 ───► Serveur A
PC3 (192.168.1.12:50001) ────────►│ 203.0.113.5:10002 ───► Serveur B
                                  │ 203.0.113.5:10003 ───► Serveur A
```

Même si les 3 PC utilisent le même port source (50001), le NAT attribue des ports différents côté public.

### CGNAT (Carrier-Grade NAT)

Avec l'épuisement des adresses IPv4, certains FAI utilisent le CGNAT : un NAT supplémentaire au niveau du fournisseur.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────┐
│ Réseau      │ NAT │ Réseau FAI  │CGNAT│ IP publique │     │ Internet │
│ domestique  │────►│ 100.64.x.x  │────►│ partagée    │────►│          │
│ 192.168.x.x │     │ (RFC 6598)  │     │             │     │          │
└─────────────┘     └─────────────┘     └─────────────┘     └──────────┘
```

La plage 100.64.0.0/10 (RFC 6598) est réservée au CGNAT.

**Problème** : double NAT = difficultés accrues pour l'hébergement de services, le P2P, les jeux en ligne.

---

## Limites du NAT

| Limitation | Explication | Impact |
|------------|-------------|--------|
| **Rupture du end-to-end** | Impossible de contacter directement un appareil derrière un NAT | P2P, VoIP, jeux en ligne complexes |
| **Configuration requise** | Certains protocoles (FTP, SIP) nécessitent des ajustements | Administration plus complexe |
| **Latence** | Chaque traduction ajoute un délai | Perceptible en temps réel |
| **Port forwarding** | Nécessaire pour héberger des services | Configuration manuelle |
| **Logs et traçabilité** | L'IP source originale est masquée | Forensics plus complexes |

---

## IPv6 et les adresses ULA

### Pourquoi IPv6 n'a pas besoin de NAT

IPv6 offre 2^128 adresses, soit environ 340 sextillions. Chaque appareil peut avoir sa propre adresse publique (GUA - Global Unicast Address).

Cependant, le besoin d'adresses internes non routables existe toujours pour :
- L'isolation de certains services
- Les communications internes uniquement
- La sécurité (ne pas exposer sur Internet)

### ULA : l'équivalent des adresses privées en IPv6

Les ULA (Unique Local Addresses) sont définies par la RFC 4193.

| Caractéristique | Valeur |
|-----------------|--------|
| Préfixe | fc00::/7 |
| Préfixe utilisé en pratique | fd00::/8 |
| Routable sur Internet | Non |
| Unique globalement | Statistiquement oui (40 bits aléatoires) |

### Structure d'une adresse ULA

```
|  8 bits |    40 bits     | 16 bits |      64 bits        |
|---------|----------------|---------|---------------------|
|   fd    | ID aléatoire   | Subnet  |    Interface ID     |
|         | (unique org.)  |         |                     |

Exemple : fd12:3456:789a:0001:0000:0000:0000:0001
          └──────┬───────┘└─┬─┘└──────────┬──────────┘
           Préfixe unique  Sous-    Identifiant interface
           de l'org.       réseau
```

### Comparaison RFC 1918 vs ULA

| Aspect | RFC 1918 (IPv4) | ULA (IPv6) |
|--------|-----------------|------------|
| Préfixes | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | fd00::/8 |
| Unicité | Non (réutilisés partout) | Oui (40 bits aléatoires) |
| Collision possible | Oui (si fusion de réseaux) | Très improbable |
| NAT nécessaire | Oui pour accéder à Internet | Non (mais filtrage recommandé) |

### Identification rapide des types d'adresses IPv6

| Commence par | Type | Routable sur Internet |
|--------------|------|----------------------|
| 2000::/3 (2xxx ou 3xxx) | GUA (Global Unicast) | Oui |
| fe80:: | Link-local | Non |
| fd00:: | ULA | Non |
| ff00:: | Multicast | Dépend du scope |
| ::1 | Loopback | Non |

---

## Implications en cybersécurité

### Reconnaissance et énumération

| Contexte | Implication |
|----------|-------------|
| Scan depuis Internet | Seules les IPs publiques sont visibles |
| Scan interne | Les plages RFC 1918 révèlent l'architecture interne |
| Identification du NAT | Un traceroute peut révéler la présence de NAT |
| CGNAT | Plusieurs clients partagent la même IP publique (attribution difficile) |

### Attaques liées au NAT

| Attaque | Description | Contre-mesure |
|---------|-------------|---------------|
| NAT slipstreaming | Exploitation du NAT pour ouvrir des ports | Mise à jour des navigateurs, inspection du trafic |
| Port scanning derrière NAT | Identifier les ports forwardés | Limiter le port forwarding, firewall |
| UPnP exploitation | Ouverture automatique de ports par des malwares | Désactiver UPnP |
| NAT traversal abuse | Techniques STUN/TURN détournées | Surveiller les connexions sortantes |

### Bonnes pratiques

| Pratique | Justification |
|----------|---------------|
| Désactiver UPnP | Empêche l'ouverture automatique de ports par des applications/malwares |
| Limiter le port forwarding | Réduire la surface d'attaque |
| Journaliser les connexions NAT | Traçabilité en cas d'incident |
| Segmenter avec des VLANs | Isolation même au sein du réseau privé |
| Filtrer les adresses privées en entrée | Anti-spoofing (une IP privée ne doit jamais arriver depuis Internet) |

### Filtrage anti-spoofing

Un paquet entrant depuis Internet avec une adresse source privée est forcément falsifié :

```
# Règles firewall anti-spoofing (exemple iptables)
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
```

Ces règles bloquent tout paquet prétendant venir d'une adresse privée sur l'interface publique.

---

## Résumé des plages à connaître

### IPv4

| Plage | CIDR | Usage |
|-------|------|-------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Privé (RFC 1918) |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Privé (RFC 1918) |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | Privé (RFC 1918) |
| 100.64.0.0 - 100.127.255.255 | 100.64.0.0/10 | CGNAT (RFC 6598) |
| 127.0.0.0 - 127.255.255.255 | 127.0.0.0/8 | Loopback |
| 169.254.0.0 - 169.254.255.255 | 169.254.0.0/16 | Link-local (APIPA) |
| 224.0.0.0 - 239.255.255.255 | 224.0.0.0/4 | Multicast |

### IPv6

| Préfixe | Usage |
|---------|-------|
| 2000::/3 | Global Unicast (public) |
| fd00::/8 | ULA (privé) |
| fe80::/10 | Link-local |
| ff00::/8 | Multicast |
| ::1/128 | Loopback |

---

## Commandes utiles

```bash
# Afficher l'IP publique (Linux)
curl ifconfig.me
curl ipinfo.io/ip

# Afficher les IPs privées (Linux)
ip addr show
hostname -I

# Afficher la table NAT (Linux avec iptables)
iptables -t nat -L -n -v
conntrack -L

# Afficher la configuration IP (Windows)
ipconfig /all

# Vérifier si une IP est publique ou privée (test manuel)
# → Vérifier si elle tombe dans les plages RFC 1918
```

---

## Ressources

| Ressource | Lien |
|-----------|------|
| RFC 1918 - Adresses privées | https://www.rfc-editor.org/rfc/rfc1918 |
| RFC 4193 - IPv6 ULA | https://www.rfc-editor.org/rfc/rfc4193 |
| RFC 6598 - CGNAT | https://www.rfc-editor.org/rfc/rfc6598 |
| Guide NAT Cisco | https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/ |
| IANA Special-Purpose Registry | https://www.iana.org/assignments/iana-ipv4-special-registry/ |
