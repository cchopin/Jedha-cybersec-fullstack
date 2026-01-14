# Lab 41: WireGuard Site-to-Site VPN

Ce lab vous permet de configurer un **VPN Site-to-Site avec WireGuard** entre deux firewalls pfSense dans GNS3.

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Configuration WireGuard](#configuration-wireguard)
6. [Vérification](#vérification)
7. [Troubleshooting](#troubleshooting)

---

## Objectifs

- Configurer un VPN Site-to-Site entre deux réseaux distincts
- Installer et configurer WireGuard sur pfSense
- Comprendre les concepts de tunnel VPN, clés publiques/privées
- Permettre la communication sécurisée entre deux sites distants

---

## Prérequis

- **GNS3** connecté au serveur distant (`192.168.144.120`)
- **Ansible** installé (`brew install ansible`)
- Avoir complété le Lab 40 (pfSense Setup)
- Connaissance de base de pfSense

---

## Architecture

```
41_wireguard_vpn/
├── ansible.cfg
├── inventory.yml
├── group_vars/all.yml
├── README.md
├── node_info.yml              # Généré automatiquement
└── playbooks/
    ├── 00_full_lab.yml        # Déploiement complet
    ├── 01_create_topology.yml # Création de la topologie
    └── 02_verify.yml          # Vérification
```

### Topologie

```
                         ┌─────────────────┐
                         │      NAT1       │
                         │   (Internet)    │
                         └────────┬────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
              em0 (WAN)                   em0 (WAN)
           ┌────────┴────────┐       ┌────────┴────────┐
           │   pfSense-A     │       │   pfSense-B     │
           │  WAN: DHCP      │       │  WAN: DHCP      │
           │  LAN: 192.168.1.1│      │  LAN: 192.168.2.1│
           │                 │       │                 │
           │  ┌───────────┐  │       │  ┌───────────┐  │
           │  │ WireGuard │◄─┼───────┼─►│ WireGuard │  │
           │  │  Tunnel   │  │  VPN  │  │  Tunnel   │  │
           │  └───────────┘  │       │  └───────────┘  │
           └────────┬────────┘       └────────┬────────┘
              em1 (LAN)                  em1 (LAN)
                    │                           │
           ┌────────┴────────┐       ┌────────┴────────┐
           │   webterm-A     │       │   webterm-B     │
           │  192.168.1.x    │       │  192.168.2.x    │
           │    (DHCP)       │       │    (DHCP)       │
           └─────────────────┘       └─────────────────┘

                 SITE A                    SITE B
            192.168.1.0/24            192.168.2.0/24
```

### Plan d'adressage

| Site | Device | Interface | Adresse IP | Rôle |
|------|--------|-----------|------------|------|
| - | NAT1 | nat0 | DHCP (host) | Accès Internet |
| A | pfSense-A | em0 (WAN) | DHCP via NAT | Interface externe |
| A | pfSense-A | em1 (LAN) | 192.168.1.1/24 | Gateway Site A |
| A | webterm-A | eth0 | 192.168.1.x (DHCP) | Client Site A |
| B | pfSense-B | em0 (WAN) | DHCP via NAT | Interface externe |
| B | pfSense-B | em1 (LAN) | 192.168.2.1/24 | Gateway Site B |
| B | webterm-B | eth0 | 192.168.2.x (DHCP) | Client Site B |

### Configuration WireGuard prévue

| Paramètre | pfSense-A | pfSense-B |
|-----------|-----------|-----------|
| Tunnel Address | 10.10.10.1/24 | 10.10.10.2/24 |
| Listen Port | 51820 | 51820 |
| Allowed IPs | 10.10.10.0/24, 192.168.2.0/24 | 10.10.10.0/24, 192.168.1.0/24 |

---

## Démarrage rapide

```bash
cd 41_wireguard_vpn

# Déploiement complet
ansible-playbook playbooks/00_full_lab.yml
```

**Note**: Les playbooks créent la topologie. La configuration WireGuard se fait manuellement via l'interface web pfSense.

---

## Configuration WireGuard

### Étape 1: Accéder aux interfaces web

Après démarrage des nodes (attendre 2-3 minutes) :

- **pfSense-A** : `https://192.168.1.1` (depuis webterm-A)
- **pfSense-B** : `https://192.168.2.1` (depuis webterm-B)

Credentials : `admin` / `pfsense`

### Étape 2: Débloquer les réseaux privés sur WAN

**IMPORTANT** : Sur chaque pfSense, désactiver le blocage des réseaux privés sur l'interface WAN.

1. Aller dans **Interfaces → WAN**
2. Décocher **Block private networks and loopback addresses**
3. Décocher **Block bogon networks**
4. Cliquer **Save** puis **Apply Changes**

### Étape 3: Installer le package WireGuard

Sur chaque pfSense :

1. Aller dans **System → Package Manager → Available Packages**
2. Rechercher **WireGuard**
3. Cliquer **Install** et confirmer
4. Attendre la fin de l'installation

### Étape 4: Récupérer les IPs WAN

Aller dans **Status → Interfaces** sur chaque pfSense et noter l'IP WAN :

| pfSense | IP WAN (exemple) |
|---------|------------------|
| pfSense-A | 192.168.122.x |
| pfSense-B | 192.168.122.y |

### Étape 5: Configurer WireGuard sur pfSense-A

#### 5.1 Créer le tunnel

1. Aller dans **VPN → WireGuard → Tunnels**
2. Cliquer **Add Tunnel**
3. Configurer :
   - **Description** : `Site-to-Site-A`
   - **Listen Port** : `51820`
   - **Interface Addresses** : `10.10.10.1/24`
4. Cliquer **Generate** pour créer les clés
5. **COPIER LA CLÉ PUBLIQUE** (nécessaire pour pfSense-B)
6. Cliquer **Save** puis **Apply Changes**

#### 5.2 Ajouter le peer (pfSense-B)

1. Aller dans **VPN → WireGuard → Peers**
2. Cliquer **Add Peer**
3. Configurer :
   - **Tunnel** : Sélectionner `tun_wg0`
   - **Description** : `pfSense-B`
   - **Public Key** : Coller la clé publique de pfSense-B
   - **Allowed IPs** : `10.10.10.2/32, 192.168.2.0/24`
   - **Endpoint** : `<IP_WAN_PFSENSE_B>:51820`
   - **Keep Alive** : `25`
4. Cliquer **Save** puis **Apply Changes**

### Étape 6: Configurer WireGuard sur pfSense-B

#### 6.1 Créer le tunnel

1. Aller dans **VPN → WireGuard → Tunnels**
2. Cliquer **Add Tunnel**
3. Configurer :
   - **Description** : `Site-to-Site-B`
   - **Listen Port** : `51820`
   - **Interface Addresses** : `10.10.10.2/24`
4. Cliquer **Generate** pour créer les clés
5. **COPIER LA CLÉ PUBLIQUE** (nécessaire pour pfSense-A)
6. Cliquer **Save** puis **Apply Changes**

#### 6.2 Ajouter le peer (pfSense-A)

1. Aller dans **VPN → WireGuard → Peers**
2. Cliquer **Add Peer**
3. Configurer :
   - **Tunnel** : Sélectionner `tun_wg0`
   - **Description** : `pfSense-A`
   - **Public Key** : Coller la clé publique de pfSense-A
   - **Allowed IPs** : `10.10.10.1/32, 192.168.1.0/24`
   - **Endpoint** : `<IP_WAN_PFSENSE_A>:51820`
   - **Keep Alive** : `25`
4. Cliquer **Save** puis **Apply Changes**

### Étape 7: Assigner l'interface WireGuard

Sur chaque pfSense :

1. Aller dans **Interfaces → Assignments**
2. Ajouter `tun_wg0` comme nouvelle interface
3. Cliquer sur le nom de l'interface (ex: OPT1)
4. Cocher **Enable Interface**
5. Renommer en **WG_VPN**
6. Cliquer **Save** puis **Apply Changes**

### Étape 8: Configurer les règles Firewall

#### Sur pfSense-A :

**Règle WAN (autoriser WireGuard)** :
1. **Firewall → Rules → WAN**
2. Ajouter une règle :
   - Action: **Pass**
   - Protocol: **UDP**
   - Destination Port: **51820**
   - Description: `Allow WireGuard`

**Règle WG_VPN (autoriser le trafic tunnel)** :
1. **Firewall → Rules → WG_VPN**
2. Ajouter une règle :
   - Action: **Pass**
   - Protocol: **Any**
   - Source: **any**
   - Destination: **any**
   - Description: `Allow all VPN traffic`

#### Sur pfSense-B :

Répéter les mêmes règles.

### Étape 9: Ajouter les routes statiques (optionnel)

Si le routage automatique ne fonctionne pas :

**Sur pfSense-A** :
1. **System → Routing → Static Routes**
2. Ajouter :
   - Destination: `192.168.2.0/24`
   - Gateway: `WG_VPN - 10.10.10.2`

**Sur pfSense-B** :
1. **System → Routing → Static Routes**
2. Ajouter :
   - Destination: `192.168.1.0/24`
   - Gateway: `WG_VPN - 10.10.10.1`

---

## Vérification

### Vérifier le statut du tunnel

Sur chaque pfSense :
1. Aller dans **VPN → WireGuard → Status**
2. Développer **Tunnel Information**
3. Vérifier que le peer est connecté (Handshake récent)

### Tester la connectivité

Depuis **webterm-A** :
```bash
# Ping le tunnel
ping 10.10.10.2

# Ping le LAN de Site B
ping 192.168.2.1

# Ping un client de Site B (si webterm-B a une IP)
ping 192.168.2.x
```

Depuis **webterm-B** :
```bash
# Ping le tunnel
ping 10.10.10.1

# Ping le LAN de Site A
ping 192.168.1.1
```

### Résultat attendu

```
VPN → WireGuard → Status

Tunnel: tun_wg0 (Site-to-Site)
├── Interface Address: 10.10.10.1/24
├── Public Key: xxxxx
├── Listen Port: 51820
└── Peer: pfSense-B
    ├── Public Key: yyyyy
    ├── Endpoint: 192.168.122.x:51820
    ├── Allowed IPs: 10.10.10.2/32, 192.168.2.0/24
    ├── Latest Handshake: X seconds ago  ✓
    └── Transfer: X MB received, Y MB sent
```

---

## Troubleshooting

### Le tunnel ne s'établit pas

1. **Vérifier les IPs WAN** : `Status → Interfaces`
2. **Vérifier que UDP 51820 est autorisé** sur le WAN
3. **Vérifier les clés publiques** : bien copiées de chaque côté ?
4. **Vérifier les Endpoints** : IP WAN correctes ?

### Pas de handshake

1. Vérifier que **Block private networks** est décoché sur WAN
2. Tester la connectivité WAN : `Diagnostics → Ping` vers l'autre pfSense WAN IP

### Ping tunnel OK mais pas le LAN distant

1. Vérifier les **Allowed IPs** incluent le réseau distant
2. Vérifier les **règles firewall** sur l'interface WG_VPN
3. Ajouter une **route statique** si nécessaire

### Erreur "No buffer space available"

Redémarrer le service WireGuard : `Status → Services → wireguard → Restart`

---

## Concepts clés

### WireGuard vs OpenVPN/IPsec

| Critère | WireGuard | OpenVPN | IPsec |
|---------|-----------|---------|-------|
| Performance | Très rapide | Moyen | Rapide |
| Configuration | Simple | Complexe | Très complexe |
| Code | ~4000 lignes | ~100000 lignes | Énorme |
| Cryptographie | Moderne (ChaCha20) | Configurable | Configurable |
| État | Stateless | Stateful | Stateful |

### Clés WireGuard

- **Clé privée** : Reste secrète sur chaque pfSense
- **Clé publique** : Partagée avec le peer distant
- **Preshared Key** (optionnel) : Couche supplémentaire de sécurité

### Allowed IPs

Définit quels réseaux peuvent transiter par le tunnel :
- `10.10.10.0/24` : Réseau du tunnel
- `192.168.x.0/24` : Réseau LAN distant

---

## Références

- [WireGuard Official](https://www.wireguard.com/)
- [pfSense WireGuard Documentation](https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/index.html)
- [WireGuard Cryptography](https://www.wireguard.com/protocol/)
