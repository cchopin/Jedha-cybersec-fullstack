# Lab 40: pfSense Setup - Firewall/Router Configuration

Ce lab vous permet de configurer un firewall/routeur **pfSense** dans GNS3 et d'accéder à son interface web depuis un conteneur Docker Webterm.

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Exercice pas à pas](#exercice-pas-à-pas)
6. [Configuration pfSense](#configuration-pfsense)
7. [Commandes de référence](#commandes-de-référence)
8. [Résultats attendus](#résultats-attendus)
9. [Troubleshooting](#troubleshooting)

---

## Objectifs

- Comprendre le rôle d'un firewall/routeur dans une architecture réseau
- Configurer les interfaces WAN et LAN de pfSense via la ligne de commande
- Accéder à l'interface web de pfSense depuis un client LAN
- Découvrir les fonctionnalités de base de pfSense (NAT, firewall, DHCP)

---

## Prérequis

- **GNS3** connecté au serveur distant (`192.168.144.120`)
- **Ansible** installé (`brew install ansible`)
- **Python 3**
- Appliance **pfSense** disponible dans GNS3
- Template **Docker Webterm** (Firefox) disponible dans GNS3

---

## Architecture

```
40_pfsense_setup/
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
                    ┌───────────────┐
                    │     NAT1      │  ← Accès Internet (DHCP)
                    │  (Internet)   │
                    └───────┬───────┘
                            │ nat0
                            │
                      em0 (WAN)
                    ┌───────┴───────┐
                    │   pfSense-1   │  ← Firewall/Routeur
                    │ WAN: DHCP     │     Interface web: https://192.168.1.1
                    │ LAN: .1.1     │
                    └───────┬───────┘
                      em1 (LAN)
                            │
                            │ eth0
                    ┌───────┴───────┐
                    │   webterm-1   │  ← Client (Docker Firefox)
                    │ 192.168.1.x   │     Pour accéder au GUI pfSense
                    │   (DHCP)      │
                    └───────────────┘
```

| Device | Interface | Adresse IP | Type | Rôle |
|--------|-----------|------------|------|------|
| NAT1 | nat0 | DHCP (host) | NAT Cloud | Accès Internet |
| pfSense-1 | em0 (WAN) | DHCP via NAT | Appliance | Interface externe |
| pfSense-1 | em1 (LAN) | 192.168.1.1 | Appliance | Interface interne (gateway) |
| webterm-1 | eth0 | 192.168.1.x (DHCP) | Docker Firefox | Client web |

---

## Démarrage rapide

```bash
cd 40_pfsense_setup

# Option 1: Déploiement complet en une commande
ansible-playbook playbooks/00_full_lab.yml

# Option 2: Étape par étape
ansible-playbook playbooks/01_create_topology.yml   # Créer la topologie
ansible-playbook playbooks/02_verify.yml            # Vérifier les nodes
```

**Note**: Les playbooks sont **idempotents** - vous pouvez les relancer sans erreur.

---

## Exercice pas à pas

### Étape 1: Déployer le lab

```bash
ansible-playbook playbooks/00_full_lab.yml
```

Le playbook va :
1. Créer un projet GNS3 nommé "Lab_40_pfSense_Setup"
2. Ajouter les nodes : pfSense, Webterm, NAT
3. Connecter les interfaces
4. Démarrer tous les équipements

### Étape 2: Attendre le boot de pfSense

pfSense prend environ **2-3 minutes** pour démarrer complètement. Connectez-vous à la console :

**Option 1 - Via GNS3 GUI (recommandé):**
- Clic droit sur **pfSense-1** → **Console**
- Une fenêtre VNC s'ouvrira

**Option 2 - Via VNC client:**
```bash
# Récupérer le port console depuis node_info.yml
cat node_info.yml

# Se connecter via un client VNC (port 5900)
# Sur macOS: open vnc://192.168.144.120:5900
# Ou utiliser un client VNC comme RealVNC, TigerVNC, etc.
```

Attendez de voir le menu principal pfSense :

```
*** Welcome to pfSense 2.x.x-RELEASE ***

 WAN (wan)       -> em0        -> v4/DHCP4: x.x.x.x/24
 LAN (lan)       -> em1        -> v4: 192.168.1.1/24

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart webConfigurator
 3) Reset webConfigurator password    12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Disable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

Enter an option:
```

### Étape 3: Vérifier la configuration des interfaces

Par défaut, pfSense devrait avoir :
- **WAN (em0)** : IP obtenue via DHCP depuis le NAT
- **LAN (em1)** : 192.168.1.1/24

Si les interfaces ne sont pas assignées correctement, utilisez l'option **1) Assign Interfaces** :

```
Enter an option: 1

Do you want to configure VLANs first? [y|n]: n

Enter the WAN interface name: em0
Enter the LAN interface name: em1

Do you want to proceed? [y|n]: y
```

### Étape 4: Configurer l'adresse IP LAN (si nécessaire)

Si l'IP LAN n'est pas 192.168.1.1, utilisez l'option **2) Set interface(s) IP address** :

```
Enter an option: 2

Available interfaces:
1 - WAN (em0 - dhcp)
2 - LAN (em1 - static)

Enter the number of the interface to configure: 2

Enter the new LAN IPv4 address: 192.168.1.1
Enter the new LAN IPv4 subnet bit count: 24

Do you want to enable the DHCP server on LAN? [y|n]: y
Enter the start address of the IPv4 client address range: 192.168.1.100
Enter the end address of the IPv4 client address range: 192.168.1.199

Do you want to revert to HTTP as the webConfigurator protocol? [y|n]: y
```

### Étape 5: Se connecter à Webterm

```bash
# Connexion VNC à webterm via le navigateur
# Ouvrez GNS3, clic droit sur webterm-1 -> Console
# Ou utilisez le port VNC affiché dans node_info.yml
```

Dans GNS3, faites un clic droit sur **webterm-1** et sélectionnez **Console**. Une fenêtre Firefox s'ouvrira.

### Étape 6: Obtenir une IP sur Webterm

Dans le terminal de webterm (ouvrez un terminal dans Firefox) :

```bash
# Vérifier si une IP a été obtenue via DHCP
ip addr show eth0

# Si pas d'IP, forcer le renouvellement DHCP
dhclient eth0

# Vérifier la gateway
ip route
```

### Étape 7: Accéder à l'interface web pfSense

Dans le navigateur Firefox de webterm, accédez à :

```
http://192.168.1.1
```

ou

```
https://192.168.1.1
```

**Identifiants par défaut :**
- Username: `admin`
- Password: `pfsense`

### Étape 8: Compléter l'assistant de configuration

L'assistant de configuration initiale vous guidera pour :
1. Configurer le hostname et le domaine
2. Configurer le serveur DNS
3. Vérifier la configuration WAN
4. Vérifier la configuration LAN
5. Changer le mot de passe admin

---

## Configuration pfSense

### Menu console pfSense

| Option | Description |
|--------|-------------|
| 1 | Assigner les interfaces (WAN, LAN, OPT) |
| 2 | Configurer les adresses IP des interfaces |
| 3 | Réinitialiser le mot de passe webConfigurator |
| 4 | Restaurer la configuration usine |
| 5 | Redémarrer le système |
| 6 | Arrêter le système |
| 7 | Ping un hôte |
| 8 | Accéder au shell |

### Interfaces pfSense

| Interface | Nom FreeBSD | Rôle | Configuration par défaut |
|-----------|-------------|------|--------------------------|
| WAN | em0 | Interface externe (Internet) | DHCP |
| LAN | em1 | Interface interne (réseau local) | 192.168.1.1/24 |

### Services pfSense par défaut

- **Firewall** : Bloque tout le trafic entrant WAN, autorise tout le trafic sortant LAN
- **NAT** : Translation d'adresses pour le trafic LAN -> WAN
- **DHCP Server** : Distribue des IPs aux clients LAN (192.168.1.100-199)
- **DNS Forwarder** : Relaye les requêtes DNS vers les serveurs configurés

---

## Commandes de référence

### Commandes console pfSense (option 8 - Shell)

```bash
# Voir la configuration des interfaces
ifconfig

# Voir la table de routage
netstat -rn

# Voir les règles firewall
pfctl -sr

# Voir les états NAT
pfctl -ss

# Redémarrer le service web
/etc/rc.restart_webgui

# Voir les logs
clog /var/log/filter.log
```

### Commandes Webterm

```bash
# Obtenir une IP via DHCP
dhclient eth0

# Vérifier l'IP
ip addr show eth0

# Tester la connectivité vers pfSense
ping 192.168.1.1

# Accéder au web GUI via curl (test)
curl -k https://192.168.1.1

# Accéder via lynx (navigateur texte)
lynx http://192.168.1.1
```

### Accès console GNS3

```bash
# Les ports sont affichés dans node_info.yml
cat node_info.yml

# Connexion telnet
telnet 192.168.144.120 <PORT>
```

---

## Résultats attendus

### Succès de l'exercice

Vous avez réussi l'exercice si :

1. **pfSense démarre correctement** avec WAN et LAN configurés
2. **Webterm obtient une IP** dans le range 192.168.1.100-199
3. **L'interface web pfSense est accessible** depuis Webterm
4. **L'assistant de configuration** s'affiche dans le navigateur

### Exemple de sortie sur pfSense

```
*** Welcome to pfSense 2.7.2-RELEASE ***

 WAN (wan)       -> em0        -> v4/DHCP4: 192.168.122.x/24
 LAN (lan)       -> em1        -> v4: 192.168.1.1/24

 0) Logout (SSH only)                  9) pfTop
 1) Assign Interfaces                 10) Filter Logs
...
```

### Exemple de sortie sur Webterm

```bash
$ ip addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0

$ ping -c 2 192.168.1.1
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.5 ms
```

---

## Troubleshooting

### pfSense ne démarre pas

1. Attendre 2-3 minutes (boot long)
2. Vérifier la console telnet
3. Si bloqué au boot, redémarrer le node dans GNS3

### Webterm n'obtient pas d'IP

1. Vérifier que pfSense est démarré et LAN configuré
2. Vérifier que le DHCP est activé sur pfSense (option 2)
3. Forcer le renouvellement : `dhclient eth0`

### Impossible d'accéder au web GUI

1. Vérifier l'IP de webterm : `ip addr show eth0`
2. Ping pfSense : `ping 192.168.1.1`
3. Essayer HTTP au lieu de HTTPS : `http://192.168.1.1`
4. Redémarrer le webConfigurator sur pfSense : option **11**

### Les interfaces ne sont pas assignées

Utiliser l'option **1) Assign Interfaces** dans le menu pfSense :
- WAN = em0
- LAN = em1

### DHCP ne fonctionne pas

1. Vérifier que le DHCP server est activé (option 2 sur pfSense)
2. Configurer manuellement une IP sur webterm :
   ```bash
   ip addr add 192.168.1.50/24 dev eth0
   ip route add default via 192.168.1.1
   ```

### Erreur SSL/TLS

Le certificat pfSense est auto-signé. Accepter l'exception de sécurité dans le navigateur ou utiliser HTTP :
```
http://192.168.1.1
```

---

## Concepts clés

### Qu'est-ce que pfSense ?

pfSense est une distribution FreeBSD open-source spécialisée dans les fonctions de :
- **Firewall** : Filtrage de paquets stateful
- **Routeur** : Routage entre réseaux
- **VPN** : OpenVPN, IPsec, WireGuard
- **Load Balancer** : Répartition de charge
- **Proxy** : Squid, HAProxy

### Architecture WAN/LAN

```
Internet ──► [WAN] pfSense [LAN] ──► Réseau interne
              │                         │
         IP publique              IP privée
         ou DHCP                  192.168.1.0/24
```

- **WAN** : Interface "non-fiable" exposée à Internet
- **LAN** : Interface "fiable" pour le réseau interne
- **NAT** : Traduit les IPs privées LAN en IP publique WAN

### Règles firewall par défaut

| Direction | Action | Description |
|-----------|--------|-------------|
| WAN → LAN | BLOCK | Tout le trafic entrant bloqué |
| LAN → WAN | ALLOW | Tout le trafic sortant autorisé |
| LAN → pfSense | ALLOW | Accès aux services (web, DNS, DHCP) |

---

## Pour aller plus loin

Après avoir complété cet exercice, vous pouvez explorer :

1. **Créer des règles firewall** personnalisées
2. **Configurer un VPN** OpenVPN ou IPsec
3. **Mettre en place des VLANs** pour segmenter le réseau
4. **Configurer le traffic shaping** pour la QoS
5. **Intégrer Snort/Suricata** pour l'IDS/IPS

---

## Références

- [Documentation officielle pfSense](https://docs.netgate.com/pfsense/en/latest/)
- [pfSense Book](https://docs.netgate.com/pfsense/en/latest/book/)
- [GNS3 pfSense Appliance](https://gns3.com/marketplace/appliances/pfsense)
