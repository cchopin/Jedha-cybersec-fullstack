# Lab ARP et Switching Fundamentals - Automatisation Ansible

Ce projet automatise le lab GNS3 du cours "ARP and Switching Fundamentals" avec Ansible.

## Table des matières

1. [Prérequis](#prérequis)
2. [Architecture](#architecture)
3. [Démarrage rapide](#démarrage-rapide)
4. [Exercices](#exercices)
5. [Commandes de référence](#commandes-de-référence)
6. [Documentation officielle](#documentation-officielle)

---

## Prérequis

- **Ansible** installé (`brew install ansible`)
- **Python 3**
- **Client GNS3** connecté au serveur distant
- Accès réseau au serveur GNS3 (192.168.139.14:80)

## Architecture

```
ansible/
├── ansible.cfg                # Config Ansible (inventaire par défaut)
├── inventory.yml              # Configuration de connexion GNS3
├── group_vars/
│   └── all.yml                # Variables globales (VLANs, IPs, switches)
├── site.yml                   # Playbook setup (topologie + config)
├── playbooks/
│   ├── 00_full_lab.yml        # MASTER: Lance tout le lab en 1 commande
│   ├── 01_create_topology.yml # Crée un NOUVEAU projet GNS3 + topologie
│   ├── 02_configure_switches.yml # Configuration VLANs/Trunk/IPs
│   ├── 03_arp_exercise.yml    # Exercices ARP
│   ├── 04_mac_table.yml       # Exercice table MAC
│   ├── 05_troubleshooting.yml # Exercice troubleshooting
│   └── 06_verification.yml    # Commandes de diagnostic
├── scripts/
│   ├── configure_switch.py    # Script config initiale
│   └── cisco_cli.py           # CLI générique Cisco
└── switch_info.yml            # Généré automatiquement (project_id, ports console)
```

### Topologie créée

```
+-------+                    +-------+
|  SW1  | e0/0 ----trunk---- |  SW2  | e0/0
+-------+                    +-------+
   │                            │
   ├── VLAN 10: 192.168.10.1    ├── VLAN 10: 192.168.10.2
   ├── VLAN 20: 192.168.20.1    ├── VLAN 20: 192.168.20.2
   └── VLAN 30: 192.168.30.1    └── VLAN 30: 192.168.30.2
```

Les interfaces VLAN sont configurées avec des adresses IP pour permettre les tests ARP entre switches.

---

## Démarrage rapide

```bash
cd ansible

# OPTION 1: Lancer TOUT le lab en une commande (recommandé)
ansible-playbook playbooks/00_full_lab.yml

# OPTION 2: Setup + config seulement
ansible-playbook site.yml

# OPTION 3: Étape par étape
ansible-playbook playbooks/01_create_topology.yml    # Crée un nouveau projet GNS3
ansible-playbook playbooks/02_configure_switches.yml # Configure les switches
ansible-playbook playbooks/03_arp_exercise.yml       # Exercices ARP
ansible-playbook playbooks/04_mac_table.yml          # Exercices MAC
```

**Note** : L'inventaire est configuré par défaut dans `ansible.cfg`, pas besoin de `-i inventory.yml`.

Le playbook `01_create_topology.yml` crée automatiquement un **nouveau projet GNS3** nommé "Lab_ARP_Switching". Le `project_id` et les ports console sont sauvegardés dans `switch_info.yml`.

---

## Exercices

### Master Playbook : Tout en une commande

**Objectif** : Lancer tout le lab (création projet, config, tous les exercices).

```bash
# Lancer tout
ansible-playbook playbooks/00_full_lab.yml

# Ou avec des tags pour filtrer
ansible-playbook playbooks/00_full_lab.yml --tags "setup"        # Seulement création + config
ansible-playbook playbooks/00_full_lab.yml --tags "exercises"    # Seulement les exercices
ansible-playbook playbooks/00_full_lab.yml --skip-tags "troubleshoot"  # Tout sauf troubleshooting
```

**Tags disponibles** : `topology`, `config`, `setup`, `arp`, `mac`, `troubleshoot`, `verify`, `exercises`

---

### Exercice 1-2 : Topologie et Configuration de base

**Objectif** : Créer 2 switches, les connecter en trunk, configurer les VLANs et les interfaces VLAN avec IPs.

```bash
ansible-playbook playbooks/01_create_topology.yml
ansible-playbook playbooks/02_configure_switches.yml
```

**Ce qui est configuré** :
- VLANs 10 (USERS), 20 (SERVERS), 30 (MANAGEMENT)
- Trunk 802.1Q sur Ethernet0/0
- Interfaces VLAN avec IPs pour tests ARP

**Configuration Cisco équivalente** :
```
! Création des VLANs
vlan 10
 name USERS
vlan 20
 name SERVERS
vlan 30
 name MANAGEMENT

! Configuration du trunk
interface Ethernet0/0
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 switchport trunk native vlan 99

! Interfaces VLAN pour ARP
interface vlan 10
 ip address 192.168.10.1 255.255.255.0
 no shutdown
interface vlan 20
 ip address 192.168.20.1 255.255.255.0
 no shutdown
interface vlan 30
 ip address 192.168.30.1 255.255.255.0
 no shutdown
```

---

### Exercice 3 : ARP - Address Resolution Protocol

**Objectif** : Comprendre le fonctionnement du protocole ARP.

```bash
# Visualiser les tables ARP
ansible-playbook playbooks/03_arp_exercise.yml -e "exercise=view_arp"

# Générer du trafic ARP (ping) et observer
ansible-playbook playbooks/03_arp_exercise.yml -e "exercise=generate_arp"

# Vider la table ARP
ansible-playbook playbooks/03_arp_exercise.yml -e "exercise=clear_arp"

# Info sur le debug ARP
ansible-playbook playbooks/03_arp_exercise.yml -e "exercise=debug_arp"
```

**Processus ARP** :

```
1. PC1 veut communiquer avec PC2 (192.168.10.2)
   ↓
2. PC1 ne connaît pas la MAC de PC2
   ↓
3. PC1 envoie un ARP Request (broadcast):
   "Who has 192.168.10.2? Tell 192.168.10.1"
   ↓
4. PC2 répond avec un ARP Reply (unicast):
   "192.168.10.2 is at AA:BB:CC:DD:EE:FF"
   ↓
5. PC1 stocke cette info dans sa table ARP
```

**Commandes ARP Cisco** :
```
show ip arp                    ! Voir la table ARP
clear ip arp                   ! Vider le cache ARP
debug arp                      ! Debug en temps réel
undebug all                    ! Désactiver les debugs
```

**Commandes ARP Linux/Windows** :
```bash
# Linux moderne
ip neigh show                  # Voir la table ARP
sudo ip neigh flush all        # Vider le cache

# Linux/macOS
arp -a                         # Voir la table ARP

# Windows
arp -a                         # Voir la table ARP
netsh interface ip delete arpcache  # Vider le cache
```

---

### Exercice 4 : Table MAC et Logique de Switching

**Objectif** : Comprendre le fonctionnement des tables d'adresses MAC.

```bash
# Visualiser la table MAC
ansible-playbook playbooks/04_mac_table.yml -e "exercise=view_mac"

# Observer l'apprentissage MAC
ansible-playbook playbooks/04_mac_table.yml -e "exercise=learn_mac"

# Vider la table MAC
ansible-playbook playbooks/04_mac_table.yml -e "exercise=clear_mac"

# MAC Aging Timer
ansible-playbook playbooks/04_mac_table.yml -e "exercise=aging"
```

**Logique de Switching** :

| Action | Description |
|--------|-------------|
| **LEARN** | Le switch note la MAC source + port d'entrée |
| **FORWARD** | Si MAC destination connue → envoie sur le bon port |
| **FLOOD** | Si MAC destination inconnue → envoie sur tous les ports (sauf source) |
| **FILTER** | Si source = destination → ne transmet pas |

**Types d'entrées MAC** :

| Type | Description |
|------|-------------|
| DYNAMIC | Apprise automatiquement (expire après ~300s) |
| STATIC | Configurée manuellement (ne expire pas) |
| SECURE | Via port-security |

**Commandes MAC Cisco** :
```
show mac address-table              ! Table complète
show mac address-table dynamic      ! Entrées dynamiques seulement
show mac address-table count        ! Nombre d'entrées par VLAN
show mac address-table aging-time   ! Timer d'expiration
clear mac address-table dynamic     ! Vider les entrées dynamiques
```

---

### Exercice 5 : Troubleshooting

**Objectif** : Diagnostiquer et résoudre les problèmes courants ARP/Switching.

```bash
# Diagnostic complet
ansible-playbook playbooks/05_troubleshooting.yml -e "problem_type=diagnose"

# Résoudre entrées ARP obsolètes
ansible-playbook playbooks/05_troubleshooting.yml -e "problem_type=stale_arp"

# Info sur MAC Table Overflow
ansible-playbook playbooks/05_troubleshooting.yml -e "problem_type=mac_overflow_info"

# Info sur détection de boucle
ansible-playbook playbooks/05_troubleshooting.yml -e "problem_type=loop_detection"
```

**Problèmes courants et solutions** :

| Problème | Symptôme | Solution |
|----------|----------|----------|
| **Stale ARP** | Ping échoue puis fonctionne | `clear ip arp` |
| **ARP Spoofing** | MACs incohérentes dans table ARP | Dynamic ARP Inspection (DAI) |
| **MAC Overflow** | Traffic flood, sniffing possible | Port Security |
| **Network Loop** | CPU 100%, broadcast storm | Spanning Tree (STP) |
| **Port Err-disabled** | Port éteint | `shutdown` puis `no shutdown` |

---

### Exercice 6 : Commandes de vérification

**Objectif** : Maîtriser les commandes de diagnostic pour le CCNA.

```bash
ansible-playbook playbooks/06_verification.yml
```

**Commandes essentielles** :

| Commande | Utilité |
|----------|---------|
| `show ip arp` | Table ARP (IP ↔ MAC) |
| `show mac address-table` | Table MAC (MAC ↔ Port) |
| `show interfaces status` | État de tous les ports |
| `show interfaces trunk` | Trunks actifs et VLANs |
| `show spanning-tree` | État STP par VLAN |
| `show ip interface brief` | IPs des interfaces |
| `show vlan brief` | Liste des VLANs |

---

## Commandes de référence

### Accès console direct

```bash
telnet 192.168.139.14 5000   # SW1
telnet 192.168.139.14 5001   # SW2
```

### Script CLI personnalisé

```bash
# Voir la table ARP
python3 scripts/cisco_cli.py --host 192.168.139.14 --port 5000 --show "show ip arp"

# Voir la table MAC
python3 scripts/cisco_cli.py --host 192.168.139.14 --port 5000 --show "show mac address-table"

# Exécuter plusieurs commandes
python3 scripts/cisco_cli.py --host 192.168.139.14 --port 5000 \
  --commands "enable;show ip arp;show mac address-table"
```

---

## Documentation officielle

### GNS3

| Ressource | Lien |
|-----------|------|
| **API REST GNS3** | https://gns3-server.readthedocs.io/en/stable/api.html |
| **Endpoints API** | https://gns3-server.readthedocs.io/en/stable/endpoints.html |

### Ansible

| Ressource | Lien |
|-----------|------|
| **Module uri** | https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html |
| **Module script** | https://docs.ansible.com/ansible/latest/collections/ansible/builtin/script_module.html |

### Cisco - ARP

| Ressource | Lien |
|-----------|------|
| **ARP Configuration Guide** | https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_arp/configuration/15-mt/arp-15-mt-book.html |
| **How ARP Works** | https://www.cisco.com/c/en/us/support/docs/ip/dynamic-address-allocation/13718-5.html |
| **CCNA Exam Topics** | https://learningnetwork.cisco.com/s/ccna-exam-topics |

### Cisco - Switching

| Ressource | Lien |
|-----------|------|
| **MAC Address Table** | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/sys_mgmt/b_1612_sys_mgmt_9300_cg/configuring_mac_address_table.html |
| **Layer 2 Switching** | https://www.cisco.com/c/en/us/tech/lan-switching/ethernet-switching/index.html |

### Sécurité

| Ressource | Lien |
|-----------|------|
| **ARP Spoofing Prevention** | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-0SY/configuration/guide/15_0_sy_swcg/dynamic_arp_inspection.html |
| **Port Security** | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/sec/b_1612_sec_9300_cg/configuring_port_security.html |

---

## Troubleshooting

### Erreur "Connection refused"

Le switch n'est pas démarré. Dans GNS3 :
- Clic droit sur le switch → Start

### Erreur "No module named telnetlib"

Python 3.13+ a supprimé telnetlib. Les scripts utilisent des sockets bruts (compatible).

### Le ping ne fonctionne pas entre switches

1. Vérifier que les interfaces VLAN sont UP : `show ip interface brief`
2. Vérifier que les VLANs existent : `show vlan brief`
3. Vérifier le trunk : `show interfaces trunk`
4. Vérifier la table ARP : `show ip arp`

### La table ARP est vide

1. Générer du trafic : `ping 192.168.10.2`
2. Vérifier que les interfaces sont UP
3. Vérifier que les VLANs sont configurés des deux côtés

---

## Concepts clés pour le CCNA

### ARP (Address Resolution Protocol)

```
┌─────────────────────────────────────────────────────────────┐
│                    PROCESSUS ARP                            │
├─────────────────────────────────────────────────────────────┤
│  1. Besoin de communiquer avec 192.168.10.2                 │
│  2. Vérifie le cache ARP local → MAC inconnue               │
│  3. Envoie ARP Request (broadcast FF:FF:FF:FF:FF:FF)        │
│     "Who has 192.168.10.2? Tell 192.168.10.1"               │
│  4. 192.168.10.2 répond en unicast                          │
│     "192.168.10.2 is at AA:BB:CC:DD:EE:FF"                  │
│  5. Mise à jour du cache ARP                                │
│  6. Communication possible en Layer 2                       │
└─────────────────────────────────────────────────────────────┘
```

### Switching Logic

```
┌─────────────────────────────────────────────────────────────┐
│                  LOGIQUE DE SWITCHING                       │
├─────────────────────────────────────────────────────────────┤
│  TRAME REÇUE sur Port X                                     │
│           │                                                 │
│           ▼                                                 │
│  ┌────────────────────┐                                     │
│  │ LEARN: Noter       │                                     │
│  │ MAC Source → Port X│                                     │
│  └────────────────────┘                                     │
│           │                                                 │
│           ▼                                                 │
│  ┌────────────────────┐     ┌───────────────────┐          │
│  │ MAC Dest connue?   │ OUI │ FORWARD: Envoyer  │          │
│  │                    │────▶│ sur le port connu │          │
│  └────────────────────┘     └───────────────────┘          │
│           │ NON                                             │
│           ▼                                                 │
│  ┌────────────────────────────────────────┐                │
│  │ FLOOD: Envoyer sur tous les ports      │                │
│  │        (sauf le port source)           │                │
│  └────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```
