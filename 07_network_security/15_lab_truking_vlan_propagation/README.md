# Lab Trunking et VLAN Propagation - Automatisation Ansible

Ce projet automatise le lab GNS3 du cours "Trunking and VLAN Propagation" avec Ansible.

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
- Acces reseau au serveur GNS3 (192.168.156.183:80)

## Architecture

```
ansible/
├── inventory.yml              # Configuration de connexion
├── group_vars/
│   └── all.yml                # Variables globales (VLANs, switches)
├── site.yml                   # Playbook principal
├── playbooks/
│   ├── 01_create_topology.yml # Création topologie GNS3
│   ├── 02_configure_switches.yml # Configuration VLANs/Trunk
│   ├── 03_dtp_modes.yml       # Exercice DTP
│   ├── 04_troubleshooting.yml # Exercice troubleshooting
│   ├── 05_security.yml        # Exercice sécurisation
│   └── 06_verification.yml    # Commandes de diagnostic
├── scripts/
│   ├── configure_switch.py    # Script config initiale
│   └── cisco_cli.py           # CLI générique Cisco
└── switch_info.yml            # Généré automatiquement (ports console)
```

### Topologie créée

```
+-------+                    +-------+
|  SW1  | e0/0 ----trunk---- |  SW2  | e0/0
+-------+                    +-------+
   │                            │
   ├── VLAN 10 (VENTES)         ├── VLAN 10 (VENTES)
   ├── VLAN 20 (IT)             ├── VLAN 20 (IT)
   ├── VLAN 30 (DIRECTION)      ├── VLAN 30 (DIRECTION)
   └── VLAN 99 (NATIVE)         └── VLAN 99 (NATIVE)
```

---

## Démarrage rapide

```bash
cd ansible

# 1. Créer la topologie et configurer (tout en un)
ansible-playbook -i inventory.yml site.yml

# 2. Ou étape par étape
ansible-playbook -i inventory.yml playbooks/01_create_topology.yml
ansible-playbook -i inventory.yml playbooks/02_configure_switches.yml
```

---

## Exercices

### Exercice 1-2 : Topologie et Configuration de base

**Objectif** : Créer 2 switches, les connecter en trunk, configurer les VLANs.

```bash
ansible-playbook -i inventory.yml playbooks/01_create_topology.yml
ansible-playbook -i inventory.yml playbooks/02_configure_switches.yml
```

**Ce qui est configuré** :
- VLANs 10 (VENTES), 20 (IT), 30 (DIRECTION)
- Trunk 802.1Q sur Ethernet0/0
- Native VLAN 99

**Configuration Cisco équivalente** :
```
! Création des VLANs
vlan 10
 name VENTES
vlan 20
 name IT
vlan 30
 name DIRECTION

! Configuration du trunk
interface Ethernet0/0
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 switchport trunk native vlan 99
```

---

### Exercice 3 : Dynamic Trunking Protocol (DTP)

**Objectif** : Comprendre les modes DTP et leur négociation.

```bash
# Tester différents scénarios
ansible-playbook -i inventory.yml playbooks/03_dtp_modes.yml -e "scenario=trunk_trunk"
ansible-playbook -i inventory.yml playbooks/03_dtp_modes.yml -e "scenario=auto_auto"
ansible-playbook -i inventory.yml playbooks/03_dtp_modes.yml -e "scenario=auto_desirable"
```

**Matrice de négociation DTP** :

| SW1 \ SW2           | trunk  | access | dynamic auto | dynamic desirable |
|---------------------|--------|--------|--------------|-------------------|
| **trunk**           | TRUNK  | ❌     | TRUNK        | TRUNK             |
| **access**          | ❌     | ACCESS | ACCESS       | ACCESS            |
| **dynamic auto**    | TRUNK  | ACCESS | ACCESS       | TRUNK             |
| **dynamic desirable**| TRUNK | ACCESS | TRUNK        | TRUNK             |

**Commandes DTP** :
```
switchport mode trunk              ! Force trunk
switchport mode access             ! Force access
switchport mode dynamic auto       ! Passif
switchport mode dynamic desirable  ! Actif
switchport nonegotiate             ! Désactive DTP
```

---

### Exercice 4 : Troubleshooting

**Objectif** : Diagnostiquer et corriger les problèmes courants.

```bash
# Créer un problème de Native VLAN mismatch
ansible-playbook -i inventory.yml playbooks/04_troubleshooting.yml -e "problem_type=native_vlan_mismatch"

# Créer un problème de VLANs autorisés
ansible-playbook -i inventory.yml playbooks/04_troubleshooting.yml -e "problem_type=allowed_vlan_mismatch"

# Corriger tous les problèmes
ansible-playbook -i inventory.yml playbooks/04_troubleshooting.yml -e "problem_type=fix_all"
```

**Problèmes courants et diagnostic** :

| Problème | Symptôme | Commande diagnostic | Solution |
|----------|----------|---------------------|----------|
| Native VLAN mismatch | Traffic mal routé, erreurs CDP | `show interfaces trunk` | Aligner native VLAN des deux côtés |
| VLANs non autorisés | VLAN absent du trunk | `show interfaces trunk` | `switchport trunk allowed vlan add X` |
| DTP mismatch | Trunk non formé | `show dtp interface` | Forcer le mode trunk |

---

### Exercice 5 : Sécurisation des Trunk Ports

**Objectif** : Appliquer les best practices de sécurité.

```bash
ansible-playbook -i inventory.yml playbooks/05_security.yml
```

**Best practices appliquées** :

1. **Désactiver DTP** : `switchport nonegotiate`
2. **Native VLAN dédié** : Utiliser VLAN 999 (pas VLAN 1)
3. **Limiter les VLANs** : Seulement ceux nécessaires
4. **Mode trunk explicite** : Pas de négociation

**Menaces couvertes** :
- VLAN Hopping (double tagging attack)
- DTP Spoofing
- Propagation VLANs non autorisés

**Configuration sécurisée** :
```
interface Ethernet0/0
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport nonegotiate              ! Désactive DTP
 switchport trunk native vlan 999    ! Native VLAN isolé
 switchport trunk allowed vlan 10,20,30
```

---

### Exercice 6 : Commandes de vérification

**Objectif** : Maîtriser les commandes de diagnostic pour le CCNA.

```bash
ansible-playbook -i inventory.yml playbooks/06_verification.yml
```

**Commandes essentielles** :

| Commande | Utilité |
|----------|---------|
| `show vlan brief` | Liste tous les VLANs |
| `show interfaces trunk` | Trunks actifs, native VLAN, VLANs autorisés |
| `show interfaces <if> switchport` | Détails complets d'un port |
| `show dtp interface <if>` | État négociation DTP |
| `show spanning-tree` | État STP par VLAN |
| `show running-config interface <if>` | Configuration actuelle |

---

## Commandes de référence

### Accès console direct

```bash
# Voir switch_info.yml pour les ports console
telnet 192.168.156.183 <PORT_SW1>
telnet 192.168.156.183 <PORT_SW2>
```

### Script CLI personnalisé

```bash
# Exécuter une commande show
python3 scripts/cisco_cli.py --host 192.168.156.183 --port <PORT> --show "show vlan brief"

# Executer plusieurs commandes
python3 scripts/cisco_cli.py --host 192.168.156.183 --port <PORT> \
  --commands "enable;show interfaces trunk"
```

---

## Documentation officielle

### GNS3

| Ressource | Lien |
|-----------|------|
| **API REST GNS3** | https://gns3-server.readthedocs.io/en/stable/api.html |
| **Endpoints API** | https://gns3-server.readthedocs.io/en/stable/endpoints.html |
| **GNS3 Python Library** | https://github.com/GNS3/gns3-server |

### Ansible

| Ressource | Lien |
|-----------|------|
| **Module uri** | https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html |
| **Collection GNS3** | https://docs.ansible.com/ansible/latest/collections/community/general/gns3_project_module.html |
| **Module script** | https://docs.ansible.com/ansible/latest/collections/ansible/builtin/script_module.html |

### Cisco

| Ressource | Lien |
|-----------|------|
| **VLAN Configuration Guide** | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/vlan/b_1612_vlan_9300_cg.html |
| **DTP Overview** | https://www.cisco.com/c/en/us/support/docs/lan-switching/vtp/10558-21.html |
| **Trunk Configuration** | https://www.cisco.com/c/en/us/support/docs/lan-switching/8021q/24067-195.html |
| **CCNA Exam Topics** | https://learningnetwork.cisco.com/s/ccna-exam-topics |

### Sécurité

| Ressource | Lien |
|-----------|------|
| **VLAN Security Best Practices** | https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-0SY/configuration/guide/15_0_sy_swcg/vlan_security.html |
| **Layer 2 Security** | https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-6500-series-switches/white_paper_c11_603839.html |

---

## Troubleshooting

### Erreur "Connection refused"

Le switch n'est pas démarré. Dans GNS3 :
- Clic droit sur le switch → Start

### Erreur "No module named telnetlib"

Python 3.13+ a supprimé telnetlib. Les scripts utilisent des sockets bruts (compatible).

### Le trunk ne se forme pas

1. Vérifier l'encapsulation : `show interfaces trunk`
2. Vérifier le mode DTP : `show dtp interface e0/0`
3. Forcer le trunk des deux côtés : `switchport mode trunk`
