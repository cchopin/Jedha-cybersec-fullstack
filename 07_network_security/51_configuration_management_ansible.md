# Gestion de Configuration et Automatisation avec Ansible

## Objectifs du cours

À mesure que les réseaux deviennent plus grands, plus complexes et plus dynamiques, les gérer manuellement devient inefficace et source d'erreurs. C'est là que l'automatisation et les outils de sauvegarde de configuration viennent à la rescousse. Que vous essayiez de prévenir les erreurs de configuration réseau, de maintenir le contrôle de version, ou de déployer des politiques cohérentes sur des milliers d'équipements, cette session est votre rampe de lancement vers les pratiques de réseau modernes.

Dans cette session, nous explorerons :

- Comment Ansible permet l'automatisation réseau sans agent et scalable
- L'automatisation de tâches comme le push de configs, la vérification de conformité et la collecte de données en temps réel
- Pourquoi des outils comme RANCID et Oxidized restent essentiels pour les sauvegardes de configuration
- Le rôle du versioning de configuration, de l'audit et du suivi des changements
- Comment les outils d'automatisation et de backup s'intègrent dans le cycle de vie réseau global

---

## Glossaire

### Termes Ansible

| Terme | Description |
|-------|-------------|
| **Ansible** | Outil d'automatisation open-source sans agent |
| **Playbook** | Fichier YAML définissant les tâches à exécuter |
| **Module** | Code prédéfini exécutant une fonction spécifique |
| **Inventory** | Liste des équipements cibles |
| **Role** | Collection organisée de playbooks, tasks, templates |
| **Task** | Action unitaire à exécuter |
| **Handler** | Task déclenché par une notification |
| **Facts** | Informations collectées sur les équipements |

### Termes réseau

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **CLI** | Command Line Interface | Interface en ligne de commande |
| **SSH** | Secure Shell | Protocole d'accès sécurisé |
| **NETCONF** | Network Configuration Protocol | Protocole de configuration réseau (XML) |
| **RESTCONF** | REST Configuration Protocol | API REST pour configuration réseau |
| **IPAM** | IP Address Management | Gestion des adresses IP |

### Outils de Backup

| Outil | Description |
|-------|-------------|
| **RANCID** | Really Awesome New Cisco config Differ |
| **Oxidized** | Alternative moderne à RANCID |
| **NetBox** | Source of Truth pour IPAM et inventaire |
| **Git** | Système de contrôle de version |

---

## Le passage du manuel à l'automatisé

### Pourquoi la gestion manuelle échoue

Dans les environnements réseau traditionnels, les ingénieurs s'appuient généralement sur l'interface en ligne de commande (CLI) accessible via SSH ou ports console pour gérer les switches, routeurs et firewalls. Bien que cette approche puisse bien fonctionner pour des déploiements à petite échelle, elle devient rapidement insoutenable quand le réseau dépasse 10 ou 20 équipements.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GESTION MANUELLE : LES PROBLÈMES                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   100 SWITCHES À METTRE À JOUR                                               │
│   ────────────────────────────                                               │
│                                                                              │
│   [Admin] ──SSH──► [Switch 1] ──► Taper les commandes ──► 10 min             │
│           ──SSH──► [Switch 2] ──► Taper les commandes ──► 10 min             │
│           ──SSH──► [Switch 3] ──► Taper les commandes ──► 10 min             │
│           ...                                                                │
│           ──SSH──► [Switch 100] ──► Taper les commandes ──► 10 min           │
│                                                                              │
│   TEMPS TOTAL : 100 × 10 min = 16+ heures                                    │
│                                                                              │
│   PROBLÈMES :                                                                │
│   • Erreurs de frappe (typos) → pannes                                       │
│   • Configurations incohérentes entre équipements                            │
│   • Pas de traçabilité (qui a changé quoi ?)                                 │
│   • Impossible de vérifier la conformité                                     │
│   • Pas de rollback facile                                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Les limites de l'approche manuelle

| Problème | Impact |
|----------|--------|
| **Temps** | Heures/jours pour des changements simples |
| **Erreurs humaines** | Typos causant des pannes |
| **Incohérence** | Configurations différentes entre équipements |
| **Visibilité** | Difficile de savoir l'état actuel |
| **Audit** | Impossible de tracer qui/quand/quoi |
| **Conformité** | Vérification manuelle fastidieuse |

### L'Impératif de l'Automatisation

L'automatisation réseau adresse ces limitations en permettant des opérations **répétables**, **standardisées** et **rapides** à travers l'infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AVEC AUTOMATISATION (ANSIBLE)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   100 SWITCHES À METTRE À JOUR                                               │
│   ────────────────────────────                                               │
│                                                                              │
│   [Admin] ──► Écrit UN playbook ──► ansible-playbook deploy.yml              │
│                      │                                                       │
│                      │                                                       │
│                      ▼                                                       │
│              ┌───────────────┐                                               │
│              │    ANSIBLE    │                                               │
│              └───────┬───────┘                                               │
│                      │                                                       │
│         ┌────────────┼────────────┐                                          │
│         │            │            │                                          │
│         ▼            ▼            ▼                                          │
│   [Switch 1]  [Switch 2]  ... [Switch 100]                                   │
│                                                                              │
│   TEMPS TOTAL : ~5 minutes (en parallèle)                                    │
│                                                                              │
│   AVANTAGES :                                                                │
│   ✓ Même config sur tous les équipements                                     │
│   ✓ Traçabilité complète (playbook dans Git)                                 │
│   ✓ Idempotent (peut être rejoué sans risque)                                │
│   ✓ Rollback possible                                                        │
│   ✓ Vérification de conformité automatique                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Ansible pour l'automatisation réseau

### Qu'est-ce qu'Ansible ?

**Ansible** est un outil d'automatisation open-source développé par Red Hat, largement utilisé en administration système, DevOps, et maintenant en réseau. Il est **sans agent** (agentless), ce qui signifie qu'il ne nécessite pas d'installer de logiciel sur les équipements cibles.

Au lieu de cela, Ansible utilise **SSH** (ou des connexions API) pour interagir avec les équipements réseau, le rendant simple, scalable et sécurisé. Il utilise des **playbooks basés sur YAML** qui décrivent l'état désiré d'un équipement ou système dans un format lisible par l'humain.

### Pourquoi Ansible ?

| Caractéristique | Description |
|-----------------|-------------|
| **Sans agent** | Pas d'installation sur les équipements |
| **Basé sur SSH** | Utilise les accès existants |
| **YAML** | Syntaxe lisible et simple |
| **Modulaire** | Vaste écosystème de modules |
| **Vendor-agnostic** | Cisco, Juniper, Arista, F5, Palo Alto... |
| **Idempotent** | Peut être rejoué sans effets de bord |

### Composants principaux d'Ansible

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      COMPOSANTS ANSIBLE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. INVENTORY (inventaire des équipements)                                  │
│   ──────────────────────────────────────────                                 │
│                                                                              │
│   [switches]                                                                 │
│   SW1 ansible_host=192.168.0.1                                               │
│   SW2 ansible_host=192.168.0.2                                               │
│                                                                              │
│   [switches:vars]                                                            │
│   ansible_user=admin                                                         │
│   ansible_password=secret                                                    │
│   ansible_network_os=ios                                                     │
│                                                                              │
│   2. PLAYBOOK (les instructions)                                             │
│   ──────────────────────────────                                             │
│                                                                              │
│   - name: Configure switches                                                 │
│     hosts: switches                                                          │
│     tasks:                                                                   │
│       - name: Set hostname                                                   │
│         ios_config:                                                          │
│           lines:                                                             │
│             - hostname {{ inventory_hostname }}                              │
│                                                                              │
│   3. MODULES (les actions)                                                   │
│   ────────────────────────                                                   │
│                                                                              │
│   ios_config    → Configurer un équipement Cisco IOS                         │
│   ios_facts     → Collecter des infos sur l'équipement                       │
│   ios_command   → Exécuter une commande show                                 │
│                                                                              │
│   4. ROLES (organisation avancée)                                            │
│   ───────────────────────────────                                            │
│                                                                              │
│   roles/                                                                     │
│   └── vlan_config/                                                           │
│       ├── tasks/main.yml                                                     │
│       ├── templates/                                                         │
│       └── vars/main.yml                                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Modules vendor-spécifiques

Ansible inclut des modules dédiés pour les principaux vendeurs réseau :

| Vendeur | Modules principaux |
|---------|-------------------|
| **Cisco IOS** | `ios_config`, `ios_facts`, `ios_command` |
| **Cisco NX-OS** | `nxos_config`, `nxos_vlan`, `nxos_interface` |
| **Juniper** | `junos_config`, `junos_rpc`, `junos_facts` |
| **Arista** | `eos_config`, `eos_facts`, `eos_vlan` |
| **Palo Alto** | `panos_security_rule`, `panos_address_object` |
| **F5** | `bigip_pool`, `bigip_virtual_server` |

Les modules gèrent toute la syntaxe spécifique à l'équipement et fournissent l'**idempotence** : vous pouvez rejouer les playbooks en toute sécurité sans causer de changements en double.

---

## Ce que vous pouvez faire avec Ansible

### 1. Pousser des configurations

```yaml
# Créer des VLANs sur tous les switches
- name: Configure VLANs
  hosts: switches
  gather_facts: no

  tasks:
    - name: Create VLAN 10 Marketing
      ios_config:
        lines:
          - vlan 10
          - name Marketing

    - name: Create VLAN 20 Finance
      ios_config:
        lines:
          - vlan 20
          - name Finance
```

### 2. Collecter des Facts (Informations)

```yaml
# Collecter l'état des interfaces
- name: Gather network facts
  hosts: all_devices
  gather_facts: no

  tasks:
    - name: Get device facts
      ios_facts:
        gather_subset:
          - interfaces
      register: device_facts

    - name: Display interfaces
      debug:
        var: device_facts.ansible_facts.ansible_net_interfaces
```

### 3. Vérifier la Conformité

```yaml
# Vérifier que NTP est configuré correctement
- name: Compliance check
  hosts: switches
  gather_facts: no

  tasks:
    - name: Check NTP configuration
      ios_command:
        commands:
          - show running-config | include ntp
      register: ntp_config

    - name: Fail if NTP not configured
      fail:
        msg: "NTP is not configured on {{ inventory_hostname }}"
      when: "'ntp server' not in ntp_config.stdout[0]"
```

### 4. Provisionner de Nouveaux Équipements

```yaml
# Configuration initiale d'un nouveau switch
- name: Initial switch setup
  hosts: new_switches
  gather_facts: no

  tasks:
    - name: Set hostname
      ios_config:
        lines:
          - hostname {{ inventory_hostname }}

    - name: Configure management interface
      ios_config:
        lines:
          - ip address {{ mgmt_ip }} 255.255.255.0
        parents: interface Vlan1

    - name: Enable SSH
      ios_config:
        lines:
          - transport input ssh
        parents: line vty 0 4

    - name: Save configuration
      ios_command:
        commands:
          - write memory
```

### Tableau récapitulatif des cas d'usage

| Cas d'usage | Description | Module typique |
|-------------|-------------|----------------|
| **Push config** | VLANs, ACLs, interfaces | `ios_config` |
| **Gather facts** | Inventaire, état interfaces | `ios_facts` |
| **Compliance** | Vérifier configs vs standard | `ios_command` + assertions |
| **Provisioning** | Setup initial nouveaux équipements | `ios_config` |
| **Backup** | Sauvegarder running-config | `ios_command` |
| **Firmware** | Mise à jour d'images | `ios_command` + copy |

---

## Lab pratique : Ansible avec GNS3

### Architecture du Lab

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LAB ANSIBLE + GNS3                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────┐              ┌─────────────────┐                       │
│   │  Network Auto   │              │   Cisco IOU     │                       │
│   │    Docker       │◄────SSH─────►│    Switch       │                       │
│   │                 │              │                 │                       │
│   │  192.168.0.2    │              │  192.168.0.1    │                       │
│   │                 │              │                 │                       │
│   │  Ansible        │              │  SW1            │                       │
│   └─────────────────┘              └─────────────────┘                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Étape 1 : Configuration du Switch

```cisco
! Configuration initiale du switch pour Ansible
Switch# configure terminal
Switch(config)# hostname SW1
Switch(config)# username ansible privilege 15 secret ansible123
Switch(config)# line vty 0 4
Switch(config-line)# login local
Switch(config-line)# transport input ssh
Switch(config-line)# exit
Switch(config)# ip domain-name gns3.local
Switch(config)# crypto key generate rsa
! Choisir 2048 bits
Switch(config)# interface vlan1
Switch(config-if)# ip address 192.168.0.1 255.255.255.0
Switch(config-if)# no shutdown
Switch(config-if)# exit
Switch(config)# ip default-gateway 192.168.0.2
Switch(config)# exit
Switch# copy running-config startup-config
```

### Étape 2 : Créer l'Inventaire Ansible

```yaml
# inventory.yml
[switches]
SW1 ansible_host=192.168.0.1

[switches:vars]
ansible_user=ansible
ansible_password=ansible123
ansible_network_os=ios
ansible_connection=network_cli
```

### Étape 3 : Créer le Playbook

```yaml
# playbook.yml
- name: Configure Cisco Switch
  hosts: switches
  gather_facts: no

  tasks:
    - name: Set hostname
      ios_config:
        lines:
          - hostname SW1

    - name: Create VLAN 10 Marketing
      ios_config:
        lines:
          - vlan 10
          - name Marketing

    - name: Create VLAN 20 Finance
      ios_config:
        lines:
          - vlan 20
          - name Finance

    - name: Create VLAN 30 Engineering
      ios_config:
        lines:
          - vlan 30
          - name Engineering

    - name: Configure interface Ethernet0/1
      ios_config:
        lines:
          - interface ethernet0/1
          - switchport mode access
          - switchport access vlan 10
```

### Étape 4 : Exécuter le Playbook

```bash
# Lancer le playbook
ansible-playbook -i inventory.yml playbook.yml

# Résultat attendu :
# PLAY [Configure Cisco Switch] ****
# TASK [Set hostname] ****
# changed: [SW1]
# TASK [Create VLAN 10 Marketing] ****
# changed: [SW1]
# ...
# PLAY RECAP ****
# SW1 : ok=5 changed=5 unreachable=0 failed=0
```

### Étape 5 : Vérifier sur le Switch

```cisco
SW1# show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Et0/0, Et0/2, Et0/3
10   Marketing                        active    Et0/1
20   Finance                          active
30   Engineering                      active
```

---

## Outils de Backup : RANCID et Oxidized

### Pourquoi des Outils de Backup ?

Même avec Ansible, il est crucial d'avoir un historique des configurations :
- **Audit** : Qui a changé quoi, quand ?
- **Rollback** : Revenir à une version précédente
- **Compliance** : Prouver l'état à un instant T
- **Troubleshooting** : Comparer avant/après un incident

### RANCID vs Oxidized

| Aspect | RANCID | Oxidized |
|--------|--------|----------|
| **Âge** | Ancien (1998) | Moderne (2014) |
| **Langage** | Perl/Expect | Ruby |
| **Interface** | CLI + Email | Web + REST API |
| **Git natif** | Via CVS/SVN | Oui |
| **Performance** | Lent | Rapide (parallèle) |
| **Support vendors** | Large | Très large |

### Workflow GitOps avec Ansible + Oxidized

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WORKFLOW GITOPS RÉSEAU                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. DÉTECTION DES CHANGEMENTS (Oxidized)                                    │
│   ───────────────────────────────────────                                    │
│                                                                              │
│   [Oxidized] ──SSH──► [Équipements] ──► Backup configs ──► [Git]             │
│                                              │                               │
│                                              ▼                               │
│                                    Détection de diff ?                       │
│                                              │                               │
│                              ┌───────────────┴───────────────┐               │
│                              │                               │               │
│                           OUI                              NON               │
│                              │                               │               │
│                              ▼                               │               │
│                      Commit + Alerte                    Rien à faire         │
│                                                                              │
│   2. CORRECTION AUTOMATIQUE (Ansible)                                        │
│   ────────────────────────────────────                                       │
│                                                                              │
│   [Ansible] ──► Compare config actuelle vs baseline                          │
│                      │                                                       │
│                      ▼                                                       │
│               Drift détecté ?                                                │
│                      │                                                       │
│           ┌──────────┴──────────┐                                            │
│           │                     │                                            │
│         OUI                   NON                                            │
│           │                     │                                            │
│           ▼                     │                                            │
│   Corriger automatiquement     OK                                            │
│   ou alerter l'admin                                                         │
│                                                                              │
│   3. RÉSULTAT : Intent-Based Networking                                      │
│   ──────────────────────────────────────                                     │
│                                                                              │
│   • Le réseau se comporte comme prévu (intent)                               │
│   • Tout changement est tracé dans Git                                       │
│   • Les dérives sont détectées et corrigées automatiquement                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Intégration avec les systèmes de gestion

### NetBox comme Source of Truth

**NetBox** fournit un inventaire centralisé et fiable :
- Inventaire des équipements en temps réel
- IPAM (gestion des adresses IP)
- Topologie et connexions
- Ansible peut interroger NetBox dynamiquement

```yaml
# Utiliser NetBox comme inventaire dynamique
# ansible.cfg
[defaults]
inventory = netbox_inventory.yml

# netbox_inventory.yml
plugin: netbox.netbox.nb_inventory
api_endpoint: https://netbox.example.com
token: your_api_token
```

### Git pour le Versioning

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STRUCTURE GIT RECOMMANDÉE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   network-automation/                                                        │
│   ├── inventory/                                                             │
│   │   ├── production.yml                                                     │
│   │   └── staging.yml                                                        │
│   ├── playbooks/                                                             │
│   │   ├── vlan_deploy.yml                                                    │
│   │   ├── acl_deploy.yml                                                     │
│   │   └── compliance_check.yml                                               │
│   ├── roles/                                                                 │
│   │   ├── base_config/                                                       │
│   │   └── vlan_config/                                                       │
│   ├── configs/                   ← Backups Oxidized                          │
│   │   ├── SW1.cfg                                                            │
│   │   └── SW2.cfg                                                            │
│   └── README.md                                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CI/CD Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - lint
  - test
  - deploy

lint:
  stage: lint
  script:
    - ansible-lint playbooks/*.yml

test:
  stage: test
  script:
    - ansible-playbook --check playbooks/vlan_deploy.yml

deploy:
  stage: deploy
  script:
    - ansible-playbook playbooks/vlan_deploy.yml
  when: manual
  only:
    - main
```

---

## Synthèse : automatisation réseau

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ÉCOSYSTÈME D'AUTOMATISATION RÉSEAU                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                    │
│   │   NetBox    │     │     Git     │     │   CI/CD     │                    │
│   │  (Source of │◄───►│ (Versioning)│◄───►│ (Pipeline)  │                    │
│   │   Truth)    │     │             │     │             │                    │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                    │
│          │                   │                   │                           │
│          └───────────────────┼───────────────────┘                           │
│                              │                                               │
│                              ▼                                               │
│                    ┌─────────────────┐                                       │
│                    │     ANSIBLE     │                                       │
│                    │  (Orchestration)│                                       │
│                    └────────┬────────┘                                       │
│                             │                                                │
│              ┌──────────────┼──────────────┐                                 │
│              │              │              │                                 │
│              ▼              ▼              ▼                                 │
│         [Switches]    [Routers]    [Firewalls]                               │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                    ┌─────────────────┐                                       │
│                    │    OXIDIZED     │                                       │
│                    │   (Backup)      │──────► Git                            │
│                    └─────────────────┘                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Ressources

- [Ansible for Network Automation Docs](https://docs.ansible.com/ansible/latest/network/index.html)
- [Oxidized GitHub](https://github.com/ytti/oxidized)
- [NetBox Documentation](https://docs.netbox.dev/)
- [GitOps and Network Automation](https://www.redhat.com/en/topics/devops/what-is-gitops)
