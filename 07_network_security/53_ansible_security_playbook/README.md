# Lab 53: Ansible Security Playbook

Création d'un playbook Ansible pour appliquer automatiquement une configuration de sécurité de base sur un switch Cisco IOU L2 dans GNS3.

**Durée estimée** : 135 minutes

**Niveau** : Exercice final du module Network Security - Aucune assistance fournie.

---

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Configuration requise via Ansible](#configuration-requise-via-ansible)
6. [Critères de validation](#critères-de-validation)
7. [Indices](#indices)
8. [Dépannage](#dépannage)

---

## Objectifs

- Créer un playbook Ansible fonctionnel pour configurer un switch Cisco
- Automatiser la création de VLANs et l'attribution de noms
- Configurer des SVIs (Switched Virtual Interfaces)
- Implémenter la sécurité des ports (port-security)
- Maîtriser l'interaction Ansible ↔ GNS3 ↔ Cisco IOS

---

## Prérequis

- GNS3 connecté au serveur distant (IP: voir `group_vars/all.yml`)
- Ansible installé (`brew install ansible` sur macOS)
- Python 3
- Appliances disponibles dans GNS3 :
  - Cisco IOU L2 (switch)
  - Conteneur Kali Linux (optionnel, pour tester)

---

## Architecture

### Structure du lab

```
53_ansible_security_playbook/
├── ansible.cfg                # Configuration Ansible
├── inventory.yml              # Inventaire GNS3
├── group_vars/
│   └── all.yml                # Variables de configuration
├── playbooks/
│   ├── 00_full_lab.yml        # Déploiement complet
│   ├── 01_create_topology.yml # Création de la topologie
│   ├── 02_configure_switch.yml # Configuration sécurité (À COMPLÉTER)
│   └── 03_verify.yml          # Vérification
├── scripts/
│   └── cisco_cli.py           # Script de configuration Cisco
├── switch_info.yml            # Généré automatiquement
├── README.md
└── SOLUTION.md                # Solution complète
```

### Topologie réseau

```
                    ┌─────────────────┐
                    │      NAT1       │
                    │   (Internet)    │
                    │  192.168.122.1  │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │       SW1       │
                    │  (Cisco IOU L2) │
                    │                 │
                    │  VLAN 50 SVI:   │
                    │  192.168.50.2   │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │      Kali       │
                    │   (Ansible)     │
                    │      DHCP       │
                    └─────────────────┘
```

### Plan d'adressage VLANs

| VLAN ID | Nom | Usage | SVI Active |
|---------|-----|-------|------------|
| 10 | Engineering | Département technique | Non |
| 20 | HR | Ressources humaines | Non |
| 30 | Finance | Département financier | Non |
| 40 | Guest | Invités | Non |
| 50 | Management | Administration réseau | **Oui** (192.168.50.2/24) |

---

## Démarrage rapide

### 1. Vérifier la connexion au serveur GNS3

```bash
curl -s http://192.168.139.188:80/v2/version
```

### 2. Modifier l'IP si nécessaire

Éditer `group_vars/all.yml` si l'IP du serveur GNS3 a changé.

### 3. Déployer la topologie de base

```bash
cd 53_ansible_security_playbook
ansible-playbook playbooks/01_create_topology.yml
```

### 4. Compléter le playbook de configuration

Éditer `playbooks/02_configure_switch.yml` pour implémenter les exigences ci-dessous.

### 5. Exécuter et valider

```bash
ansible-playbook playbooks/02_configure_switch.yml
ansible-playbook playbooks/03_verify.yml
```

---

## Configuration requise via Ansible

Le playbook `02_configure_switch.yml` doit effectuer les tâches suivantes :

### 1. Création des VLANs

Créer les 5 VLANs suivants sur le switch Cisco IOU L2 :

| VLAN | Nom |
|------|-----|
| 10 | Engineering |
| 20 | HR |
| 30 | Finance |
| 40 | Guest |
| 50 | Management |

### 2. Configuration des SVIs

- **Désactiver** les interfaces VLAN (SVIs) pour les VLANs 10, 20, 30, 40
- **Activer** uniquement l'interface VLAN 50 avec :
  - Adresse IP : `192.168.50.2/24`
  - Description : `Ansible Management Interface`
  - État : `no shutdown`

### 3. Port Security sur les ports access

Configurer la sécurité des ports sur les interfaces Ethernet0/0 à Ethernet0/3 (VLANs 10-40) :

| Paramètre | Valeur |
|-----------|--------|
| Mode port | Access |
| Port-security | Activé |
| Maximum MAC | 1 |
| Violation | Restrict |
| Sticky MAC | Activé (optionnel mais recommandé) |

### 4. Sauvegarde

Sauvegarder la configuration avec `write memory`.

---

## Critères de validation

Exécuter `ansible-playbook playbooks/03_verify.yml` et vérifier :

- [ ] Les 5 VLANs sont créés avec les bons noms
- [ ] Seul VLAN 50 a une SVI active
- [ ] L'interface VLAN 50 a l'IP 192.168.50.2/24
- [ ] Port-security est activé sur les ports Ethernet0/0 à Ethernet0/3
- [ ] Maximum 1 adresse MAC autorisée par port
- [ ] Action violation = restrict
- [ ] Configuration sauvegardée

### Commandes de vérification manuelles

Depuis la console du switch :

```
show vlan brief
show ip interface brief
show interface vlan 50
show port-security
show port-security interface Ethernet0/0
show running-config
```

---

## Indices

<details>
<summary>Indice 1 : Structure du playbook</summary>

Le playbook doit utiliser le script `cisco_cli.py` pour envoyer des commandes au switch via sa console GNS3.

```yaml
- name: "Configurer le switch"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ switch_console_port }}
    --commands "{{ config_commands | join(';') }}"
```

</details>

<details>
<summary>Indice 2 : Commandes Cisco pour les VLANs</summary>

```
enable
configure terminal
vlan 10
  name Engineering
exit
vlan 20
  name HR
exit
...
```

</details>

<details>
<summary>Indice 3 : Commandes Cisco pour port-security</summary>

```
interface Ethernet0/0
  switchport mode access
  switchport access vlan 10
  switchport port-security
  switchport port-security maximum 1
  switchport port-security violation restrict
  switchport port-security mac-address sticky
  no shutdown
exit
```

</details>

<details>
<summary>Indice 4 : Désactiver une SVI</summary>

```
interface vlan 10
  shutdown
exit
```

</details>

<details>
<summary>Indice 5 : Configurer la SVI Management</summary>

```
interface vlan 50
  description Ansible Management Interface
  ip address 192.168.50.2 255.255.255.0
  no shutdown
exit
```

</details>

---

## Dépannage

### Le switch ne répond pas aux commandes

1. Vérifier que le switch est démarré dans GNS3
2. Attendre 60-90 secondes après le démarrage
3. Vérifier le port console dans `switch_info.yml`

### Erreur "Connection refused"

```bash
# Vérifier la connexion GNS3
curl http://192.168.139.188:80/v2/version

# Vérifier que le projet existe
curl http://192.168.139.188:80/v2/projects
```

### Port-security ne s'active pas

Le port-security nécessite que le port soit en mode access :

```
switchport mode access
switchport port-security
```

### La SVI ne prend pas l'IP

Vérifier que le VLAN existe avant de configurer la SVI :

```
show vlan brief
show ip interface brief
```

### Commandes ignorées

Les switches IOU peuvent être lents. Augmenter le `wait_time` dans le script ou ajouter des pauses.

---

## Références

- [Ansible Network Automation](https://docs.ansible.com/ansible/latest/network/index.html)
- [Cisco IOS Port Security](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/port_sec.html)
- [GNS3 API Documentation](https://gns3-server.readthedocs.io/en/latest/api.html)

---

## Solution

Une fois l'exercice terminé (ou en cas de blocage), consulter `SOLUTION.md` pour la solution complète.
