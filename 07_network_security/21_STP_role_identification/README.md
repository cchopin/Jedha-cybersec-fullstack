# Lab 21: STP Role Identification

## Objectif

Comprendre et identifier les rôles Spanning Tree Protocol (STP) dans une topologie en triangle.

## Topologie

```
           Switch1
          /       \
     Et0/0         Et0/1
        /           \
   Switch2 ------- Switch3
          Et0/1-Et0/0
```

- **3 switches IOU L2** connectés en triangle
- **3 VPCs** (un par switch, tous dans VLAN 10)
- **Liens trunk 802.1Q** entre les switches

## Prérequis

- GNS3 server accessible sur `192.168.156.183:80`
- Templates `Cisco IOU L2` et `VPCS` disponibles
- Ansible installé

## Utilisation

### Setup complet (recommandé)

```bash
cd /Users/cchopin/projets-git/jedha/07_network_security/21_STP_role_identification
ansible-playbook playbooks/00_full_lab.yml
```

### Execution étape par étape

```bash
# 1. Créer la topologie
ansible-playbook playbooks/01_create_topology.yml

# 2. Configurer VLANs et Trunks
ansible-playbook playbooks/02_configure_vlans.yml

# 3. Configurer les IPs des VPCs
ansible-playbook playbooks/03_configure_vpcs.yml

# 4. Vérifier STP
ansible-playbook playbooks/04_verify_stp.yml
```

## Exercices Pratiques

### 1. Identifier le Root Bridge

Sur chaque switch, exécuter:
```
show spanning-tree vlan 10
```

Le Root Bridge est le switch dont le Bridge ID apparaît comme "Root ID".

### 2. Identifier les rôles des ports

| Role | Description |
|------|-------------|
| Root Port | Meilleur chemin vers le Root Bridge |
| Designated Port | Forward le trafic sur un segment |
| Alternate/Blocked | Bloque pour éviter les boucles |

### 3. Forcer un Root Bridge

Pour forcer Switch1 comme Root Bridge:
```
Switch1# configure terminal
Switch1(config)# spanning-tree vlan 10 priority 4096
Switch1(config)# end
```

### 4. Observer les changéments

Apres avoir changé la priorité:
```
show spanning-tree vlan 10
```

### 5. Test de connectivité

Sur PC1:
```
ping 192.168.10.2
ping 192.168.10.3
```

## Commandes STP Utiles

```
show spanning-tree
show spanning-tree vlan 10
show spanning-tree root
show spanning-tree bridge
show spanning-tree interface e0/0
show spanning-tree detail
```

## Structure du Lab

```
21_STP_role_identification/
├── ansible.cfg
├── inventory.yml
├── group_vars/
│   └── all.yml
├── playbooks/
│   ├── 00_full_lab.yml
│   ├── 01_create_topology.yml
│   ├── 02_configure_vlans.yml
│   ├── 03_configure_vpcs.yml
│   └── 04_verify_stp.yml
├── scripts/
│   └── cisco_cli.py
├── switch_info.yml (généré automatiquement)
└── README.md
```

## Adresses IP

| Machine | IP | VLAN |
|---------|-----|------|
| PC1 | 192.168.10.1/24 | 10 |
| PC2 | 192.168.10.2/24 | 10 |
| PC3 | 192.168.10.3/24 | 10 |
