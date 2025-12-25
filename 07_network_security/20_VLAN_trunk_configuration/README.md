# Lab 20: VLAN and Trunk Configuration

## Objectifs

- Creer et nommer des VLANs sur des switches Cisco
- Configurer des ports access pour les end-devices
- Configurer des trunks 802.1Q entre switches
- Verifier l'isolation Layer 2 entre VLANs
- Tester la connectivite intra-VLAN a travers plusieurs switches

---

## Architecture

```
20_VLAN_Trunk_Configuration/
├── ansible.cfg
├── inventory.yml
├── group_vars/all.yml
├── switch_info.yml          # Genere automatiquement
├── README.md
├── playbooks/
│   ├── 00_full_lab.yml      # Setup complet
│   ├── 01_create_topology.yml
│   ├── 02_configure_vlans.yml
│   ├── 03_configure_vpcs.yml
│   └── 04_verify.yml
└── scripts/
    └── cisco_cli.py
```

---

## Topologie

```
  PC_Guests_1 ──┐                                           ┌── PC_Guests_2
  (VLAN 50)    │                                           │   (VLAN 50)
               │                                           │
  PC_IT_1 ─────┤                                           ├── PC_HR_2
  (VLAN 40)    │                                           │   (VLAN 20)
               │         TRUNK           TRUNK             │
  PC_Admin_1 ──┼── IOU1 ═══════════ IOU2 ═══════════ IOU3 ─┼── PC_Sales_2
  (VLAN 10)    │         (e0/0)     (e0/0)(e0/1)    (e0/0) │   (VLAN 30)
               │           │             │                 │
  PC_HR_1 ─────┤           │             │
  (VLAN 20)    │           │             └── PC_IT_2
               │           │                 (VLAN 40)
  PC_Sales_3 ──┘           │
  (VLAN 30)                └── PC_Admin_2
                               (VLAN 10)
```

---

## Configuration des VLANs

| VLAN ID | Nom           | Reseau          |
|---------|---------------|-----------------|
| 10      | Administration | 192.168.10.0/24 |
| 20      | HR            | 192.168.20.0/24 |
| 30      | Sales         | 192.168.30.0/24 |
| 40      | IT            | 192.168.40.0/24 |
| 50      | Guests        | 192.168.50.0/24 |

---

## Attribution des VPCs

| VPC          | Switch | Port  | VLAN | IP             |
|--------------|--------|-------|------|----------------|
| PC_Admin_1   | IOU1   | e0/2  | 10   | 192.168.10.10  |
| PC_Admin_2   | IOU2   | e0/2  | 10   | 192.168.10.20  |
| PC_HR_1      | IOU1   | e0/3  | 20   | 192.168.20.10  |
| PC_HR_2      | IOU3   | e0/2  | 20   | 192.168.20.20  |
| PC_Sales_2   | IOU3   | e0/3  | 30   | 192.168.30.20  |
| PC_Sales_3   | IOU1   | e1/0  | 30   | 192.168.30.30  |
| PC_IT_1      | IOU1   | e1/1  | 40   | 192.168.40.10  |
| PC_IT_2      | IOU2   | e0/3  | 40   | 192.168.40.20  |
| PC_Guests_1  | IOU1   | e1/2  | 50   | 192.168.50.10  |
| PC_Guests_2  | IOU3   | e1/0  | 50   | 192.168.50.20  |

---

## Demarrage rapide

```bash
cd 20_VLAN_Trunk_Configuration

# Setup complet (topologie + VLANs + VPCs)
ansible-playbook playbooks/00_full_lab.yml

# Ou etape par etape:
ansible-playbook playbooks/01_create_topology.yml
ansible-playbook playbooks/02_configure_vlans.yml
ansible-playbook playbooks/03_configure_vpcs.yml
```

---

## Verification

### Via Ansible

```bash
# Verifier IOU1
ansible-playbook playbooks/04_verify.yml -e "verify_switch=IOU1"

# Verifier IOU2
ansible-playbook playbooks/04_verify.yml -e "verify_switch=IOU2"

# Verifier IOU3
ansible-playbook playbooks/04_verify.yml -e "verify_switch=IOU3"
```

### Via Console

```bash
# Connexion a un switch (voir switch_info.yml pour les ports)
telnet 192.168.156.183 <PORT>

# Commandes de verification
show vlan brief
show interfaces trunk
show mac address-table
show spanning-tree
```

---

## Tests de connectivite

### Pings qui doivent FONCTIONNER (meme VLAN)

```bash
# Depuis PC_Admin_1 vers PC_Admin_2 (VLAN 10)
ping 192.168.10.20

# Depuis PC_HR_1 vers PC_HR_2 (VLAN 20)
ping 192.168.20.20

# Depuis PC_IT_1 vers PC_IT_2 (VLAN 40)
ping 192.168.40.20

# Depuis PC_Guests_1 vers PC_Guests_2 (VLAN 50)
ping 192.168.50.20
```

### Pings qui NE doivent PAS fonctionner (VLANs differents)

```bash
# Depuis PC_Admin_1 vers PC_HR_1
ping 192.168.20.10    # FAIL - pas de routage inter-VLAN
```

---

## Commandes Cisco de reference

### Creation des VLANs

```
enable
configure terminal
vlan 10
  name Administration
vlan 20
  name HR
vlan 30
  name Sales
vlan 40
  name IT
vlan 50
  name Guests
exit
```

### Configuration port Access

```
interface Ethernet0/2
  switchport mode access
  switchport access vlan 10
  spanning-tree portfast
  no shutdown
```

### Configuration port Trunk

```
interface Ethernet0/0
  switchport trunk encapsulation dot1q
  switchport mode trunk
  switchport trunk allowed vlan 10,20,30,40,50
  no shutdown
```

### Sauvegarde

```
# Sur les switches
copy running-config startup-config
# ou
write memory

# Sur les VPCs
save
```

---

## Troubleshooting

### Le trunk ne fonctionne pas

```
show interfaces trunk
show interfaces e0/0 switchport
```

Verifier:
- Encapsulation dot1q configuree des deux cotes
- Mode trunk des deux cotes
- VLANs autorises sur le trunk

### Les VPCs ne communiquent pas

1. Verifier que les VPCs sont dans le bon VLAN:
   ```
   show vlan brief
   ```

2. Verifier la table MAC:
   ```
   show mac address-table
   ```

3. Verifier que le trunk transporte le VLAN:
   ```
   show interfaces trunk
   ```

### Pas de connectivite inter-VLAN

C'est normal. Ce lab est Layer 2 uniquement.
Pour le routage inter-VLAN, voir le Lab 21.

---

## Resume des commandes

| Commande | Description |
|----------|-------------|
| `show vlan brief` | Liste des VLANs et ports assignes |
| `show interfaces trunk` | Etat des trunks |
| `show mac address-table` | Table d'adresses MAC |
| `show interfaces switchport` | Config switchport d'un port |
| `show spanning-tree` | Etat du STP |
