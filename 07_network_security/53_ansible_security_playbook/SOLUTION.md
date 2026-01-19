# Lab 53: Ansible Security Playbook - Solution

Solution complète du playbook Ansible pour la configuration de sécurité du switch Cisco IOU L2.

---

## Playbook complet : 02_configure_switch.yml

```yaml
---
# ============================================
# PLAYBOOK : CONFIGURATION SÉCURITÉ DU SWITCH
# ============================================
# Ce playbook configure le switch Cisco IOU L2 :
# - Création de 5 VLANs (10-50)
# - Configuration des SVIs
# - Port-security sur les ports access
#
# Prérequis: Avoir exécuté 01_create_topology.yml
# Usage: ansible-playbook playbooks/02_configure_switch.yml

- name: "ETAPE 2 : Configuration sécurité du switch"
  hosts: localhost
  gather_facts: false

  vars_files:
    - ../switch_info.yml

  tasks:
    - name: "Afficher les informations de connexion"
      debug:
        msg:
          - "Port console SW1 : {{ switch_console_port }}"
          - "Serveur GNS3 : {{ gns3_host }}"

    # ==========================================
    # PARTIE 1 : Création des VLANs
    # ==========================================
    - name: "Créer les 5 VLANs"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ vlan_commands | join(';') }}"
      vars:
        vlan_commands:
          - "enable"
          - "configure terminal"
          # VLAN 10 - Engineering
          - "vlan 10"
          - "name Engineering"
          - "exit"
          # VLAN 20 - HR
          - "vlan 20"
          - "name HR"
          - "exit"
          # VLAN 30 - Finance
          - "vlan 30"
          - "name Finance"
          - "exit"
          # VLAN 40 - Guest
          - "vlan 40"
          - "name Guest"
          - "exit"
          # VLAN 50 - Management
          - "vlan 50"
          - "name Management"
          - "exit"
          - "end"
      register: vlan_result

    - name: "Pause après création VLANs"
      pause:
        seconds: 3

    # ==========================================
    # PARTIE 2 : Désactiver les SVIs non-utilisées
    # ==========================================
    - name: "Désactiver les SVIs des VLANs 10-40"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ svi_shutdown_commands | join(';') }}"
      vars:
        svi_shutdown_commands:
          - "enable"
          - "configure terminal"
          # Désactiver SVI VLAN 10
          - "interface vlan 10"
          - "shutdown"
          - "exit"
          # Désactiver SVI VLAN 20
          - "interface vlan 20"
          - "shutdown"
          - "exit"
          # Désactiver SVI VLAN 30
          - "interface vlan 30"
          - "shutdown"
          - "exit"
          # Désactiver SVI VLAN 40
          - "interface vlan 40"
          - "shutdown"
          - "exit"
          - "end"

    - name: "Pause après désactivation SVIs"
      pause:
        seconds: 2

    # ==========================================
    # PARTIE 3 : Configurer SVI Management (VLAN 50)
    # ==========================================
    - name: "Configurer l'interface VLAN 50 (Management)"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ svi_mgmt_commands | join(';') }}"
      vars:
        svi_mgmt_commands:
          - "enable"
          - "configure terminal"
          - "interface vlan 50"
          - "description Ansible Management Interface"
          - "ip address 192.168.50.2 255.255.255.0"
          - "no shutdown"
          - "exit"
          - "end"

    - name: "Pause après configuration SVI Management"
      pause:
        seconds: 2

    # ==========================================
    # PARTIE 4 : Port-Security sur ports access
    # ==========================================
    - name: "Configurer port-security sur Ethernet0/0 (VLAN 10)"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ port_sec_e00_commands | join(';') }}"
      vars:
        port_sec_e00_commands:
          - "enable"
          - "configure terminal"
          - "interface Ethernet0/0"
          - "switchport mode access"
          - "switchport access vlan 10"
          - "switchport port-security"
          - "switchport port-security maximum 1"
          - "switchport port-security violation restrict"
          - "switchport port-security mac-address sticky"
          - "no shutdown"
          - "exit"
          - "end"

    - name: "Configurer port-security sur Ethernet0/1 (VLAN 20)"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ port_sec_e01_commands | join(';') }}"
      vars:
        port_sec_e01_commands:
          - "enable"
          - "configure terminal"
          - "interface Ethernet0/1"
          - "switchport mode access"
          - "switchport access vlan 20"
          - "switchport port-security"
          - "switchport port-security maximum 1"
          - "switchport port-security violation restrict"
          - "switchport port-security mac-address sticky"
          - "no shutdown"
          - "exit"
          - "end"

    - name: "Configurer port-security sur Ethernet0/2 (VLAN 30)"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ port_sec_e02_commands | join(';') }}"
      vars:
        port_sec_e02_commands:
          - "enable"
          - "configure terminal"
          - "interface Ethernet0/2"
          - "switchport mode access"
          - "switchport access vlan 30"
          - "switchport port-security"
          - "switchport port-security maximum 1"
          - "switchport port-security violation restrict"
          - "switchport port-security mac-address sticky"
          - "no shutdown"
          - "exit"
          - "end"

    - name: "Configurer port-security sur Ethernet0/3 (VLAN 40)"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "{{ port_sec_e03_commands | join(';') }}"
      vars:
        port_sec_e03_commands:
          - "enable"
          - "configure terminal"
          - "interface Ethernet0/3"
          - "switchport mode access"
          - "switchport access vlan 40"
          - "switchport port-security"
          - "switchport port-security maximum 1"
          - "switchport port-security violation restrict"
          - "switchport port-security mac-address sticky"
          - "no shutdown"
          - "exit"
          - "end"

    - name: "Pause après configuration port-security"
      pause:
        seconds: 3

    # ==========================================
    # PARTIE 5 : Sauvegarde de la configuration
    # ==========================================
    - name: "Sauvegarder la configuration"
      script: >
        ../scripts/cisco_cli.py
        --host {{ gns3_host }}
        --port {{ switch_console_port }}
        --commands "enable;write memory"

    - name: "Configuration terminée !"
      debug:
        msg:
          - "=========================================="
          - "Configuration de sécurité appliquée :"
          - "=========================================="
          - "✓ VLANs créés : 10, 20, 30, 40, 50"
          - "✓ SVIs 10-40 : désactivées"
          - "✓ SVI 50 : 192.168.50.2/24 (active)"
          - "✓ Port-security : E0/0-E0/3"
          - "✓ Configuration sauvegardée"
          - ""
          - "Vérification : ansible-playbook playbooks/03_verify.yml"
```

---

## Résultats attendus

### show vlan brief

```
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Et1/0, Et1/1, Et1/2, Et1/3
                                                Et2/0, Et2/1, Et2/2, Et2/3
                                                Et3/0, Et3/1, Et3/2, Et3/3
10   Engineering                      active    Et0/0
20   HR                               active    Et0/1
30   Finance                          active    Et0/2
40   Guest                            active    Et0/3
50   Management                       active
```

### show ip interface brief

```
Interface              IP-Address      OK? Method Status                Protocol
Ethernet0/0            unassigned      YES unset  up                    up
Ethernet0/1            unassigned      YES unset  up                    up
Ethernet0/2            unassigned      YES unset  up                    up
Ethernet0/3            unassigned      YES unset  up                    up
...
Vlan1                  unassigned      YES unset  administratively down down
Vlan10                 unassigned      YES unset  administratively down down
Vlan20                 unassigned      YES unset  administratively down down
Vlan30                 unassigned      YES unset  administratively down down
Vlan40                 unassigned      YES unset  administratively down down
Vlan50                 192.168.50.2    YES manual up                    up
```

### show interface vlan 50

```
Vlan50 is up, line protocol is up
  Hardware is EtherSVI, address is aabb.cc00.0100 (bia aabb.cc00.0100)
  Description: Ansible Management Interface
  Internet address is 192.168.50.2/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  ...
```

### show port-security

```
Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action
                (Count)       (Count)          (Count)
---------------------------------------------------------------------------
      Et0/0              1            0                  0         Restrict
      Et0/1              1            0                  0         Restrict
      Et0/2              1            0                  0         Restrict
      Et0/3              1            0                  0         Restrict
---------------------------------------------------------------------------
Total Addresses in System (excluding one mac per port)     : 0
Max Addresses limit in System (excluding one mac per port) : 4096
```

### show port-security interface Ethernet0/0

```
Port Security              : Enabled
Port Status                : Secure-up
Violation Mode             : Restrict
Aging Time                 : 0 mins
Aging Type                 : Absolute
SecureStatic Address Aging : Disabled
Maximum MAC Addresses      : 1
Total MAC Addresses        : 0
Configured MAC Addresses   : 0
Sticky MAC Addresses       : 0
Last Source Address:Vlan   : 0000.0000.0000:0
Security Violation Count   : 0
```

---

## Configuration finale running-config (extrait)

```
!
hostname SW1
!
vlan 10
 name Engineering
!
vlan 20
 name HR
!
vlan 30
 name Finance
!
vlan 40
 name Guest
!
vlan 50
 name Management
!
interface Ethernet0/0
 switchport access vlan 10
 switchport mode access
 switchport port-security maximum 1
 switchport port-security
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
interface Ethernet0/1
 switchport access vlan 20
 switchport mode access
 switchport port-security maximum 1
 switchport port-security
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
interface Ethernet0/2
 switchport access vlan 30
 switchport mode access
 switchport port-security maximum 1
 switchport port-security
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
interface Ethernet0/3
 switchport access vlan 40
 switchport mode access
 switchport port-security maximum 1
 switchport port-security
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
interface Vlan10
 no ip address
 shutdown
!
interface Vlan20
 no ip address
 shutdown
!
interface Vlan30
 no ip address
 shutdown
!
interface Vlan40
 no ip address
 shutdown
!
interface Vlan50
 description Ansible Management Interface
 ip address 192.168.50.2 255.255.255.0
!
end
```

---

## Validation des objectifs

- [x] **5 VLANs créés** : 10 (Engineering), 20 (HR), 30 (Finance), 40 (Guest), 50 (Management)
- [x] **Noms assignés** : Chaque VLAN a son nom descriptif
- [x] **SVIs désactivées** : VLANs 10-40 sont en `shutdown`
- [x] **SVI Management active** : VLAN 50 avec 192.168.50.2/24
- [x] **Description SVI** : "Ansible Management Interface"
- [x] **Port-security activé** : Sur E0/0, E0/1, E0/2, E0/3
- [x] **Maximum 1 MAC** : Configuré sur chaque port
- [x] **Violation restrict** : Action configurée
- [x] **Sticky MAC** : Activé (bonus)
- [x] **Configuration sauvegardée** : `write memory` exécuté

---

## Version alternative avec boucle

Pour les étudiants avancés, voici une version utilisant une boucle Ansible :

```yaml
- name: "Configurer port-security sur tous les ports"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ switch_console_port }}
    --commands "{{ item.commands | join(';') }}"
  loop:
    - name: "E0/0"
      commands:
        - "enable"
        - "configure terminal"
        - "interface Ethernet0/0"
        - "switchport mode access"
        - "switchport access vlan 10"
        - "switchport port-security"
        - "switchport port-security maximum 1"
        - "switchport port-security violation restrict"
        - "switchport port-security mac-address sticky"
        - "no shutdown"
        - "exit"
        - "end"
    - name: "E0/1"
      commands:
        - "enable"
        - "configure terminal"
        - "interface Ethernet0/1"
        - "switchport mode access"
        - "switchport access vlan 20"
        # ... (même structure)
  loop_control:
    label: "{{ item.name }}"
```

---

## Commandes de vérification complètes

```bash
# Vérifier les VLANs
show vlan brief

# Vérifier les interfaces
show ip interface brief

# Vérifier la SVI Management
show interface vlan 50

# Vérifier port-security global
show port-security

# Vérifier port-security par interface
show port-security interface Ethernet0/0
show port-security interface Ethernet0/1
show port-security interface Ethernet0/2
show port-security interface Ethernet0/3

# Vérifier la configuration complète
show running-config
```
