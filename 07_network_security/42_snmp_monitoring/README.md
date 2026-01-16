# Lab 42: SNMP Monitoring

Configuration et test du protocole **SNMP** (Simple Network Management Protocol) entre deux machines Linux Debian 12.6 dans GNS3.

**Durée estimée** : 90 minutes

---

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Configuration](#configuration)
6. [Exercices](#exercices)
7. [SNMPv3 (Bonus)](#snmpv3-bonus)
8. [Référence des commandes](#référence-des-commandes)
9. [Dépannage](#dépannage)

---

## Objectifs

- Installer et configurer un agent SNMP (`snmpd`) sur Linux
- Interroger des métriques système à distance avec `snmpwalk` et `snmpget`
- Récupérer des informations système : uptime, description, localisation
- Configurer SNMPv3 avec authentification et chiffrement (bonus)

---

## Prérequis

- GNS3 connecté au serveur distant
- Ansible installé (`brew install ansible` sur macOS)
- Python 3
- Appliance Debian 12.6 disponible dans GNS3

---

## Architecture

### Structure du lab

```
42_snmp_monitoring/
├── ansible.cfg                # Configuration Ansible
├── inventory.yml              # Inventaire GNS3
├── group_vars/
│   └── all.yml                # Variables de configuration
├── playbooks/
│   ├── 00_full_lab.yml        # Déploiement complet
│   ├── 01_create_topology.yml # Création de la topologie
│   └── 02_verify.yml          # Vérification
├── node_info.yml              # Généré automatiquement
└── README.md
```

### Topologie réseau

```
                    ┌─────────────────┐
                    │      NAT1       │
                    │   (Internet)    │
                    │  192.168.122.1  │  <- Gateway
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │     Switch1     │
                    └───┬─────────┬───┘
                        │         │
                   ens4 │         │ ens4
                        │         │
             ┌──────────┴───┐ ┌───┴──────────┐
             │  SNMP-Agent  │ │ SNMP-Manager │
             │    snmpd     │ │   snmpwalk   │
             │192.168.122.10│ │192.168.122.20│
             └──────────────┘ └──────────────┘
                Debian 12.6     Debian 12.6
```

### Plan d'adressage

| Équipement | Interface | Adresse IP | Rôle |
|------------|-----------|------------|------|
| NAT1 | nat0 | 192.168.122.1 | Gateway / Internet |
| Switch1 | - | - | Interconnexion L2 |
| SNMP-Agent | ens4 | 192.168.122.10/24 | Agent SNMP (snmpd) |
| SNMP-Manager | ens4 | 192.168.122.20/24 | Manager SNMP (snmpwalk) |

### Ports

| Service | Port | Protocole |
|---------|------|-----------|
| SNMP | 161 | UDP |
| SNMP Trap | 162 | UDP |

---

## Démarrage rapide

```bash
cd 42_snmp_monitoring

# Modifier l'IP du serveur GNS3 si nécessaire dans inventory.yml et group_vars/all.yml

# Déploiement complet
ansible-playbook playbooks/00_full_lab.yml

# Vérification
ansible-playbook playbooks/02_verify.yml
```

> Les playbooks sont idempotents.

---

## Configuration

### 1. Déploiement de la topologie

```bash
ansible-playbook playbooks/00_full_lab.yml
```

Le playbook crée automatiquement :
- Le projet GNS3 "Lab_42_SNMP_Monitoring"
- Les nodes : NAT1, Switch1, SNMP-Agent, SNMP-Manager
- Les connexions réseau
- Le démarrage des équipements

Résultat attendu :

```
NODES:
  NAT1         - Accès Internet
  Switch1      - Switch interne
  SNMP-Agent   - Console (port 5002)
  SNMP-Manager - Console (port 5004)
```

### 2. Connexion aux VMs

Attendre 1-2 minutes le démarrage des VMs Debian.

**Via GNS3 GUI** : Clic droit sur le node → Console

**Via telnet** :
```bash
telnet <IP_SERVEUR_GNS3> 5002  # SNMP-Agent
telnet <IP_SERVEUR_GNS3> 5004  # SNMP-Manager
```

**Identifiants Debian** : `debian` / `debian`

### 3. Configuration réseau

Les VMs nécessitent une configuration IP statique.

#### SNMP-Agent (192.168.122.10)

```bash
sudo -s

# Configuration DNS
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Configuration réseau
cat > /etc/network/interfaces << 'EOF'
auto lo
iface lo inet loopback

auto ens4
iface ens4 inet static
    address 192.168.122.10
    netmask 255.255.255.0
    gateway 192.168.122.1
    dns-nameservers 8.8.8.8
EOF

# Activation de l'interface
ip link set ens4 up
ip addr add 192.168.122.10/24 dev ens4
ip route add default via 192.168.122.1
```

#### SNMP-Manager (192.168.122.20)

```bash
sudo -s

echo 'nameserver 8.8.8.8' > /etc/resolv.conf

cat > /etc/network/interfaces << 'EOF'
auto lo
iface lo inet loopback

auto ens4
iface ens4 inet static
    address 192.168.122.20
    netmask 255.255.255.0
    gateway 192.168.122.1
    dns-nameservers 8.8.8.8
EOF

ip link set ens4 up
ip addr add 192.168.122.20/24 dev ens4
ip route add default via 192.168.122.1
```

### 4. Vérification de la connectivité

Depuis SNMP-Manager :

```bash
ping -c 2 192.168.122.10    # Vers l'agent
ping -c 2 8.8.8.8           # Vers Internet
ping -c 2 deb.debian.org    # Résolution DNS
```

Résultat attendu :

```
PING 192.168.122.10 (192.168.122.10) 56(84) bytes of data.
64 bytes from 192.168.122.10: icmp_seq=1 ttl=64 time=1.91 ms
64 bytes from 192.168.122.10: icmp_seq=2 ttl=64 time=1.25 ms
--- 192.168.122.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
```

### 5. Installation SNMP

#### Sur SNMP-Agent

```bash
apt update && apt install -y snmpd snmp
```

#### Sur SNMP-Manager

```bash
apt update && apt install -y snmp
```

### 6. Configuration de l'agent SNMP

Sur SNMP-Agent, éditer `/etc/snmp/snmpd.conf` :

```bash
nano /etc/snmp/snmpd.conf
```

Modifications requises :

```conf
# Écoute sur toutes les interfaces (remplacer la ligne agentaddress existante)
agentaddress udp:161

# Communauté lecture seule pour le réseau local (ajouter à la fin)
rocommunity public 192.168.122.0/24

# Informations système (modifier les lignes existantes)
sysLocation    GNS3 Lab - SNMP Agent
sysContact     admin@lab.local
```

Redémarrage du service :

```bash
systemctl restart snmpd
systemctl status snmpd
```

Vérification de l'écoute sur le port 161 :

```bash
ss -ulnp | grep 161
```

Résultat attendu :

```
UNCONN 0  0  0.0.0.0:161  0.0.0.0:*  users:(("snmpd",pid=1145,fd=6))
```

### 7. Test SNMP

Depuis SNMP-Manager, exécuter des requêtes vers l'agent :

#### snmpwalk - Parcours de l'arbre MIB

```bash
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1
```

Résultat attendu :

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux debian 6.1.0-22-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.94-1 (2024-06-21) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (121930) 0:20:19.30
iso.3.6.1.2.1.1.4.0 = STRING: "admin@lab.local"
iso.3.6.1.2.1.1.5.0 = STRING: "debian"
iso.3.6.1.2.1.1.6.0 = STRING: "GNS3 Lab - SNMP Agent"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
```

#### snmpget - Requêtes unitaires

```bash
# Description système (sysDescr)
snmpget -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1.1.0

# Uptime (sysUpTime)
snmpget -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1.3.0

# Contact (sysContact)
snmpget -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1.4.0

# Nom système (sysName)
snmpget -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1.5.0

# Localisation (sysLocation)
snmpget -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1.6.0
```

---

## Exercices

### Exercice 1 : Interfaces réseau

```bash
# Liste des interfaces
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.2

# Octets entrants par interface
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.10

# Octets sortants par interface
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.16
```

### Exercice 2 : Ressources système

```bash
# Charge CPU
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.3.3.1.2

# Mémoire utilisée
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.2.3.1.6

# Espace disque
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.2.3.1.5
```

### Exercice 3 : Processus

```bash
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.4.2.1.2
```

### Exercice 4 : Exploration complète

```bash
snmpwalk -v2c -c public 192.168.122.10 .1
```

---

## SNMPv3 (Bonus)

SNMPv3 ajoute l'authentification et le chiffrement des communications.

### Configuration sur l'agent

```bash
# Arrêt du service
systemctl stop snmpd

# Création d'un utilisateur SNMPv3
net-snmp-create-v3-user -ro -A authpass123 -a SHA -X privpass123 -x AES snmpuser

# Redémarrage
systemctl start snmpd
```

Paramètres :
- `-ro` : lecture seule
- `-A authpass123` : mot de passe d'authentification (min. 8 caractères)
- `-a SHA` : algorithme d'authentification
- `-X privpass123` : mot de passe de chiffrement (min. 8 caractères)
- `-x AES` : algorithme de chiffrement

### Test depuis le manager

```bash
# Requête avec authentification et chiffrement
snmpwalk -v3 -u snmpuser -l authPriv -a SHA -A authpass123 -x AES -X privpass123 192.168.122.10 .1.3.6.1.2.1.1

# Récupération de l'uptime
snmpget -v3 -u snmpuser -l authPriv -a SHA -A authpass123 -x AES -X privpass123 192.168.122.10 .1.3.6.1.2.1.1.3.0
```

### Niveaux de sécurité SNMPv3

| Niveau | Option `-l` | Description |
|--------|-------------|-------------|
| noAuthNoPriv | `noAuthNoPriv` | Sans authentification ni chiffrement |
| authNoPriv | `authNoPriv` | Authentification uniquement |
| authPriv | `authPriv` | Authentification + chiffrement |

---

## Référence des commandes

### Syntaxe

```bash
# SNMPv2c
snmpwalk -v2c -c <community> <host> <OID>
snmpget -v2c -c <community> <host> <OID>

# SNMPv3
snmpwalk -v3 -u <user> -l <level> -a <auth_proto> -A <auth_pass> -x <priv_proto> -X <priv_pass> <host> <OID>
```

### OIDs courants

| OID | Nom | Description |
|-----|-----|-------------|
| .1.3.6.1.2.1.1.1.0 | sysDescr | Description du système |
| .1.3.6.1.2.1.1.3.0 | sysUpTime | Uptime (centisecondes) |
| .1.3.6.1.2.1.1.4.0 | sysContact | Contact administrateur |
| .1.3.6.1.2.1.1.5.0 | sysName | Nom du système |
| .1.3.6.1.2.1.1.6.0 | sysLocation | Localisation |
| .1.3.6.1.2.1.2.2.1.2 | ifDescr | Interfaces réseau |
| .1.3.6.1.2.1.2.2.1.10 | ifInOctets | Octets entrants |
| .1.3.6.1.2.1.2.2.1.16 | ifOutOctets | Octets sortants |
| .1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName | Processus actifs |

### Diagnostic

```bash
# Vérifier l'écoute de snmpd
ss -ulnp | grep 161

# Statut du service
systemctl status snmpd

# Logs
journalctl -u snmpd -f

# Test de configuration
snmpd -f -Le -C -c /etc/snmp/snmpd.conf
```

---

## Dépannage

### Timeout / No Response

1. **Vérifier l'écoute de snmpd**
   ```bash
   ss -ulnp | grep 161
   # Attendu : 0.0.0.0:161 (pas 127.0.0.1:161)
   ```

2. **Vérifier la configuration**
   ```bash
   grep -E "^agentaddress|^rocommunity" /etc/snmp/snmpd.conf
   ```

3. **Vérifier la connectivité**
   ```bash
   ping 192.168.122.10
   ```

4. **Vérifier le firewall**
   ```bash
   iptables -L -n | grep 161
   # Si bloqué :
   iptables -A INPUT -p udp --dport 161 -j ACCEPT
   ```

### Unknown Object Identifier

Les MIBs ne sont pas chargées. Utiliser les OIDs numériques ou installer les MIBs :

```bash
apt install snmp-mibs-downloader
download-mibs
echo "mibs +ALL" >> /etc/snmp/snmp.conf
```

### Pas d'accès Internet

```bash
# Vérifier DNS
cat /etc/resolv.conf
# Attendu : nameserver 8.8.8.8

# Vérifier la route par défaut
ip route
# Attendu : default via 192.168.122.1

# Correction manuelle
echo 'nameserver 8.8.8.8' > /etc/resolv.conf
ip route add default via 192.168.122.1
```

### snmpd ne démarre pas

```bash
# Mode debug
snmpd -f -Le -C -c /etc/snmp/snmpd.conf

# Consultation des logs
journalctl -u snmpd --no-pager
```

---

## Critères de validation

- [ ] Communication entre les deux VMs (ping)
- [ ] snmpd actif sur l'agent (port 161/UDP)
- [ ] Requêtes snmpwalk/snmpget fonctionnelles
- [ ] Récupération des métriques : uptime, sysDescr, sysLocation
- [ ] (Bonus) SNMPv3 avec authentification et chiffrement

---

## Références

- [Net-SNMP Documentation](http://www.net-snmp.org/docs/)
- [RFC 3411 - SNMP Architecture](https://tools.ietf.org/html/rfc3411)
- [RFC 3414 - SNMPv3 Security](https://tools.ietf.org/html/rfc3414)
- [OID Repository](http://oid-info.com/)
- [Debian SNMP Wiki](https://wiki.debian.org/SNMP)
