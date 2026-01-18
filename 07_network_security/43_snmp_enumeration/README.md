# Lab 43: SNMP Énumération

Reconnaissance sur un équipement SNMP mal configuré pour identifier les informations sensibles exposées.

---

## Objectifs pédagogiques

A la fin de ce lab :

1. **Comprendre SNMP** : Savoir ce qu'est SNMP et pourquoi il représente un risque de sécurité
2. **Énumérer un système** : Utiliser `snmpwalk` pour extraire des informations d'un équipement
3. **Identifier les risques** : Reconnaitre les données sensibles exposées par une mauvaise configuration
4. **Rédiger un rapport** : Documenter les vulnérabilités trouvées

---

## Qu'est-ce que SNMP ?

**SNMP** (Simple Network Management Protocol) est un protocole de supervision réseau permettant de :
- Surveiller l'état des équipements (CPU, mémoire, disque)
- Collecter des statistiques réseau
- Configurer des équipements a distance

### Le problème de sécurité

SNMP utilise des **community strings** comme mot de passe :
- `public` : accès en lecture (par défaut)
- `private` : accès en lecture/ecriture (par défaut)

**SNMPv2c** (le plus répandu) transmet ces community strings **en clair** sur le réseau.

Un attaquant qui découvre un service SNMP avec la community `public` peut extraire :
- Version de l'OS et du kernel
- Liste des processus en cours
- Ports ouverts
- Logiciels installés avec versions
- Configuration réseau complète

---

## Architecture du lab

```
                    ┌─────────────────┐
                    │      NAT1       │
                    │   (Internet)    │
                    │  192.168.122.1  │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │     Switch1     │
                    └───┬─────────┬───┘
                        │         │
             ┌──────────┴───┐ ┌───┴──────────┐
             │     Kali     │ │    Target    │
             │  (Attacker)  │ │  (SNMP-vuln) │
             │     DHCP     │ │192.168.122.10│
             └──────────────┘ └──────────────┘
```

| Machine | Role | IP |
|---------|------|-----|
| NAT1 | Gateway Internet | 192.168.122.1 |
| Kali | Machine attaquante | DHCP |
| Target | Cible SNMP vulnerable | 192.168.122.10 |

---

## Structure des fichiers

```
43_snmp_énumération/
├── README.md                  # Ce fichier
├── SOLUTION.md                # Résultats de l'énumération
├── ansible.cfg                # Configuration Ansible
├── inventory.yml              # Serveur GNS3
├── group_vars/
│   └── all.yml                # Variables (templates, IPs)
├── playbooks/
│   ├── 00_full_lab.yml        # Déploiement complet
│   ├── 01_create_topology.yml # Creation topologie
│   └── 02_verify.yml          # Verification
└── node_info.yml              # Généré automatiquement
```

---

## Déploiement du lab

### Étape 1 : Vérifier les prérequis

```bash
# Vérifier Ansible
ansible --version

# Vérifier la connexion au serveur GNS3
curl -s http://VOTRE_IP_GNS3:80/v2/version
```

### Étape 2 : Configurer l'inventaire

Editer `inventory.yml` avec l'IP du serveur GNS3 :

```yaml
all:
  hosts:
    localhost:
      ansible_connection: local
  vars:
    gns3_server: "http://VOTRE_IP_GNS3:80"
```

Editer aussi `group_vars/all.yml` :

```yaml
gns3_server_url: "http://VOTRE_IP_GNS3:80"
```

### Étape 3 : Déployer la topologie

```bash
cd 43_snmp_énumération
ansible-playbook playbooks/00_full_lab.yml
```

Le playbook crée automatiquement :
- Le projet GNS3 "Lab_43_SNMP_Énumération"
- Les 4 nodes (NAT1, Switch1, Kali, Target)
- Les liens réseau
- Démarre tous les équipements

### Étape 4 : Vérifier le déploiement

```bash
ansible-playbook playbooks/02_verify.yml
```

Résultat attendu :
```
TASK [Display node status] *****
ok: [localhost] =>
  msg: |-
    NAT1: started
    Switch1: started
    Kali: started
    Target: started
```

---

## Configuration manuelle de la cible

> **Important** : La VM Target doit être configurée manuellement car elle n'a pas d'IP au démarrage.

### Étape 1 : Connexion a la console Target

Dans GNS3, double-cliquer sur "Target" pour ouvrir la console.

**Credentials** : `debian` / `debian`

### Étape 2 : Configuration réseau

```bash
sudo -s

# Configurer DNS
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Configurer l'interface réseau
ip addr add 192.168.122.10/24 dev ens4
ip link set ens4 up

# Ajouter la route par défaut
ip route add default via 192.168.122.1

# Tester la connectivite
ping -c 2 8.8.8.8
```

### Étape 3 : Installation et configuration SNMP

```bash
# Mettre a jour et installér SNMP
apt update && apt install -y snmpd snmp

# Creer une configuration VULNERABLE (pour le lab)
cat > /etc/snmp/snmpd.conf << 'EOF'
# Configuration SNMP VULNERABLE - NE PAS UTILISER EN PRODUCTION!

# Écoute sur toutes les interfaces
agentaddress udp:161

# Community strings par défaut (DANGER!)
rocommunity public
rwcommunity private

# Informations système exposées
sysLocation Server Room - Rack 42
sysContact admin@vulnerable-corp.local
sysName target-server

# Acces complet a l'arbre MIB
view all included .1
EOF

# Redémarrer le service
systemctl restart snmpd
systemctl enable snmpd

# Vérifier que SNMP écoute
ss -ulnp | grep 161
```

Résultat attendu :
```
UNCONN 0 0 0.0.0.0:161 0.0.0.0:* users:(("snmpd",pid=XXX,fd=6))
```

### Étape 4 : Test SNMP local

```bash
snmpwalk -v2c -c public localhost sysDescr
```

Résultat attendu :
```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux debian 6.1.0-22-cloud-amd64 ..."
```

---

## Exercices d'énumération

### Exercice 1 : Découverte du service SNMP

Depuis Kali (ou directement depuis Target pour ce lab) :

```bash
# Vérifier que le port 161/UDP est ouvert
nmap -sU -p 161 192.168.122.10
```

### Exercice 2 : Énumération système

```bash
# Informations système complètes
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1
```

**Questions** :
- Quel est le système d'exploitation ?
- Quel est le nom d'hôte ?
- Qui est le contact administrateur ?

### Exercice 3 : Énumération réseau

```bash
# Interfaces réseau
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.2

# Adresses IP
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.4.20.1.1

# Adresses MAC
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.6
```

### Exercice 4 : Énumération des services

```bash
# Processus en cours
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.4.2.1.2

# Ports TCP en écoute
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.6.13

# Ports UDP en écoute
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.7.5.1.2
```

### Exercice 5 : Énumération des logiciels

```bash
# Logiciels installés (attention: peut être long)
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.6.3.1.2 | head -30
```

### Exercice 6 : Recherche de credentials

```bash
# Paramêtres des processus (peut contenir des mots de passe)
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.4.2.1.5
```

---

## Référence des OIDs importants

| OID | Nom | Description |
|-----|-----|-------------|
| .1.3.6.1.2.1.1.1 | sysDescr | Description du système |
| .1.3.6.1.2.1.1.4 | sysContact | Contact administrateur |
| .1.3.6.1.2.1.1.5 | sysName | Nom d'hôte |
| .1.3.6.1.2.1.1.6 | sysLocation | Localisation physique |
| .1.3.6.1.2.1.2.2.1.2 | ifDescr | Noms des interfaces |
| .1.3.6.1.2.1.2.2.1.6 | ifPhysAddress | Adresses MAC |
| .1.3.6.1.2.1.4.20.1.1 | ipAdEntAddr | Adresses IP |
| .1.3.6.1.2.1.6.13 | tcpConnTable | Connexions TCP |
| .1.3.6.1.2.1.7.5.1.2 | udpLocalPort | Ports UDP |
| .1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName | Processus en cours |
| .1.3.6.1.2.1.25.4.2.1.5 | hrSWRunParameters | Paramêtres processus |
| .1.3.6.1.2.1.25.6.3.1.2 | hrSWInstalledName | Logiciels installés |
| .1.3.6.1.2.1.25.2.3.1.3 | hrStorageDescr | Stockage |

---

## Outil snmp-check

`snmp-check` automatise l'énumération SNMP et genere un rapport formaté.

### Installation

```bash
apt install snmp-check -y
```

### Utilisation

```bash
snmp-check 192.168.122.10 -c public
```

### Comparaison avec snmpwalk

| Critere | snmpwalk | snmp-check |
|---------|----------|------------|
| Type | Manuel, OID par OID | Automatise, scan complet |
| Sortie | Brute (OIDs numériques) | Formatee, lisible |
| Flexibilite | Haute | Basse |
| Cas d'usage | Requetes ciblees | Audit initial |

---

## Rapport de sécurité

Après l'énumération, rédiger un rapport incluant :

### 1. Résumé executif
- Cible : 192.168.122.10
- Sévérité globale : CRITIQUE

### 2. Vulnerabilites identifiées

| # | Vulnerabilite | Sévérité | Donnees exposées |
|---|---------------|----------|------------------|
| 1 | Community string "public" | CRITIQUE | Acces complet en lecture |
| 2 | Version OS exposée | HAUTE | Debian 6.1.0-22, kernel exact |
| 3 | Email admin exposé | MOYENNE | admin@vulnerable-corp.local |
| 4 | Localisation exposée | MOYENNE | Server Room - Rack 42 |
| 5 | Liste des processus | HAUTE | sshd, snmpd, systemd... |
| 6 | Ports ouverts | HAUTE | SSH sur 0.0.0.0:22 |
| 7 | Paquets installés | MOYENNE | Versions exactes exposées |

### 3. Recommandations

1. **Migrer vers SNMPv3** avec authentification et chiffrement
2. **Changer la community string** si SNMPv2c obligatoire
3. **Restreindre les vues SNMP** pour limiter les OIDs accèssibles
4. **Filtrer par IP source** avec des ACLs
5. **Configurer un firewall** pour limiter l'accès au port 161/UDP

---

## Difficultés rencontrées et solutions

### Problème 1 : Template Kali introuvable

**Symptôme** :
```
FAILED! => {"msg": "Template 'Kali' not found"}
```

**Cause** : Le nom du template dans GNS3 peut varier.

**Solution** : Vérifier le nom exact dans GNS3 et mettre a jour `group_vars/all.yml` :
```yaml
template_names:
  kali: "kalilinux-kali-rolling"  # Nom exact dans GNS3
```

### Problème 2 : Kali Docker trop minimaliste

**Symptôme** : Le conteneur Kali n'a pas `ip`, `ping`, `snmpwalk`...

**Cause** : L'image Docker Kali est tres légère par défaut.

**Solution** : Effectuer l'énumération depuis la Target elle-même (localhost) ou utiliser une VM Kali complète.

### Problème 3 : Target sans IP au démarrage

**Symptôme** : La VM Target démarre mais n'a pas d'adresse IP.

**Cause** : Pas de serveur DHCP sur le réseau NAT pour la VM.

**Solution** : Configurer l'IP manuellement (voir section "Configuration manuelle de la cible").

### Problème 4 : snmpwalk timeout

**Symptôme** :
```
Timeout: No Response from 192.168.122.10
```

**Causes possibles** :
1. SNMP non installé sur la cible
2. Mauvaise community string
3. Firewall bloquant le port 161/UDP

**Solutions** :
```bash
# Sur la cible, verifier que snmpd tourne
systemctl status snmpd

# Vérifier le port
ss -ulnp | grep 161

# Tester localement
snmpwalk -v2c -c public localhost sysDescr
```

### Problème 5 : OIDs numériques au lieu de noms

**Symptôme** :
```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux..."
```
au lieu de :
```
SNMPv2-MIB::sysDescr.0 = STRING: "Linux..."
```

**Solution** :
```bash
apt install snmp-mibs-downloader -y
download-mibs
echo "mibs +ALL" >> /etc/snmp/snmp.conf
```

---

## Validation du lab

Checklist des elements a complèter :

- [ ] Topologie déployée via Ansible
- [ ] Target configurée avec IP statique
- [ ] SNMP installé et configuré sur Target
- [ ] Port 161/UDP accèssible
- [ ] Informations système énumérées (OS, hostname)
- [ ] Interfaces réseau listées
- [ ] Processus en cours identifiés
- [ ] Ports TCP/UDP documentés
- [ ] Logiciels installés énumérés
- [ ] Rapport de sécurité rédigé

---

## Pour aller plus loin

- **SNMPv3** : Configurer SNMPv3 avec authentification (MD5/SHA) et chiffrement (DES/AES)
- **Brute force** : Utiliser `onesixtyone` pour tester des community strings
- **SNMP write** : Explorer les possibilites avec `rwcommunity private`
- **Automatisation** : Creer un script Python avec la bibliothèque `pysnmp`

---

## Références

- [Net-SNMP Documentation](http://www.net-snmp.org/docs/)
- [SNMP OID Repository](http://oid-info.com/)
- [HackTricks - SNMP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
