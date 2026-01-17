# Lab 43: SNMP Enumeration

Reconnaissance sur un equipement SNMP mal configure pour identifier les informations sensibles exposees.

---

## Objectifs pedagogiques

A la fin de ce lab :

1. **Comprendre SNMP** : Savoir ce qu'est SNMP et pourquoi il represente un risque de securite
2. **Enumerer un systeme** : Utiliser `snmpwalk` pour extraire des informations d'un equipement
3. **Identifier les risques** : Reconnaitre les donnees sensibles exposees par une mauvaise configuration
4. **Rediger un rapport** : Documenter les vulnerabilites trouvees

---

## Qu'est-ce que SNMP ?

**SNMP** (Simple Network Management Protocol) est un protocole de supervision reseau permettant de :
- Surveiller l'etat des equipements (CPU, memoire, disque)
- Collecter des statistiques reseau
- Configurer des equipements a distance

### Le probleme de securite

SNMP utilise des **community strings** comme mot de passe :
- `public` : acces en lecture (par defaut)
- `private` : acces en lecture/ecriture (par defaut)

**SNMPv2c** (le plus repandu) transmet ces community strings **en clair** sur le reseau.

Un attaquant qui decouvre un service SNMP avec la community `public` peut extraire :
- Version de l'OS et du kernel
- Liste des processus en cours
- Ports ouverts
- Logiciels installes avec versions
- Configuration reseau complete

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
43_snmp_enumeration/
├── README.md                  # Ce fichier
├── SOLUTION.md                # Resultats de l'enumeration
├── ansible.cfg                # Configuration Ansible
├── inventory.yml              # Serveur GNS3
├── group_vars/
│   └── all.yml                # Variables (templates, IPs)
├── playbooks/
│   ├── 00_full_lab.yml        # Deploiement complet
│   ├── 01_create_topology.yml # Creation topologie
│   └── 02_verify.yml          # Verification
└── node_info.yml              # Genere automatiquement
```

---

## Deploiement du lab

### Etape 1 : Verifier les prerequis

```bash
# Verifier Ansible
ansible --version

# Verifier la connexion au serveur GNS3
curl -s http://VOTRE_IP_GNS3:80/v2/version
```

### Etape 2 : Configurer l'inventaire

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

### Etape 3 : Deployer la topologie

```bash
cd 43_snmp_enumeration
ansible-playbook playbooks/00_full_lab.yml
```

Le playbook cree automatiquement :
- Le projet GNS3 "Lab_43_SNMP_Enumeration"
- Les 4 nodes (NAT1, Switch1, Kali, Target)
- Les liens reseau
- Demarre tous les equipements

### Etape 4 : Verifier le deploiement

```bash
ansible-playbook playbooks/02_verify.yml
```

Resultat attendu :
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

> **Important** : La VM Target doit etre configuree manuellement car elle n'a pas d'IP au demarrage.

### Etape 1 : Connexion a la console Target

Dans GNS3, double-cliquer sur "Target" pour ouvrir la console.

**Credentials** : `debian` / `debian`

### Etape 2 : Configuration reseau

```bash
sudo -s

# Configurer DNS
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Configurer l'interface reseau
ip addr add 192.168.122.10/24 dev ens4
ip link set ens4 up

# Ajouter la route par defaut
ip route add default via 192.168.122.1

# Tester la connectivite
ping -c 2 8.8.8.8
```

### Etape 3 : Installation et configuration SNMP

```bash
# Mettre a jour et installer SNMP
apt update && apt install -y snmpd snmp

# Creer une configuration VULNERABLE (pour le lab)
cat > /etc/snmp/snmpd.conf << 'EOF'
# Configuration SNMP VULNERABLE - NE PAS UTILISER EN PRODUCTION!

# Ecoute sur toutes les interfaces
agentaddress udp:161

# Community strings par defaut (DANGER!)
rocommunity public
rwcommunity private

# Informations systeme exposees
sysLocation Server Room - Rack 42
sysContact admin@vulnerable-corp.local
sysName target-server

# Acces complet a l'arbre MIB
view all included .1
EOF

# Redemarrer le service
systemctl restart snmpd
systemctl enable snmpd

# Verifier que SNMP ecoute
ss -ulnp | grep 161
```

Resultat attendu :
```
UNCONN 0 0 0.0.0.0:161 0.0.0.0:* users:(("snmpd",pid=XXX,fd=6))
```

### Etape 4 : Test SNMP local

```bash
snmpwalk -v2c -c public localhost sysDescr
```

Resultat attendu :
```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux debian 6.1.0-22-cloud-amd64 ..."
```

---

## Exercices d'enumeration

### Exercice 1 : Decouverte du service SNMP

Depuis Kali (ou directement depuis Target pour ce lab) :

```bash
# Verifier que le port 161/UDP est ouvert
nmap -sU -p 161 192.168.122.10
```

### Exercice 2 : Enumeration systeme

```bash
# Informations systeme completes
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.1
```

**Questions** :
- Quel est le systeme d'exploitation ?
- Quel est le nom d'hote ?
- Qui est le contact administrateur ?

### Exercice 3 : Enumeration reseau

```bash
# Interfaces reseau
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.2

# Adresses IP
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.4.20.1.1

# Adresses MAC
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.2.2.1.6
```

### Exercice 4 : Enumeration des services

```bash
# Processus en cours
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.4.2.1.2

# Ports TCP en ecoute
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.6.13

# Ports UDP en ecoute
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.7.5.1.2
```

### Exercice 5 : Enumeration des logiciels

```bash
# Logiciels installes (attention: peut etre long)
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.6.3.1.2 | head -30
```

### Exercice 6 : Recherche de credentials

```bash
# Parametres des processus (peut contenir des mots de passe)
snmpwalk -v2c -c public 192.168.122.10 .1.3.6.1.2.1.25.4.2.1.5
```

---

## Reference des OIDs importants

| OID | Nom | Description |
|-----|-----|-------------|
| .1.3.6.1.2.1.1.1 | sysDescr | Description du systeme |
| .1.3.6.1.2.1.1.4 | sysContact | Contact administrateur |
| .1.3.6.1.2.1.1.5 | sysName | Nom d'hote |
| .1.3.6.1.2.1.1.6 | sysLocation | Localisation physique |
| .1.3.6.1.2.1.2.2.1.2 | ifDescr | Noms des interfaces |
| .1.3.6.1.2.1.2.2.1.6 | ifPhysAddress | Adresses MAC |
| .1.3.6.1.2.1.4.20.1.1 | ipAdEntAddr | Adresses IP |
| .1.3.6.1.2.1.6.13 | tcpConnTable | Connexions TCP |
| .1.3.6.1.2.1.7.5.1.2 | udpLocalPort | Ports UDP |
| .1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName | Processus en cours |
| .1.3.6.1.2.1.25.4.2.1.5 | hrSWRunParameters | Parametres processus |
| .1.3.6.1.2.1.25.6.3.1.2 | hrSWInstalledName | Logiciels installes |
| .1.3.6.1.2.1.25.2.3.1.3 | hrStorageDescr | Stockage |

---

## Outil snmp-check

`snmp-check` automatise l'enumeration SNMP et genere un rapport formate.

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
| Sortie | Brute (OIDs numeriques) | Formatee, lisible |
| Flexibilite | Haute | Basse |
| Cas d'usage | Requetes ciblees | Audit initial |

---

## Rapport de securite

Apres l'enumeration, rediger un rapport incluant :

### 1. Resume executif
- Cible : 192.168.122.10
- Severite globale : CRITIQUE

### 2. Vulnerabilites identifiees

| # | Vulnerabilite | Severite | Donnees exposees |
|---|---------------|----------|------------------|
| 1 | Community string "public" | CRITIQUE | Acces complet en lecture |
| 2 | Version OS exposee | HAUTE | Debian 6.1.0-22, kernel exact |
| 3 | Email admin expose | MOYENNE | admin@vulnerable-corp.local |
| 4 | Localisation exposee | MOYENNE | Server Room - Rack 42 |
| 5 | Liste des processus | HAUTE | sshd, snmpd, systemd... |
| 6 | Ports ouverts | HAUTE | SSH sur 0.0.0.0:22 |
| 7 | Paquets installes | MOYENNE | Versions exactes exposees |

### 3. Recommandations

1. **Migrer vers SNMPv3** avec authentification et chiffrement
2. **Changer la community string** si SNMPv2c obligatoire
3. **Restreindre les vues SNMP** pour limiter les OIDs accessibles
4. **Filtrer par IP source** avec des ACLs
5. **Configurer un firewall** pour limiter l'acces au port 161/UDP

---

## Difficultes rencontrees et solutions

### Probleme 1 : Template Kali introuvable

**Symptome** :
```
FAILED! => {"msg": "Template 'Kali' not found"}
```

**Cause** : Le nom du template dans GNS3 peut varier.

**Solution** : Verifier le nom exact dans GNS3 et mettre a jour `group_vars/all.yml` :
```yaml
template_names:
  kali: "kalilinux-kali-rolling"  # Nom exact dans GNS3
```

### Probleme 2 : Kali Docker trop minimaliste

**Symptome** : Le conteneur Kali n'a pas `ip`, `ping`, `snmpwalk`...

**Cause** : L'image Docker Kali est tres legere par defaut.

**Solution** : Effectuer l'enumeration depuis la Target elle-meme (localhost) ou utiliser une VM Kali complete.

### Probleme 3 : Target sans IP au demarrage

**Symptome** : La VM Target demarre mais n'a pas d'adresse IP.

**Cause** : Pas de serveur DHCP sur le reseau NAT pour la VM.

**Solution** : Configurer l'IP manuellement (voir section "Configuration manuelle de la cible").

### Probleme 4 : snmpwalk timeout

**Symptome** :
```
Timeout: No Response from 192.168.122.10
```

**Causes possibles** :
1. SNMP non installe sur la cible
2. Mauvaise community string
3. Firewall bloquant le port 161/UDP

**Solutions** :
```bash
# Sur la cible, verifier que snmpd tourne
systemctl status snmpd

# Verifier le port
ss -ulnp | grep 161

# Tester localement
snmpwalk -v2c -c public localhost sysDescr
```

### Probleme 5 : OIDs numeriques au lieu de noms

**Symptome** :
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

Checklist des elements a completer :

- [ ] Topologie deployee via Ansible
- [ ] Target configuree avec IP statique
- [ ] SNMP installe et configure sur Target
- [ ] Port 161/UDP accessible
- [ ] Informations systeme enumerees (OS, hostname)
- [ ] Interfaces reseau listees
- [ ] Processus en cours identifies
- [ ] Ports TCP/UDP documentes
- [ ] Logiciels installes enumeres
- [ ] Rapport de securite redige

---

## Pour aller plus loin

- **SNMPv3** : Configurer SNMPv3 avec authentification (MD5/SHA) et chiffrement (DES/AES)
- **Brute force** : Utiliser `onesixtyone` pour tester des community strings
- **SNMP write** : Explorer les possibilites avec `rwcommunity private`
- **Automatisation** : Creer un script Python avec la bibliotheque `pysnmp`

---

## References

- [Net-SNMP Documentation](http://www.net-snmp.org/docs/)
- [SNMP OID Repository](http://oid-info.com/)
- [HackTricks - SNMP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
