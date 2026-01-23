# Comprendre les services exposés

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

Un système Linux n'est pas isolé : il communique avec d'autres machines via des services réseau. Ces services sont essentiels au fonctionnement, mais ils représentent aussi des points d'entrée potentiels pour les attaquants. Dans cette leçon, vous apprendrez :

- comment identifier les services en écoute sur votre système,
- comment utiliser nmap pour scanner les ports,
- comment analyser les services exposés,
- quels sont les risques associés aux services courants.

---

## Ports et services

### Qu'est-ce qu'un port ?

Un port est un numéro (de 0 à 65535) qui identifie un service spécifique sur une machine. Quand une application écoute sur un port, elle attend des connexions entrantes.

### Catégories de ports

| Plage | Nom | Description |
|-------|-----|-------------|
| 0-1023 | Ports privilégiés | Réservés aux services système (root requis) |
| 1024-49151 | Ports enregistrés | Utilisés par des applications connues |
| 49152-65535 | Ports dynamiques | Utilisés pour les connexions temporaires |

### Ports courants

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | Transfert de fichiers |
| 22 | SSH | Accès distant sécurisé |
| 23 | Telnet | Accès distant non sécurisé |
| 25 | SMTP | Envoi d'emails |
| 53 | DNS | Résolution de noms |
| 80 | HTTP | Web non sécurisé |
| 443 | HTTPS | Web sécurisé |
| 3306 | MySQL | Base de données MySQL |
| 5432 | PostgreSQL | Base de données PostgreSQL |
| 6379 | Redis | Cache/base de données en mémoire |
| 27017 | MongoDB | Base de données NoSQL |

---

## Identifier les services en écoute

### Avec ss (recommandé)

`ss` est l'outil moderne pour examiner les sockets :

```bash
# Lister tous les ports en écoute (TCP et UDP)
$ ss -tuln
Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*
tcp    LISTEN  0       511     0.0.0.0:80          0.0.0.0:*
tcp    LISTEN  0       128     127.0.0.1:3306      0.0.0.0:*

# Avec les noms de processus
$ sudo ss -tulnp
tcp  LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
tcp  LISTEN  0  511  0.0.0.0:80  0.0.0.0:*  users:(("nginx",pid=5678,fd=6))
```

| Option | Description |
|--------|-------------|
| `-t` | TCP |
| `-u` | UDP |
| `-l` | Sockets en écoute seulement |
| `-n` | Afficher les numéros de port (pas les noms) |
| `-p` | Afficher les processus (root requis) |

### Avec netstat (legacy)

```bash
# Équivalent à ss -tuln
$ netstat -tuln

# Avec les processus
$ sudo netstat -tulnp
```

### Avec lsof

```bash
# Tous les fichiers réseau
$ sudo lsof -i

# Ports en écoute seulement
$ sudo lsof -i -P -n | grep LISTEN

# Un port spécifique
$ sudo lsof -i :22
```

### Analyser les résultats

```bash
$ ss -tulnp | grep LISTEN
tcp   LISTEN  0  128  0.0.0.0:22     0.0.0.0:*    # SSH accessible de partout
tcp   LISTEN  0  511  127.0.0.1:3306 0.0.0.0:*    # MySQL local seulement
tcp   LISTEN  0  128  :::80          :::*          # HTTP sur IPv6
```

| Adresse | Signification |
|---------|---------------|
| `0.0.0.0:port` | Écoute sur toutes les interfaces IPv4 |
| `127.0.0.1:port` | Écoute uniquement en local |
| `:::port` | Écoute sur toutes les interfaces IPv6 |
| `::1:port` | Écoute uniquement en local IPv6 |

---

## Scanner avec nmap

**nmap** est l'outil de référence pour scanner les ports et découvrir les services.

### Installation

```bash
# Debian/Ubuntu
$ sudo apt install nmap

# Red Hat/CentOS
$ sudo dnf install nmap
```

### Scans de base

```bash
# Scan TCP des 1000 ports les plus courants
$ nmap 192.168.1.1

# Scan de tous les ports TCP
$ nmap -p- 192.168.1.1

# Scan d'une plage de ports
$ nmap -p 1-1000 192.168.1.1

# Scan de ports spécifiques
$ nmap -p 22,80,443 192.168.1.1

# Scan UDP (plus lent)
$ sudo nmap -sU 192.168.1.1

# Scan TCP + UDP
$ sudo nmap -sS -sU 192.168.1.1
```

### Détection de services

```bash
# Détection de version des services
$ nmap -sV 192.168.1.1
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3
80/tcp  open  http    nginx 1.18.0

# Détection aggressive (OS, versions, scripts)
$ nmap -A 192.168.1.1

# Scripts de détection de vulnérabilités
$ nmap --script vuln 192.168.1.1
```

### Types de scans

| Option | Type | Description |
|--------|------|-------------|
| `-sS` | SYN scan | Rapide, furtif (défaut avec root) |
| `-sT` | TCP connect | Connexion complète, plus lent |
| `-sU` | UDP scan | Scan des ports UDP |
| `-sV` | Version detection | Identifie les versions des services |
| `-sC` | Script scan | Exécute les scripts par défaut |
| `-O` | OS detection | Détecte le système d'exploitation |

### Scanner son propre système

```bash
# Scan local
$ nmap localhost
$ nmap 127.0.0.1

# Depuis l'extérieur (avec une autre machine ou via IP publique)
$ nmap <votre_ip_publique>
```

### Sortie et rapports

```bash
# Sortie normale vers fichier
$ nmap -oN scan.txt 192.168.1.1

# Sortie XML
$ nmap -oX scan.xml 192.168.1.1

# Sortie grepable
$ nmap -oG scan.gnmap 192.168.1.1

# Toutes les sorties
$ nmap -oA scan 192.168.1.1
```

---

## Analyse des services exposés

### Vérifier un service spécifique

```bash
# Qui écoute sur le port 80 ?
$ sudo ss -tulnp | grep :80
$ sudo lsof -i :80

# Quelle version ?
$ nmap -sV -p 80 localhost
```

### Services problématiques

| Service | Risque | Recommandation |
|---------|--------|----------------|
| Telnet (23) | Texte clair | Utiliser SSH |
| FTP (21) | Texte clair | Utiliser SFTP/SCP |
| MySQL (3306) | Accès direct DB | Limiter à localhost |
| Redis (6379) | Souvent sans auth | Configurer auth + bind local |
| MongoDB (27017) | Auth désactivée par défaut | Activer auth + bind local |
| Elasticsearch (9200) | Pas d'auth par défaut | Activer X-Pack/auth |

### Vérification des configurations

```bash
# MySQL - vérifier l'adresse d'écoute
$ grep bind-address /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1  # OK

# Redis - vérifier le bind
$ grep bind /etc/redis/redis.conf
bind 127.0.0.1  # OK

# SSH - vérifier la configuration
$ grep -E "^(Port|PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config
```

---

## Réduire la surface d'attaque

### Désactiver les services inutiles

```bash
# Lister les services actifs
$ systemctl list-units --type=service --state=running

# Désactiver un service
$ sudo systemctl stop nom_service
$ sudo systemctl disable nom_service

# Vérifier
$ systemctl is-enabled nom_service
```

### Limiter les interfaces d'écoute

Au lieu d'écouter sur `0.0.0.0` (toutes les interfaces), configurer les services pour écouter uniquement sur les interfaces nécessaires.

**Exemple pour MySQL :**
```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1
```

**Exemple pour Redis :**
```conf
# /etc/redis/redis.conf
bind 127.0.0.1
```

### Utiliser un pare-feu

Même si un service est configuré pour écouter sur toutes les interfaces, le pare-feu peut bloquer les connexions externes (voir la leçon suivante sur les pare-feu).

---

## Surveillance continue

### Détecter les nouveaux ports en écoute

```bash
# Script de surveillance simple
#!/bin/bash
PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}' | sort)
BASELINE="/var/log/baseline_ports.txt"

if [ -f "$BASELINE" ]; then
    diff <(cat "$BASELINE") <(echo "$PORTS") && echo "OK" || echo "ALERTE: Ports changés!"
else
    echo "$PORTS" > "$BASELINE"
    echo "Baseline créée"
fi
```

### Alertes avec auditd

```bash
# Surveiller les connexions réseau
$ sudo auditctl -a always,exit -F arch=b64 -S bind -k network_bind
$ sudo auditctl -a always,exit -F arch=b64 -S listen -k network_listen

# Rechercher les événements
$ sudo ausearch -k network_bind
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Port** | Numéro identifiant un service sur une machine |
| **Socket** | Point de communication réseau (IP:port) |
| **TCP** | Transmission Control Protocol - Protocole de transport fiable |
| **UDP** | User Datagram Protocol - Protocole de transport non fiable mais rapide |
| **nmap** | Network Mapper - Outil de scan de ports |
| **ss** | Socket Statistics - Outil pour examiner les sockets |
| **netstat** | Network Statistics - Ancien outil pour les stats réseau |
| **lsof** | List Open Files - Liste les fichiers ouverts (incluant sockets) |
| **SYN scan** | Scan TCP semi-ouvert (stealth) |
| **Service fingerprinting** | Identification des versions de services |
| **Attack surface** | Surface d'attaque - Ensemble des points d'entrée potentiels |

---

## Récapitulatif des commandes

### Identification des services

| Commande | Description |
|----------|-------------|
| `ss -tuln` | Lister les ports en écoute |
| `ss -tulnp` | Avec les processus (root) |
| `netstat -tuln` | Alternative à ss |
| `lsof -i -P -n` | Lister les connexions réseau |
| `lsof -i :port` | Voir qui utilise un port |

### Scan avec nmap

| Commande | Description |
|----------|-------------|
| `nmap host` | Scan TCP des ports courants |
| `nmap -p- host` | Scan de tous les ports |
| `nmap -p 22,80,443 host` | Scan de ports spécifiques |
| `nmap -sV host` | Détection des versions |
| `nmap -A host` | Scan agressif (OS, versions, scripts) |
| `nmap -sU host` | Scan UDP |
| `nmap --script vuln host` | Détection de vulnérabilités |
| `nmap -oN fichier host` | Sauvegarder les résultats |

### Gestion des services

| Commande | Description |
|----------|-------------|
| `systemctl list-units --type=service` | Lister les services |
| `systemctl status service` | Statut d'un service |
| `systemctl stop service` | Arrêter un service |
| `systemctl disable service` | Désactiver au démarrage |

---

## Ressources

- nmap Official Documentation - nmap.org
- Linux Networking Commands - Red Hat
- Service Enumeration - OWASP

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Nmap](https://tryhackme.com/room/furthernmap) | Maîtriser nmap |
| TryHackMe | [Nmap Live Host Discovery](https://tryhackme.com/room/nmap01) | Découverte d'hôtes |
| TryHackMe | [Network Services](https://tryhackme.com/room/dvnetworkservices) | Services réseau courants |
| TryHackMe | [Network Services 2](https://tryhackme.com/room/dvnetworkservices2) | Suite services réseau |
| HackTheBox | [Starting Point](https://app.hackthebox.com/starting-point) | Énumération de services |
