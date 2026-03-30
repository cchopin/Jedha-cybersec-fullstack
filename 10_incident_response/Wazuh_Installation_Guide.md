# Wazuh SIEM - Documentation d'installation complète

**Date :** 30 mars 2026
**Auteur :** tely / Claude Code
**Version Wazuh :** 4.11.2

---

## Table des matières

1. [Architecture](#1-architecture)
2. [Prérequis](#2-prérequis)
3. [Nettoyage du VPS](#3-nettoyage-du-vps)
4. [Installation du Wazuh Manager](#4-installation-du-wazuh-manager)
5. [Configuration Nginx reverse proxy + SSL](#5-configuration-nginx-reverse-proxy--ssl)
6. [Installation des agents](#6-installation-des-agents)
7. [Configuration des sources de logs](#7-configuration-des-sources-de-logs)
8. [Règles de détection personnalisées](#8-règles-de-détection-personnalisées)
9. [Active Response](#9-active-response)
10. [Monitors et alertes](#10-monitors-et-alertes)
11. [Dashboards](#11-dashboards)
12. [Maintenance et commandes utiles](#12-maintenance-et-commandes-utiles)
13. [Accès et identifiants](#13-accès-et-identifiants)
14. [Alertes Email](#14-alertes-email)
15. [Sécurisation (Hardening)](#15-sécurisation-hardening)
16. [Mises à jour automatiques](#16-mises-à-jour-automatiques)
17. [Firewall (iptables)](#17-firewall-iptables)
18. [VirusTotal](#18-virustotal)
19. [Threat Intelligence - Listes IP malveillantes](#19-threat-intelligence---listes-ip-malveillantes)
20. [Suricata (IDS réseau)](#20-suricata-ids-réseau)
21. [Rotation des index](#21-rotation-des-index)
22. [Backup automatique](#22-backup-automatique)

---

## 1. Architecture

```
┌───────────────────────────────────────────────────┐
│              VPS - darkforge                      │
│          57.128.168.155 (vps.tely.info)           │
│                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │   Wazuh     │  │   Wazuh      │  │  Wazuh   │  │
│  │   Indexer   │  │   Manager    │  │ Dashboard│  │
│  │  :9200      │  │  :1514/:1515 │  │  :5601   │  │
│  └─────────────┘  └──────────────┘  └──────────┘  │
│                                          ▲        │
│  ┌─────────────┐  ┌──────────────┐       │        │
│  │   Nginx     │  │   Hytale     │       │        │
│  │   :8443 SSL─┼──┘   Server     │       │        │
│  └─────────────┘  └──────────────┘       │        │
│         ▲                                │        │
└─────────┼────────────────────────────────┘        │
          │                                         │
          │ HTTPS :8443                             │
          │ (Let's Encrypt)                         │
          │                                         │
     ┌────┴────┐                                    │
     │ Browser │                                    │
     └─────────┘                                    │
                                                    │
    ┌────────────────┐          ┌────────────────┐  │
    │  Mac Studio    │          │  Raspberry Pi  │  │
    │  Agent :1514  ─┼──────────┼─ Agent :1514  ─┼──┘
    │  (macOS arm64) │          │  (Debian 12)   │
    └────────────────┘          └────────────────┘
```

**Composants :**
- **Wazuh Indexer** (OpenSearch) : stockage et indexation des alertes
- **Wazuh Manager** : moteur d'analyse, règles de détection, active response
- **Wazuh Dashboard** (OpenSearch Dashboards) : interface web
- **Filebeat** : transfert des alertes du manager vers l'indexer
- **Nginx** : reverse proxy HTTPS avec certificat Let's Encrypt
- **Agents** : collectent les logs et les envoient au manager

---

## 2. Prérequis

### VPS (darkforge)
- **OS :** Ubuntu (kernel 6.14.0-37-generic)
- **RAM :** 12 Go (minimum 4 Go recommandé)
- **Disque :** 96 Go (26 Go utilisés post-install)
- **IP publique :** 57.128.168.155
- **DNS :** vps.tely.info
- **SSH :** port 443

### Raspberry Pi (rasp)
- **OS :** Debian 12 (bookworm) aarch64
- **IP locale :** 192.168.0.239

### Mac Studio
- **OS :** macOS 26.3.1 arm64

---

## 3. Nettoyage du VPS

Avant l'installation, le VPS contenait Exegol (70 Go) et des outils CTF. Nettoyage effectué :

```bash
# Suppression Exegol
docker rm exegol-default
docker rmi nwodtuhs/exegol:free
sudo rm -rf ~/.exegol

# Suppression outils CTF
sudo rm -rf ~/go ~/go1.25.0.linux-amd64.tar.gz ~/iamb-* ~/vpn ~/wordlists ~/soc-tools ~/Downloads
rm -f ~/FOREST_*_bloodhound.zip

# Suppression nmap
sudo apt remove --purge nmap nmap-common -y
sudo apt autoremove -y
```

**Résultat :** disque passé de 89% à 18% d'utilisation.

---

## 4. Installation du Wazuh Manager

### 4.1. Téléchargement des fichiers d'installation

```bash
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.11/config.yml
```

### 4.2. Configuration (single-node)

```yaml
# config.yml
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"
  server:
    - name: wazuh-1
      ip: "127.0.0.1"
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
```

> **Note :** Utiliser `127.0.0.1` et non l'IP publique (le script refuse les IP publiques).

### 4.3. Génération des certificats

```bash
sudo bash wazuh-install.sh --generate-config-files
```

Crée `wazuh-install-files.tar` contenant certificats et mots de passe.

### 4.4. Installation de l'indexer

```bash
sudo bash wazuh-install.sh --wazuh-indexer node-1
```

> **Attention UFW :** S'assurer que les ports 9200 et 9300 sont accessibles en local.

### 4.5. Installation du serveur (manager + filebeat)

```bash
sudo bash wazuh-install.sh --wazuh-server wazuh-1
```

### 4.6. Initialisation du cluster

```bash
sudo bash wazuh-install.sh --start-cluster
```

### 4.7. Installation du dashboard

Le port 443 étant utilisé par SSH, le dashboard est installé sur le port **8443** :

```bash
sudo bash wazuh-install.sh --wazuh-dashboard dashboard -p 8443
```

### 4.8. Reconfiguration du dashboard en local

Pour permettre le reverse proxy Nginx, le dashboard est reconfiguré pour écouter uniquement en local :

```bash
# /etc/wazuh-dashboard/opensearch_dashboards.yml
server.port: 5601        # (au lieu de 8443)
server.host: 127.0.0.1   # (au lieu de 0.0.0.0)
```

```bash
sudo systemctl restart wazuh-dashboard
```

### 4.9. Ouverture des ports UFW

```bash
sudo ufw allow 8443/tcp comment 'Wazuh Dashboard'
sudo ufw allow 1514/tcp comment 'Wazuh Agent'
sudo ufw allow 1515/tcp comment 'Wazuh Agent Registration'
sudo ufw allow 80/tcp comment 'HTTP - LetsEncrypt'
```

### 4.10. Récupération du mot de passe admin

```bash
sudo tar -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -A1 'admin'
```

---

## 5. Configuration Nginx reverse proxy + SSL

### 5.1. Installation

```bash
sudo apt-get install nginx certbot python3-certbot-nginx -y
```

### 5.2. Certificat Let's Encrypt

```bash
sudo certbot certonly --nginx -d vps.tely.info --non-interactive --agree-tos --email tely@tely.info
```

Certificat enregistré dans :
- `/etc/letsencrypt/live/vps.tely.info/fullchain.pem`
- `/etc/letsencrypt/live/vps.tely.info/privkey.pem`

Renouvellement automatique configuré par certbot.

### 5.3. Configuration Nginx

```nginx
# /etc/nginx/sites-available/wazuh
server {
    listen 8443 ssl;
    server_name vps.tely.info;

    ssl_certificate /etc/letsencrypt/live/vps.tely.info/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vps.tely.info/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}
```

```bash
sudo ln -sf /etc/nginx/sites-available/wazuh /etc/nginx/sites-enabled/wazuh
sudo nginx -t
sudo systemctl reload nginx
```

**Accès :** `https://vps.tely.info:8443`

---

## 6. Installation des agents

### 6.1. Raspberry Pi (Debian 12 / aarch64)

```bash
# Ajout du dépôt Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

# Installation (version identique au manager)
sudo apt-get update
sudo WAZUH_MANAGER='57.128.168.155' WAZUH_AGENT_NAME='rasp' \
  apt-get install wazuh-agent=4.11.2-1 -y

# Configuration de l'adresse du manager
sudo sed -i 's/<address>.*<\/address>/<address>57.128.168.155<\/address>/' \
  /var/ossec/etc/ossec.conf

# Enregistrement et démarrage
sudo /var/ossec/bin/agent-auth -m 57.128.168.155
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent
```

> **Important :** La version de l'agent doit être <= à celle du manager. Si une version plus récente est installée, downgrader avec `--allow-downgrades`.

### 6.2. Mac Studio (macOS arm64)

```bash
# Téléchargement du package
curl -sO https://packages.wazuh.com/4.x/macos/wazuh-agent-4.11.2-1.arm64.pkg

# Installation
sudo WAZUH_MANAGER='57.128.168.155' WAZUH_AGENT_NAME='mac-cchopin' \
  installer -pkg ~/wazuh-agent-4.11.2-1.arm64.pkg -target /

# Correction de l'adresse manager (le pkg n'écrit pas toujours la variable)
sudo sed -i.bak 's/MANAGER_IP/57.128.168.155/' /Library/Ossec/etc/ossec.conf

# Enregistrement et démarrage
sudo /Library/Ossec/bin/agent-auth -m 57.128.168.155
sudo /Library/Ossec/bin/wazuh-control start
```

**Démarrage automatique :** Le fichier `/Library/LaunchDaemons/com.wazuh.agent.plist` est installé avec `RunAtLoad: true`.

### 6.3. Vérification des agents

```bash
# Sur le manager
sudo /var/ossec/bin/agent_control -l
```

Résultat attendu :
```
ID: 000, Name: darkforge (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: rasp, IP: any, Active
ID: 002, Name: Mac-Studio.local, IP: any, Active
```

---

## 7. Configuration des sources de logs

### 7.1. VPS (darkforge) - `/var/ossec/etc/ossec.conf`

Logs ajoutés dans la section `<ossec_config>` :

```xml
<!-- === NGINX === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/error.log</location>
</localfile>

<!-- === HYTALE SERVER === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/home/tely/hytale/Server/logs/*_server.log</location>
</localfile>

<!-- === FAIL2BAN === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/fail2ban.log</location>
</localfile>

<!-- === UFW FIREWALL === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

### 7.2. Raspberry Pi (rasp) - `/var/ossec/etc/ossec.conf`

```xml
<!-- === NGINX - SITES === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/crab.eve-goats.fr.access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/crab.eve-goats.fr.error.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/fc-advisor.eve-goats.fr.access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/fc-advisor.eve-goats.fr.error.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/news.eve-goats.fr.access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/news.eve-goats.fr.error.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/eve-dashboard.access.log</location>
</localfile>

<!-- === FAIL2BAN === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/fail2ban.log</location>
</localfile>

<!-- === ABUSIVE IPS CHECK === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/check_abusive_ips.log</location>
</localfile>

<!-- === DOCKER FC-ADVISOR === -->
<localfile>
  <log_format>syslog</log_format>
  <command>docker logs --tail 50 fc-advisor_web_1 2>&amp;1</command>
  <frequency>360</frequency>
</localfile>
```

### 7.3. Mac Studio - `/Library/Ossec/etc/ossec.conf`

```xml
<!-- === SYSTEM LOGS (macOS Unified Log) === -->
<localfile>
  <log_format>macos</log_format>
  <location>macos</location>
  <query type="trace" level="default">process == "sshd" OR process == "sudo"
    OR process == "loginwindow" OR process == "screensharingd"
    OR process == "tccd" OR eventMessage CONTAINS "authentication"
    OR eventMessage CONTAINS "failed"</query>
</localfile>

<!-- === WIFI === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wifi.log</location>
</localfile>

<!-- === INSTALL LOG === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/install.log</location>
</localfile>

<!-- === SYSTEM LOG === -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/system.log</location>
</localfile>
```

> **Après toute modification :** redémarrer le service correspondant.
> - VPS : `sudo systemctl restart wazuh-manager`
> - Rasp : `sudo systemctl restart wazuh-agent`
> - Mac : `sudo /Library/Ossec/bin/wazuh-control restart`

---

## 8. Règles de détection personnalisées

Fichier : `/var/ossec/etc/rules/local_rules.xml` sur le manager (darkforge)

### SSH
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100010  | 10    | SSH brute force (8+ échecs en 2min) |
| 100011  | 12    | SSH connexion réussie (vérifier si post-brute force) |
| 100012  | 10    | SSH tentative de connexion en root |

### Attaques Web
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100020  | 12    | Injection SQL détectée |
| 100021  | 12    | XSS détecté |
| 100022  | 12    | Path traversal détecté |
| 100023  | 8     | Scan de vulnérabilités web (wp-admin, .env, .git...) |
| 100024  | 14    | Tentative d'exécution de commande (RCE/Shellshock) |
| 100025  | 10    | Brute force de répertoires (15+ erreurs 404 en 1min) |

### Réseau / Firewall
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100030  | 10    | Port scan détecté (10+ blocs en 1min) |

### Fail2Ban
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100040  | 6     | IP bannie par Fail2Ban |
| 100041  | 3     | IP débannie par Fail2Ban |
| 100042  | 10    | Récidiviste banni (attaquant persistant) |

### Sudo
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100050  | 10    | Échecs sudo multiples (escalade de privilèges) |

### Intégrité des fichiers (FIM)
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100060  | 12    | Fichier système critique modifié (/etc/passwd, sudoers...) |
| 100061  | 8     | Fichier web modifié (défacement potentiel) |

### Hytale
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100070  | 3     | Événement serveur Hytale |
| 100071  | 8     | Erreur serveur Hytale |
| 100072  | 5     | Warning serveur Hytale |

### Threat Intelligence - IPs malveillantes
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100080  | 14    | Connexion depuis IP botnet C2 connue (abuse.ch) |
| 100081  | 10    | Connexion depuis IP malveillante connue (blocklist.de) |

### Commandes suspectes
| Rule ID | Level | Description |
|---------|-------|-------------|
| 100090  | 14    | Tentative de reverse shell |
| 100091  | 12    | Modification permissions dangereuse (chmod 777, setuid) |
| 100092  | 14    | Crypto-miner détecté (xmrig, monero...) |
| 100093  | 12    | Download & execute détecté |
| 100094  | 8     | Commandes de reconnaissance (whoami, linpeas...) |
| 100095  | 10    | Modification crontab |
| 100096  | 12    | Injection clé SSH (authorized_keys) |

### Niveaux de sévérité Wazuh
- **0-3** : Info
- **4-7** : Low
- **8-11** : Medium/High
- **12-14** : Critical
- **15** : Maximum

---

## 9. Active Response

> **Note :** Les Active Response Wazuh (firewall-drop) ont été **désactivées** car elles interféraient avec les règles iptables et provoquaient des lockouts SSH. Le blocage automatique est assuré par **Fail2Ban** à la place (voir section 15).

### IPs whitelistées

Configurées dans `/etc/fail2ban/jail.local` :
```
ignoreip = 127.0.0.1/8 82.67.154.147 192.168.0.0/24
```

Et dans `/var/ossec/etc/ossec.conf` (section `<global>`) :
```xml
<white_list>127.0.0.1</white_list>
<white_list>82.67.154.147</white_list>
<white_list>192.168.0.0/24</white_list>
```

---

## 10. Monitors et alertes

Configurés dans **OpenSearch Alerting** (`Alerting > Monitors` dans le dashboard).

| Monitor | Intervalle | Sévérité | Condition |
|---------|-----------|----------|-----------|
| Alertes Critiques (niveau 12+) | 1 min | 1 - Critical | rule.level >= 12 dans les 5 dernières min |
| SSH Brute Force | 2 min | 2 - High | 5+ échecs auth en 5min |
| Attaques Web (SQLi/XSS/RCE) | 1 min | 1 - Critical | Tout event groupe web_attack |
| Port Scan détecté | 2 min | 2 - High | 10+ blocs firewall même IP en 5min |
| Fichier système critique modifié | 5 min | 1 - Critical | Event syscheck level >= 10 |
| Agent déconnecté | 5 min | 3 - Medium | Message "Agent disconnected" |
| Abus Sudo | 2 min | 2 - High | 3+ mauvais mots de passe sudo en 5min |

---

## 11. Dashboards

Accessibles via le menu **OpenSearch Dashboards > Dashboard**.

| Dashboard | Description | Auto-refresh |
|-----------|-------------|-------------|
| **SOC Command Center** | KPIs (total alertes, critiques, agents, auth failures, FIM), timeline sévérité, heatmap agent x sévérité, tag cloud règles | 30s |
| **Nginx & Applications Web** | Requêtes par code HTTP, top IPs, alertes par site, top URLs, attaques web | 1min |
| **Firewall, SSH & Accès** | UFW connexions bloquées, top ports ciblés, top IPs bloquées, Fail2Ban bans, heatmap SSH, usernames tentés, commandes sudo | 30s |
| **Threat Intelligence & MITRE** | Tactiques MITRE, techniques MITRE, activité par agent, heatmap temporelle | 1min |
| **Compliance & Hardening** | Conformité PCI-DSS, SCA checks échoués par agent, détail des contrôles SCA | 5min |
| **Security Overview - Tely SOC** | Vue générale alertes, top agents, sévérité, MITRE, top règles, SCA | 1min |
| **Vulnérabilités & Intégrité Fichiers** | Vulnérabilités par sévérité, packages vulnérables, changements FIM, événements auth | 5min |

---

## 12. Maintenance et commandes utiles

### Vérifier l'état des services

```bash
# Sur le VPS
systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard filebeat nginx

# Lister les agents
sudo /var/ossec/bin/agent_control -l

# Vérifier la config avant redémarrage
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Redémarrer les services

```bash
# VPS - Manager complet
sudo systemctl restart wazuh-manager

# VPS - Dashboard
sudo systemctl restart wazuh-dashboard

# VPS - Indexer (si crash, recréer le log dir)
sudo mkdir -p /var/log/wazuh-indexer
sudo chown wazuh-indexer:wazuh-indexer /var/log/wazuh-indexer
sudo systemctl restart wazuh-indexer

# Raspberry Pi
sudo systemctl restart wazuh-agent

# Mac
sudo /Library/Ossec/bin/wazuh-control restart
```

### Logs utiles

```bash
# Manager
sudo tail -f /var/ossec/logs/ossec.log

# Alertes en temps réel
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Indexer
sudo tail -f /var/log/wazuh-indexer/wazuh-indexer.log

# Agent (Rasp)
sudo tail -f /var/ossec/logs/ossec.log

# Agent (Mac)
sudo tail -f /Library/Ossec/logs/ossec.log
```

### Renouvellement SSL

Le certificat Let's Encrypt se renouvelle automatiquement. Pour forcer :

```bash
sudo certbot renew --nginx
sudo systemctl reload nginx
```

### Débloquer une IP bannie par Fail2Ban

```bash
# Voir les IPs bannies
sudo fail2ban-client status sshd

# Débloquer manuellement
sudo fail2ban-client set sshd unbanip <IP>

# Lister toutes les règles iptables
sudo iptables -L INPUT -n --line-numbers
```

### Sauvegarder la configuration

Un backup automatique tourne chaque jour à 3h dans `/home/tely/wazuh-backup/` (repo git local, secrets filtrés).

```bash
# Backup manuel
sudo /usr/local/bin/wazuh-backup.sh

# Voir l'historique des backups
cd ~/wazuh-backup && git log --oneline
```

---

## 13. Accès et identifiants

| Service | URL / Connexion | Login | Password |
|---------|----------------|-------|----------|
| **Wazuh Dashboard** | `https://vps.tely.info:8443` | `admin` | `KD8Jus6+SDQcAV?3mGIS6FFx*D7pI+U*` |
| **VPS SSH** | `ssh tely@vps.tely.info -p 443` | tely | (clé SSH) |
| **Raspberry Pi SSH** | `ssh tely@192.168.0.239` | tely | (clé SSH) |

### Fichiers importants

| Fichier | Machine | Description |
|---------|---------|-------------|
| `/var/ossec/etc/ossec.conf` | VPS | Config principale du manager |
| `/var/ossec/etc/rules/local_rules.xml` | VPS | Règles de détection custom |
| `/var/ossec/etc/decoders/local_decoder.xml` | VPS | Décodeurs custom |
| `/etc/nginx/sites-available/wazuh` | VPS | Config reverse proxy |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | VPS | Config dashboard |
| `/var/ossec/etc/ossec.conf` | Rasp | Config agent Raspberry Pi |
| `/Library/Ossec/etc/ossec.conf` | Mac | Config agent Mac |
| `/home/tely/wazuh-install-files.tar` | VPS | Certificats et mots de passe |

---

## 14. Alertes Email

### Configuration

- **Destinataire :** telykin@proton.me
- **Expéditeur :** wazuh-soc@tely.info
- **SMTP :** localhost (postfix, loopback-only)
- **Max :** 12 emails/heure

### Événements notifiés par email

| Événement | Rule ID | Délai |
|-----------|---------|-------|
| Toute alerte level >= 12 | * | Immédiat |
| SSH brute force | 100010 | Immédiat |
| Attaques web (SQLi/XSS/RCE) | groupe web_attack | Immédiat |
| Port scan | 100030 | Immédiat |
| Fail2Ban récidiviste | 100042 | Immédiat |
| Fichier critique modifié | 100060 | Immédiat |
| Hytale crash | 100071 | Groupé |

Configuration dans `/var/ossec/etc/ossec.conf`, sections `<global>` et `<email_alerts>`.

---

## 15. Sécurisation (Hardening)

### Fail2Ban - Jails actifs

| Jail | Protège | MaxRetry | Bantime |
|------|---------|----------|---------|
| sshd | SSH ports 443/2222 | 3 | 2h |
| nginx-http-auth | Auth nginx | 3 | 1h |
| nginx-botsearch | Scans/bots | 10 en 60s | 1h |
| nginx-limit-req | Rate limit (ports 80,8443) | 5 | 1h |
| recidive | Récidivistes | 3 bans/24h | 24h |

> **Important :** Les jails nginx ne couvrent que les ports 80 et 8443 (pas 443 qui est SSH). L'IP 82.67.154.147 et le réseau 192.168.0.0/24 sont whitelistés (`ignoreip`).

Config : `/etc/fail2ban/jail.local`

### Nginx Hardening

Fichier `/etc/nginx/conf.d/security.conf` :
- Headers de sécurité (X-Frame-Options, X-Content-Type-Options, XSS-Protection, CSP, Referrer-Policy)
- Rate limiting : 10 req/s avec burst de 20

### Kernel Hardening

Fichier `/etc/sysctl.d/99-security.conf` :
- Protection anti-spoofing (rp_filter)
- Désactivation du source routing
- Ignore des redirections ICMP
- SYN flood protection (syncookies)
- Ignore des broadcasts ICMP
- Log des paquets martiens

### Postfix

- Écoute uniquement en loopback (pas de relay ouvert)
- Banner minimal (pas de version)
- Relais restreint aux réseaux locaux

---

## 16. Mises à jour automatiques

### Configuration

Fichier `/etc/apt/apt.conf.d/50unattended-upgrades` :

```
Unattended-Upgrade::Allowed-Origins {
    "Wazuh:stable";
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Mail "telykin@proton.me";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
```

Fichier `/etc/apt/apt.conf.d/20auto-upgrades` :

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

Packages mis à jour automatiquement :
- Sécurité Ubuntu
- Wazuh (manager, indexer, dashboard, filebeat)

Un email est envoyé à telykin@proton.me après chaque mise à jour.

---

## 17. Firewall (iptables)

> **Note :** UFW a été remplacé par des règles iptables directes car UFW interférait avec Fail2Ban et causait des lockouts SSH.

### Configuration

Les règles sont persistées dans `/etc/iptables/rules.v4` via `iptables-persistent`.

```bash
# Policy par défaut
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback + established
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Services
iptables -A INPUT -p tcp --dport 443 -j ACCEPT    # SSH
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT   # SSH alt
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT   # Wazuh agent
iptables -A INPUT -p tcp --dport 1515 -j ACCEPT   # Wazuh registration
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT   # Dashboard
iptables -A INPUT -p tcp --dport 80 -j ACCEPT     # Let's Encrypt
iptables -A INPUT -p udp --dport 51820 -j ACCEPT  # WireGuard
iptables -A INPUT -p udp --dport 5520 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT  # Ping
```

### Sauvegarder après modification

```bash
sudo bash -c 'iptables-save > /etc/iptables/rules.v4'
```

---

## 18. VirusTotal

### Configuration

Intégré dans `/var/ossec/etc/ossec.conf` :

```xml
<integration>
  <name>virustotal</name>
  <api_key>VOTRE_API_KEY</api_key>
  <rule_id>554,550,553</rule_id>
  <alert_format>json</alert_format>
</integration>
```

- **Déclenchement :** à chaque alerte FIM (fichier ajouté/modifié, règles 550/553/554)
- **Action :** le hash du fichier est vérifié contre la base VirusTotal
- **Limite :** 4 requêtes/minute (API gratuite)

---

## 19. Threat Intelligence - Listes IP malveillantes

### Sources

| Source | Contenu | URL |
|--------|---------|-----|
| abuse.ch (Feodo Tracker) | IPs de serveurs C2 botnet | feodotracker.abuse.ch |
| blocklist.de | IPs d'attaquants connus (48h) | lists.blocklist.de |

### Configuration

- **Liste CDB :** `/var/ossec/etc/lists/malicious-ips` (~5000 entrées)
- **Mise à jour :** automatique chaque jour à 4h (`/etc/cron.d/update-ip-lists`)
- **Script :** `/var/ossec/etc/lists/update-ip-lists.sh`

### Mise à jour manuelle

```bash
sudo bash /var/ossec/etc/lists/update-ip-lists.sh
sudo systemctl restart wazuh-manager
```

---

## 20. Suricata (IDS réseau)

### Installation

```bash
sudo apt-get install -y suricata suricata-update
sudo suricata-update  # Télécharge ~49000 règles
sudo systemctl enable suricata
sudo systemctl start suricata
```

### Configuration

- **Fichier :** `/etc/suricata/suricata.yaml`
- **Interface :** ens3
- **Logs :** `/var/log/suricata/eve.json` (format JSON)
- **Règles :** `/var/lib/suricata/rules/suricata.rules` (~49000 règles)

### Intégration Wazuh

Ajouté dans `/var/ossec/etc/ossec.conf` :

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Wazuh parse automatiquement les alertes Suricata (alertes réseau, signatures, anomalies) et les affiche dans le dashboard.

### Mise à jour des règles

```bash
sudo suricata-update
sudo systemctl restart suricata
```

---

## 21. Rotation des index

### Policy ISM (Index State Management)

Les index Wazuh sont automatiquement supprimés après **90 jours** via une policy OpenSearch ISM.

- **Index concernés :** `wazuh-alerts-*`, `wazuh-monitoring-*`, `wazuh-statistics-*`
- **Vérification :** dans le dashboard, menu OpenSearch > Index Management > State management policies

---

## 22. Backup automatique

### Configuration

- **Script :** `/usr/local/bin/wazuh-backup.sh`
- **Destination :** `/home/tely/wazuh-backup/` (repo git local)
- **Fréquence :** chaque jour à 3h (`/etc/cron.d/wazuh-backup`)
- **Secrets :** automatiquement filtrés (API keys, passwords remplacés par REDACTED)

### Fichiers sauvegardés

| Fichier | Description |
|---------|-------------|
| `ossec.conf.bak` | Config principale Wazuh (secrets filtrés) |
| `local_rules.xml.bak` | Règles de détection custom |
| `local_decoder.xml.bak` | Décodeurs custom |
| `nginx-wazuh.conf.bak` | Config reverse proxy |
| `dashboard.yml.bak` | Config dashboard (password filtré) |
| `fail2ban-jail.bak` | Config Fail2Ban |
| `iptables-rules.bak` | Règles firewall |
| `suricata.yaml.bak` | Config Suricata IDS |

### Restauration

```bash
cd ~/wazuh-backup
git log --oneline                    # Voir l'historique
git diff HEAD~1                      # Voir les changements
git checkout <commit> -- <fichier>   # Restaurer un fichier
```

---

## Annexe : Ports réseau

| Port | Protocole | Service | Direction |
|------|-----------|---------|-----------|
| 443/tcp | SSH | OpenSSH (VPS) | Entrant |
| 1514/tcp | Wazuh | Communication agent → manager | Entrant |
| 1515/tcp | Wazuh | Enregistrement agent | Entrant |
| 5601/tcp | HTTPS | Dashboard (local uniquement) | Local |
| 8443/tcp | HTTPS | Nginx reverse proxy → Dashboard | Entrant |
| 9200/tcp | HTTPS | Indexer API (local uniquement) | Local |
| 80/tcp | HTTP | Let's Encrypt ACME challenge | Entrant |
