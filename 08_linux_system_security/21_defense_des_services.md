# Défense des services

**Durée : 60 min**

## Ce que vous allez apprendre dans ce cours

Même avec un pare-feu correctement configuré, les services exposés restent des cibles potentielles. Dans cette leçon, vous apprendrez à durcir les services les plus courants pour réduire les risques d'intrusion. Vous découvrirez :

- comment sécuriser SSH,
- comment configurer fail2ban pour bloquer les attaques par force brute,
- les principes de durcissement des services web,
- comment protéger les bases de données.

---

## Durcissement de SSH

SSH est souvent le service le plus critique : c'est la porte d'entrée pour l'administration. Sa sécurisation est primordiale.

### Configuration de base

Le fichier de configuration principal est `/etc/ssh/sshd_config`.

```bash
# Éditer la configuration
$ sudo nano /etc/ssh/sshd_config
```

### Options de sécurité recommandées

```bash
# /etc/ssh/sshd_config

# Changer le port par défaut (security through obscurity, optionnel)
Port 2222

# Désactiver le login root
PermitRootLogin no

# Désactiver l'authentification par mot de passe
PasswordAuthentication no

# Activer uniquement l'authentification par clé
PubkeyAuthentication yes

# Désactiver les méthodes d'authentification faibles
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Limiter les utilisateurs autorisés
AllowUsers admin deployer

# Ou limiter par groupe
AllowGroups ssh-users

# Désactiver le forwarding X11 si non utilisé
X11Forwarding no

# Désactiver le forwarding d'agent si non utilisé
AllowAgentForwarding no

# Timeout de connexion inactive
ClientAliveInterval 300
ClientAliveCountMax 2

# Limiter les tentatives d'authentification
MaxAuthTries 3

# Désactiver les protocoles anciens (SSH v1)
Protocol 2

# Utiliser des algorithmes de chiffrement forts
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512

# Afficher une bannière d'avertissement
Banner /etc/ssh/banner
```

### Appliquer les changements

```bash
# Vérifier la syntaxe
$ sudo sshd -t

# Redémarrer SSH
$ sudo systemctl restart sshd
```

### Authentification par clé

```bash
# Sur le client : générer une paire de clés
$ ssh-keygen -t ed25519 -a 100 -C "utilisateur@machine"

# Copier la clé publique sur le serveur
$ ssh-copy-id -i ~/.ssh/id_ed25519.pub user@serveur

# Ou manuellement sur le serveur
$ mkdir -p ~/.ssh
$ chmod 700 ~/.ssh
$ echo "clé_publique" >> ~/.ssh/authorized_keys
$ chmod 600 ~/.ssh/authorized_keys
```

### Bonnes pratiques clés SSH

| Pratique | Description |
|----------|-------------|
| Utiliser ed25519 | Algorithme moderne et sûr |
| Protéger la clé privée | Jamais la partager, utiliser une passphrase |
| Rotation des clés | Changer régulièrement les clés |
| Une clé par machine | Ne pas réutiliser les clés |

---

## fail2ban

**fail2ban** surveille les logs et bloque automatiquement les IP qui montrent des comportements malveillants (tentatives de connexion échouées).

### Installation

```bash
# Debian/Ubuntu
$ sudo apt install fail2ban

# Red Hat/CentOS
$ sudo dnf install fail2ban

# Démarrer et activer
$ sudo systemctl enable fail2ban
$ sudo systemctl start fail2ban
```

### Configuration de base

fail2ban utilise deux types de fichiers :
- `jail.conf` : configuration par défaut (ne pas modifier)
- `jail.local` : vos personnalisations

```bash
# Créer le fichier local
$ sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
# Temps de bannissement (10 minutes)
bantime = 10m

# Fenêtre de temps pour compter les échecs
findtime = 10m

# Nombre d'échecs avant bannissement
maxretry = 5

# Action par défaut
banaction = nftables-multiport

# Email pour les notifications (optionnel)
destemail = admin@example.com
sender = fail2ban@example.com
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
```

### Commandes fail2ban

```bash
# Statut général
$ sudo fail2ban-client status

# Statut d'une jail spécifique
$ sudo fail2ban-client status sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed: 2
|  |- Total failed: 15
|  `- File list: /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned: 3
   `- Banned IP list: 10.0.0.5

# Débannir une IP
$ sudo fail2ban-client set sshd unbanip 10.0.0.5

# Bannir manuellement une IP
$ sudo fail2ban-client set sshd banip 10.0.0.6

# Recharger la configuration
$ sudo fail2ban-client reload
```

### Jails pour autres services

```ini
# /etc/fail2ban/jail.local

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 3

[postfix]
enabled = true
port = smtp,465,587
filter = postfix
logpath = /var/log/mail.log
maxretry = 5
```

---

## Sécurisation des serveurs web

### Nginx

```nginx
# /etc/nginx/nginx.conf

# Cacher la version
server_tokens off;

# Headers de sécurité
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self';" always;

# Désactiver les méthodes HTTP inutiles
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}

# Limiter la taille des requêtes
client_max_body_size 10M;

# Timeout
client_body_timeout 10s;
client_header_timeout 10s;

# Rate limiting
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

server {
    limit_req zone=req_limit burst=20 nodelay;
    limit_conn conn_limit 10;
}
```

### Apache

```apache
# /etc/apache2/conf-enabled/security.conf

# Cacher la version
ServerTokens Prod
ServerSignature Off

# Headers de sécurité
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"

# Désactiver le listing de répertoires
<Directory /var/www/>
    Options -Indexes
</Directory>

# Limiter les méthodes HTTP
<Directory /var/www/>
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
```

### HTTPS avec Let's Encrypt

```bash
# Installer certbot
$ sudo apt install certbot python3-certbot-nginx

# Obtenir un certificat
$ sudo certbot --nginx -d example.com -d www.example.com

# Renouvellement automatique
$ sudo certbot renew --dry-run
```

---

## Sécurisation des bases de données

### MySQL/MariaDB

```bash
# Script de sécurisation initial
$ sudo mysql_secure_installation
```

Configuration dans `/etc/mysql/mysql.conf.d/mysqld.cnf` :

```ini
[mysqld]
# Écouter uniquement en local
bind-address = 127.0.0.1

# Désactiver le chargement de fichiers locaux
local-infile = 0

# Désactiver le symbolic-links
symbolic-links = 0

# Journalisation des requêtes lentes
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
```

Bonnes pratiques utilisateurs :

```sql
-- Créer un utilisateur avec privilèges limités
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'motdepasse_fort';
GRANT SELECT, INSERT, UPDATE, DELETE ON mabase.* TO 'appuser'@'localhost';

-- Ne jamais utiliser root pour les applications
-- Supprimer les utilisateurs anonymes
DELETE FROM mysql.user WHERE User='';

-- Supprimer les bases de test
DROP DATABASE IF EXISTS test;
```

### PostgreSQL

Configuration dans `/etc/postgresql/15/main/postgresql.conf` :

```ini
# Écouter uniquement en local
listen_addresses = 'localhost'

# Activer SSL pour les connexions distantes (si nécessaires)
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'

# Journalisation
log_connections = on
log_disconnections = on
log_statement = 'ddl'
```

Configuration de l'authentification dans `/etc/postgresql/15/main/pg_hba.conf` :

```
# TYPE  DATABASE  USER      ADDRESS        METHOD
local   all       postgres                 peer
local   all       all                      peer
host    all       all       127.0.0.1/32   scram-sha-256
```

### Redis

Configuration dans `/etc/redis/redis.conf` :

```ini
# Écouter uniquement en local
bind 127.0.0.1

# Mode protégé
protected-mode yes

# Mot de passe
requirepass motdepasse_tres_fort

# Désactiver les commandes dangereuses
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command DEBUG ""
```

---

## Surveillance et détection

### Centraliser les logs

```bash
# Configurer rsyslog pour envoyer les logs à un serveur central
# /etc/rsyslog.d/50-remote.conf
*.* @logserver.example.com:514
```

### Alertes avec logwatch

```bash
# Installer logwatch
$ sudo apt install logwatch

# Exécution manuelle
$ sudo logwatch --detail high --mailto admin@example.com --range yesterday

# Configuration pour envoi quotidien
$ sudo nano /etc/cron.daily/00logwatch
```

### Surveillance des fichiers critiques

```bash
# Avec AIDE
$ sudo aide --check

# Avec inotifywait
$ inotifywait -m /etc/ssh/sshd_config -e modify
```

---

## Checklist de durcissement

### SSH

- [ ] Désactiver le login root
- [ ] Utiliser l'authentification par clé uniquement
- [ ] Changer le port par défaut (optionnel)
- [ ] Limiter les utilisateurs autorisés
- [ ] Configurer des timeouts
- [ ] Utiliser des algorithmes de chiffrement modernes

### Services web

- [ ] Cacher les versions des logiciels
- [ ] Ajouter les headers de sécurité
- [ ] Configurer HTTPS avec des certificats valides
- [ ] Activer le rate limiting
- [ ] Désactiver les méthodes HTTP inutiles

### Bases de données

- [ ] Écouter uniquement sur localhost
- [ ] Utiliser des utilisateurs avec privilèges minimaux
- [ ] Activer l'authentification forte
- [ ] Désactiver les fonctionnalités dangereuses

### Général

- [ ] Installer et configurer fail2ban
- [ ] Centraliser les logs
- [ ] Mettre en place des alertes

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **SSH** | Secure Shell - Protocole de connexion sécurisée |
| **fail2ban** | Outil de protection contre les attaques par force brute |
| **Jail** | Configuration fail2ban pour un service spécifique |
| **Brute force** | Attaque par essais successifs de mots de passe |
| **Rate limiting** | Limitation du nombre de requêtes |
| **HTTPS** | HTTP sécurisé avec TLS |
| **TLS** | Transport Layer Security - Chiffrement des communications |
| **Let's Encrypt** | Autorité de certification gratuite |
| **CSP** | Content Security Policy - Politique de sécurité du contenu |
| **HSTS** | HTTP Strict Transport Security - Force l'utilisation de HTTPS |

---

## Récapitulatif des commandes

### SSH

| Commande | Description |
|----------|-------------|
| `sshd -t` | Vérifier la syntaxe de la configuration |
| `systemctl restart sshd` | Redémarrer SSH |
| `ssh-keygen -t ed25519` | Générer une paire de clés |
| `ssh-copy-id user@host` | Copier la clé publique |

### fail2ban

| Commande | Description |
|----------|-------------|
| `fail2ban-client status` | Statut général |
| `fail2ban-client status sshd` | Statut d'une jail |
| `fail2ban-client set jail unbanip IP` | Débannir une IP |
| `fail2ban-client set jail banip IP` | Bannir une IP |
| `fail2ban-client reload` | Recharger la config |

### Serveurs web

| Commande | Description |
|----------|-------------|
| `nginx -t` | Vérifier la syntaxe Nginx |
| `apache2ctl configtest` | Vérifier la syntaxe Apache |
| `certbot --nginx` | Obtenir un certificat Let's Encrypt |
| `certbot renew` | Renouveler les certificats |

### Bases de données

| Commande | Description |
|----------|-------------|
| `mysql_secure_installation` | Sécuriser MySQL |
| `sudo -u postgres psql` | Se connecter à PostgreSQL |
| `redis-cli ping` | Tester Redis |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/ssh/sshd_config` | Configuration SSH |
| `/etc/fail2ban/jail.local` | Configuration fail2ban |
| `/etc/nginx/nginx.conf` | Configuration Nginx |
| `/etc/mysql/mysql.conf.d/mysqld.cnf` | Configuration MySQL |
| `/etc/postgresql/*/main/pg_hba.conf` | Authentification PostgreSQL |
| `/etc/redis/redis.conf` | Configuration Redis |

---

## Ressources

- OpenSSH Security Best Practices - ssh.com
- fail2ban Documentation - fail2ban.org
- Mozilla SSL Configuration Generator
- CIS Benchmarks - cisecurity.org

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Hardening](https://tryhackme.com/room/dvlinuxhardening) | Durcissement global |
| TryHackMe | [Network Services](https://tryhackme.com/room/dvnetworkservices) | Attaques sur les services |
| TryHackMe | [Brute Force](https://tryhackme.com/room/dvbruteforce) | Attaques par force brute |
| TryHackMe | [SQL Injection](https://tryhackme.com/room/dvinjection) | Sécurité bases de données |
| HackTheBox | [Starting Point](https://app.hackthebox.com/starting-point) | Exploitation de services mal configurés |
