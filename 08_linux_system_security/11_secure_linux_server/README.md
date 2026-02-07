# Secure Linux Server

## Contexte

Sécurisation d'un serveur Ubuntu 24.04 LTS (192.168.140.234) hébergeant une application web Dockerisée (Python + PostgreSQL). Le serveur présente plusieurs failles de sécurité à corriger : services inutiles exposés, configurations par défaut non durcies, absence de pare-feu et de protection contre le brute-force.

---

## Etape 1 : Reconnaissance

### Connexion FTP anonyme

Le serveur expose un service FTP avec accès anonyme. La connexion en mode actif échoue, il faut utiliser le mode passif :

```bash
ftp -p Anonymous@192.168.140.234
```

> Le flag `-p` active le mode passif (PASV), nécessaire lorsque le mode actif (PORT) est bloqué par un NAT/firewall.

Une fois connecté, lister les fichiers et récupérer les informations utiles (identifiants, fichiers de configuration...).

### Connexion SSH

Avec les identifiants trouvés via FTP :

```bash
ssh jedha@192.168.140.234
```

---

## Etape 2 : Durcissement des services

### 2.1 Inventaire des ports en écoute

```bash
ss -tlnp    # TCP
ss -ulnp    # UDP
```

Résultat initial :

| Port | Protocole | Interface | Service | Nécessaire |
|------|-----------|-----------|---------|------------|
| 22 | TCP | `*` | SSH (sshd) | **Oui** |
| 80 | TCP | `0.0.0.0` / `[::]` | Web app (Docker) | **Oui** |
| 21 | TCP | `*` | FTP (vsftpd) | **Non** |
| 631 | TCP | `0.0.0.0` / `[::]` | CUPS (impression) | **Non** |
| 5432 | TCP | `0.0.0.0` / `[::]` | PostgreSQL (Docker) | **A sécuriser** |
| 53 | TCP/UDP | `127.0.0.53` / `127.0.0.54` | DNS (systemd-resolved) | OK (local) |
| 5353 | UDP | `0.0.0.0` / `[::]` | Avahi/mDNS | **Non** |
| 34626/46857 | UDP | `0.0.0.0` / `[::]` | Avahi (ports aléatoires) | **Non** |
| 68 | UDP | `192.168.140.234` | DHCP client | OK |

### 2.2 Suppression de FTP (vsftpd)

```bash
sudo systemctl stop vsftpd
sudo systemctl disable vsftpd
sudo apt remove vsftpd
```

**Pourquoi ?** Le FTP transmet les identifiants en clair, l'accès anonyme était activé, et ce service n'est pas nécessaire pour servir une application web.

### 2.3 Suppression de CUPS (service d'impression)

```bash
sudo systemctl stop cups cups-browsed
sudo systemctl disable cups cups-browsed
sudo apt remove cups cups-browsed
```

**Pourquoi ?** Un serveur web n'a aucun besoin d'un service d'impression. Chaque service exposé augmente la surface d'attaque.

### 2.4 Suppression d'Avahi (mDNS/Zeroconf)

```bash
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon
sudo apt remove avahi-daemon
```

**Pourquoi ?** Avahi permet la découverte automatique de services sur le réseau local (comme Bonjour d'Apple). Inutile et potentiellement dangereux sur un serveur de production.

### 2.5 Sécurisation de PostgreSQL (Docker)

Le port 5432 était exposé sur toutes les interfaces via Docker, ce qui permettait à n'importe qui sur le réseau d'accéder à la base de données.

Editer le fichier docker-compose :

```bash
sudo vim /home/jedha/webapp/docker-compose.yaml
```

**Avant (dangereux)** :

```yaml
services:
  web:
    build: .
    ports:
      - "80:80"
    depends_on:
      - db

  db:
    image: postgres:9.1
    environment:
      POSTGRES_DB: demo
      POSTGRES_USER: webapp
      POSTGRES_PASSWORD: insecure
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
```

**Après (sécurisé)** :

```yaml
services:
  web:
    build: .
    ports:
      - "80:80"
    depends_on:
      - db

  db:
    image: postgres:9.1
    environment:
      POSTGRES_DB: demo
      POSTGRES_USER: webapp
      POSTGRES_PASSWORD: S3cur3_P@ssw0rd!2026
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
```

Modifications apportées :
- **Suppression de la section `ports`** du service `db` : le container `web` communique avec `db` via le réseau interne Docker (résolution DNS par nom de service), donc aucun besoin d'exposer le port à l'hôte
- **Changement du mot de passe** : `insecure` remplacé par un mot de passe fort

Redémarrage des containers :

```bash
cd /home/jedha/webapp
sudo docker compose down -v
sudo docker compose up -d
```

### 2.6 Durcissement de SSH

Copier sa clé SSH sur le serveur (depuis la machine locale) :

```bash
ssh-copy-id jedha@192.168.140.234
```

Editer la configuration SSH sur le serveur :

```bash
sudo vim /etc/ssh/sshd_config
```

Ajouter les lignes suivantes en haut du fichier (après la ligne `Include`) :

```
MaxAuthTries 3
X11Forwarding no
PermitEmptyPasswords no
PermitRootLogin no
PasswordAuthentication no
```

| Directive | Valeur | Explication |
|-----------|--------|-------------|
| `PermitRootLogin` | `no` | Interdit la connexion directe en root |
| `MaxAuthTries` | `3` | Limite les tentatives d'authentification par session |
| `X11Forwarding` | `no` | Désactive le forwarding graphique X11 (inutile sur un serveur) |
| `PermitEmptyPasswords` | `no` | Interdit les mots de passe vides |
| `PasswordAuthentication` | `no` | Oblige l'authentification par clé SSH uniquement |

Redémarrer SSH :

```bash
sudo systemctl restart ssh
```

> **Important** : avant de fermer la session active, vérifier dans un second terminal que la connexion par clé fonctionne toujours : `ssh jedha@192.168.140.234`

### 2.7 Nettoyage des dépendances orphelines

```bash
sudo apt autoremove
```

### 2.8 Vérification finale

```bash
ss -tlnp
```

Résultat après durcissement :

| Port | Service | Statut |
|------|---------|--------|
| 22 | SSH | Durci (clé uniquement, root interdit) |
| 53 | DNS | Local uniquement (127.0.0.x) |
| 80 | Web app | Application Docker |

Les ports 21, 631, 5353 et 5432 ne sont plus exposés.

---

## Etape 3 : Pare-feu et Fail2ban

### 3.1 Configuration du pare-feu UFW

L'ordre des commandes est important pour ne pas perdre la session SSH :

```bash
# 1. Autoriser SSH en premier
sudo ufw allow 22/tcp

# 2. Autoriser HTTP
sudo ufw allow 80/tcp

# 3. Politique par défaut : bloquer tout le trafic entrant
sudo ufw default deny incoming

# 4. Autoriser le trafic sortant
sudo ufw default allow outgoing

# 5. Activer le pare-feu
sudo ufw enable
```

> **Attention** : si on active `ufw` avec `default deny incoming` AVANT d'autoriser le port 22, la session SSH sera immédiatement coupée. Toujours autoriser SSH en premier.

Vérification :

```bash
sudo ufw status verbose
```

Résultat attendu :

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
80/tcp (v6)                ALLOW IN    Anywhere (v6)
```

**Pourquoi un pare-feu en plus de la suppression des services ?** Si un service commence à écouter de manière inattendue (installation de MySQL, mauvaise configuration Docker exposant un port...), le pare-feu bloque quand même le trafic. C'est le principe de la **défense en profondeur**.

### 3.2 Installation et configuration de Fail2ban

Installation :

```bash
sudo apt update && sudo apt install fail2ban -y
```

Créer une configuration locale (ne jamais modifier le fichier par défaut) :

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo vim /etc/fail2ban/jail.local
```

Dans vim, rechercher la section `[sshd]` avec `/[sshd]` puis `n` pour naviguer jusqu'à la bonne section. Modifier comme suit :

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600
findtime = 600
```

| Paramètre | Valeur | Explication |
|-----------|--------|-------------|
| `enabled` | `true` | Active la jail SSH |
| `maxretry` | `3` | Nombre de tentatives avant bannissement |
| `bantime` | `600` | Durée du ban en secondes (10 minutes) |
| `findtime` | `600` | Fenêtre de temps pour compter les tentatives (10 min) |

Démarrer et activer Fail2ban :

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3.3 Vérification de Fail2ban

Vérifier le statut de la jail SSH :

```bash
sudo fail2ban-client status sshd
```

Résultat :

```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     2
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
```

### 3.4 Test de Fail2ban

Depuis une machine externe, tenter des connexions SSH avec un mauvais utilisateur :

```bash
ssh fakeuser@192.168.140.234
# Entrer un mauvais mot de passe plusieurs fois
```

### 3.5 Fichier journal de Fail2ban

Le fichier journal à consulter pour voir Fail2ban en action :

```
/var/log/fail2ban.log
```

```bash
sudo tail -f /var/log/fail2ban.log
```

Exemple de sortie :

```
2026-02-07 13:47:38,633 fail2ban.jail  [138617]: INFO  Jail 'sshd' started
2026-02-07 13:48:52,722 fail2ban.filter [138617]: INFO  [sshd] Found 192.168.145.69 - 2026-02-07 13:48:52
```

On y voit :
- Le démarrage des jails
- Les IP détectées (`Found`)
- Les bannissements (`Ban`) et débannissements (`Unban`)

Le journal d'authentification SSH surveillé par Fail2ban est `/var/log/auth.log`.

---

## Résumé des actions

| Action | Commande principale | Objectif |
|--------|---------------------|----------|
| Supprimer FTP | `sudo apt remove vsftpd` | Eliminer un service transmettant en clair |
| Supprimer CUPS | `sudo apt remove cups cups-browsed` | Eliminer le service d'impression inutile |
| Supprimer Avahi | `sudo apt remove avahi-daemon` | Eliminer la découverte réseau mDNS |
| Sécuriser PostgreSQL | Supprimer `ports` dans docker-compose + changer le mot de passe | Empêcher l'accès externe à la BDD |
| Durcir SSH | Editer `sshd_config` (clé uniquement, root interdit) | Réduire la surface d'attaque SSH |
| Pare-feu UFW | `ufw allow 22,80/tcp` + `default deny incoming` | Bloquer tout trafic non autorisé |
| Fail2ban | Activer la jail `sshd` (3 tentatives, ban 10 min) | Protection contre le brute-force |
| Nettoyage | `sudo apt autoremove` | Supprimer les dépendances orphelines |
