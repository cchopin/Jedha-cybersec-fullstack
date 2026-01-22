# Services et planification

**Duree : 55 min**

## Ce que vous allez apprendre dans ce cours

Dans la lecon precedente, nous avons explore ce que sont les processus et comment les inspecter et les gerer. Maintenant, nous allons nous concentrer sur une categorie speciale de processus : les **services**. Tous les services sont des processus, mais tous les processus ne sont pas des services. Comprendre les services est crucial car ils :

- controlent les fonctions systeme cles du demarrage a l'arret,
- offrent aux attaquants un chemin discret vers la persistence,
- deviennent souvent des points de defaillance ou d'escalade quand ils sont mal configures.

Dans cette lecon, vous apprendrez a :

- inspecter et controler les services avec systemctl,
- comprendre la structure des fichiers unit systemd,
- apprendre a securiser vos services contre les attaques,
- detecter les tactiques de persistence basees sur les services.

---

## Qu'est-ce qu'un service ?

Contrairement aux programmes reguliers (comme un editeur de texte) que vous ouvrez, utilisez et fermez, les **services** sont des processus de longue duree geres par le systeme pour effectuer des fonctions specifiques sans interaction directe de l'utilisateur. Ils demarrent generalement au boot et s'executent en arriere-plan.

### Daemon vs service

| Concept | Description |
|---------|-------------|
| **Daemon** | Processus en arriere-plan executant independamment, sans interaction utilisateur |
| **Service** | Processus en arriere-plan officiellement gere par le systeme d'init (systemd) |

Un service inclut :
- Definition de comment et quand il demarre
- Surveillance s'il reste actif ou redemarrage en cas de crash
- Application de controles de securite (permissions limitees)
- Integration aux logs systeme et pistes d'audit

---

## Le systeme d'init : systemd

Le **systeme d'init** est le premier processus espace utilisateur demarre par le noyau (PID 1). Il est responsable de l'amorcage du systeme et de la gestion de tous les autres processus.

### Autres systemes d'init

| Systeme | Description |
|---------|-------------|
| **SysVinit** | Traditionnel, utilise des scripts shell dans `/etc/init.d/` |
| **OpenRC** | Leger et rapide, utilise dans Alpine Linux et Gentoo |
| **systemd** | Standard moderne sur la plupart des distributions |

### Fichiers unit

Chaque ressource ou tache que systemd gere est definie comme une **unit**. Le **fichier unit** (ex: `.service`) est un fichier de configuration specifiant comment systemd doit gerer ces ressources.

**Emplacement :** `/lib/systemd/system/`

**Exemple : cups.service**
```ini
[Unit]
Description=CUPS Scheduler
Documentation=man:cupsd(8)
After=network.target nss-user-lookup.target nslcd.service
Requires=cups.socket

[Service]
ExecStart=/usr/sbin/cupsd -l
Type=notify
Restart=on-failure

[Install]
Also=cups.socket cups.path
WantedBy=printer.target multi-user.target
```

### Sections d'un fichier unit

| Section | Description |
|---------|-------------|
| `[Unit]` | Informations de base : Description, Documentation, Before, After, Requires |
| `[Service]` | Proprietes du service : ExecStart, Type, Restart |
| `[Install]` | Utilise par enable/disable : Also, WantedBy, RequiredBy |

**Options courantes de [Service] :**
| Option | Description |
|--------|-------------|
| `ExecStart` | Commande a executer |
| `Type` | Type de demarrage (simple, forking, notify, oneshot) |
| `Restart` | Comportement de redemarrage (no, on-failure, always) |
| `User` | Utilisateur sous lequel executer |
| `Group` | Groupe sous lequel executer |

---

## Gestion des services

### Utiliser systemctl

`systemctl` est la commande pour interagir avec systemd.

**Voir tous les services en cours :**
```bash
$ systemctl --type=service --state=running
```

**Arreter un service :**
```bash
$ sudo systemctl stop cups
```

**Demarrer un service :**
```bash
$ sudo systemctl start cups
```

**Verifier le statut :**
```bash
$ systemctl status cups
```

**Autres commandes importantes :**
| Commande | Description |
|----------|-------------|
| `systemctl restart service` | Redemarrer un service |
| `systemctl reload service` | Recharger la configuration sans redemarrer |
| `systemctl daemon-reload` | Relire tous les fichiers unit |
| `systemctl enable service` | Activer au demarrage |
| `systemctl disable service` | Desactiver au demarrage |

**Lister les services actives/desactives :**
```bash
$ systemctl list-unit-files --type=service
```

> **Bonne pratique** : Desactiver les services inutiles pour reduire la surface d'attaque.

> **Securite - Persistence** : Les attaquants peuvent deposer un fichier unit malveillant dans `/etc/systemd/system/` ou `~/.config/systemd/user/` pour lancer un malware au demarrage.

### Utiliser service (ancienne methode)

Avant systemctl, on utilisait `service` :
```bash
$ sudo service cups stop
$ sudo service cups start
$ sudo service cups restart
$ sudo service cups status
```

### Verifier les logs des services

**journald** est le systeme de journalisation integre a systemd. Il collecte et stocke les logs dans un format binaire structure.

**Acceder aux logs d'un service :**
```bash
$ journalctl -u cups
```

**Options utiles :**
| Option | Description |
|--------|-------------|
| `-u service` | Logs d'un service specifique |
| `--since "10 minutes ago"` | Logs recents |
| `-f` | Suivre en temps reel |
| `-e` | Aller a la fin |

**Trouver les services echoues :**
```bash
$ systemctl --failed
```

**Voir le fichier unit d'un service :**
```bash
$ systemctl cat cups
```

**Messages du noyau avec dmesg :**
```bash
$ sudo dmesg | tail
```

### rsyslog

Le service **rsyslog** collecte et stocke les logs dans des fichiers sous `/var/log/` :
- `/var/log/syslog`
- `/var/log/auth.log`
- `/var/log/messages`

---

## Services actives par socket

Certains services ne demarrent que quand ils sont necessaires. systemd ecoute sur un socket et demarre automatiquement le service quand une connexion arrive.

### Qu'est-ce qu'un socket ?

Un **socket** est un point de terminaison pour la communication entre deux programmes.

| Type | Description |
|------|-------------|
| **Socket reseau** | Defini par protocole, adresse IP et port |
| **Socket UNIX** | Communication locale entre processus (ex: `/var/run/docker.sock`) |

### Configuration

- Un fichier `.socket` definit le socket d'ecoute
- Un fichier `.service` correspondant definit le service a lancer

**Lister les sockets actifs :**
```bash
$ systemctl list-sockets
```

**Verifier un socket :**
```bash
$ systemctl status cups.socket
```

---

## Securiser les services

Les services sont souvent le premier point d'entree pour les attaquants car ils sont constamment en cours d'execution et souvent accessibles via le reseau.

### Executer les services en tant qu'utilisateur non-root

Configurer les services pour s'executer sous des utilisateurs dedies et non privilegies :

```ini
[Service]
User=serviced
Group=serviced
```

> **Bonne pratique** : Creer un utilisateur et groupe specifique pour chaque service.

### Restreindre les capabilities et privileges

**Limiter les capabilities :**
```ini
CapabilityBoundingSet=CAP_SETGID CAP_SETUID
```

**Accorder des capabilities specifiques :**
```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

**Empecher l'acquisition de nouveaux privileges :**
```ini
NoNewPrivileges=yes
```

### Isolation du systeme de fichiers

| Option | Description |
|--------|-------------|
| `ProtectSystem=full` ou `strict` | Remonte `/usr` et `/etc` en lecture seule |
| `ProtectHome=read-only` ou `yes` | Controle l'acces aux repertoires home |
| `ReadOnlyDirectories=` | Repertoires en lecture seule |
| `InaccessibleDirectories=` | Repertoires completement inaccessibles |
| `TemporaryFileSystem=` | Systeme de fichiers temporaire |

### Analyser la securite avec systemd-analyze

**Analyser un service specifique :**
```bash
$ systemd-analyze security cups
```

**Analyser tous les services :**
```bash
$ systemd-analyze security
```

Le score d'exposition va de 0.0 (tres securise) a 10.0 (tres expose).

> **Note** : Ce score est base sur les fonctionnalites de securite systemd utilisees, pas sur la securite inherente du service.

**Analyser les performances :**
```bash
# Services par temps de demarrage
$ systemd-analyze blame

# Chaine critique de demarrage
$ systemd-analyze critical-chain
```

---

## Planification des taches

### Cron jobs

**Cron** est un outil classique pour automatiser les taches periodiques. Le daemon `crond` s'execute en arriere-plan et verifie chaque minute si des taches doivent etre executees.

**Structure d'une entree crontab :**
```
minute heure jour mois jour_semaine commande
```

**Valeurs speciales :**
| Symbole | Signification |
|---------|---------------|
| `*` | Toute valeur |
| `-` | Plage (ex: 3-6) |
| `/` | Pas (ex: */5 = toutes les 5 unites) |
| `,` | Liste (ex: 0,6 = samedi et dimanche) |

**Exemples :**
| Crontab | Signification |
|---------|---------------|
| `0 * * * *` | Chaque heure, a la minute 0 |
| `*/5 3-6 * * 0,6` | Toutes les 5 min, entre 3h et 6h, sam et dim |
| `0 2 * * *` | Tous les jours a 2h du matin |

**Commandes cron :**
| Commande | Description |
|----------|-------------|
| `crontab -l` | Lister les cron jobs de l'utilisateur |
| `crontab -e` | Editer les cron jobs |
| `cat /etc/crontab` | Voir le crontab systeme |

**Repertoires cron systeme :**
- `/etc/cron.d/`
- `/etc/cron.daily/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`

### Timers systemd

Les **timers systemd** sont une alternative moderne a cron, avec une meilleure integration au systeme.

**Configuration requise :**
1. Un fichier `.service` definissant l'action
2. Un fichier `.timer` definissant quand declencher

**Exemple de service `/etc/systemd/system/backup.service` :**
```ini
[Unit]
Description=Run daily backup

[Service]
ExecStart=/usr/local/bin/backup.sh
```

**Exemple de timer `/etc/systemd/system/backup.timer` :**
```ini
[Unit]
Description=Daily backup timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

**Options de timer :**
| Option | Description |
|--------|-------------|
| `OnCalendar=daily` | Tous les jours a minuit |
| `OnCalendar=Mon *-*-* 06:00:00` | Tous les lundis a 6h |
| `Persistent=true` | Execute immediatement si le systeme etait eteint |

**Lister tous les timers :**
```bash
$ systemctl list-timers --all
```

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **Service** | Processus en arriere-plan gere par le systeme d'init |
| **Daemon** | Processus en arriere-plan de longue duree |
| **systemd** | Systeme d'init moderne pour Linux |
| **Unit** | Ressource geree par systemd (service, socket, timer...) |
| **Unit file** | Fichier de configuration d'une unit systemd |
| **systemctl** | Commande pour controler systemd |
| **journald** | Systeme de journalisation de systemd |
| **journalctl** | Commande pour lire les logs journald |
| **rsyslog** | Service de journalisation traditionnel |
| **Socket** | Point de terminaison pour la communication inter-processus |
| **Socket activation** | Demarrage d'un service a la demande via socket |
| **Cron** | Planificateur de taches classique Unix |
| **Crontab** | Fichier de configuration cron |
| **Timer** | Unit systemd pour la planification |
| **polkit** | Service controlant les permissions pour les actions privilegiees |
| **Persistence** | Technique d'attaquant pour maintenir l'acces apres redemarrage |

---

## Recapitulatif des commandes

### Gestion des services avec systemctl

| Commande | Description |
|----------|-------------|
| `systemctl start service` | Demarrer un service |
| `systemctl stop service` | Arreter un service |
| `systemctl restart service` | Redemarrer un service |
| `systemctl reload service` | Recharger la configuration |
| `systemctl status service` | Voir le statut |
| `systemctl enable service` | Activer au demarrage |
| `systemctl disable service` | Desactiver au demarrage |
| `systemctl is-enabled service` | Verifier si active au demarrage |
| `systemctl daemon-reload` | Relire les fichiers unit |
| `systemctl --type=service` | Lister les services |
| `systemctl --failed` | Lister les services echoues |
| `systemctl list-unit-files` | Lister tous les fichiers unit |
| `systemctl cat service` | Afficher le fichier unit |

### Logs avec journalctl

| Commande | Description |
|----------|-------------|
| `journalctl` | Tous les logs |
| `journalctl -u service` | Logs d'un service |
| `journalctl -f` | Suivre en temps reel |
| `journalctl -e` | Aller a la fin |
| `journalctl --since "1 hour ago"` | Logs recents |
| `journalctl -b` | Logs depuis le demarrage |

### Sockets

| Commande | Description |
|----------|-------------|
| `systemctl list-sockets` | Lister les sockets actifs |
| `systemctl status socket.socket` | Statut d'un socket |

### Analyse

| Commande | Description |
|----------|-------------|
| `systemd-analyze security` | Analyser la securite de tous les services |
| `systemd-analyze security service` | Analyser un service |
| `systemd-analyze blame` | Temps de demarrage par service |
| `systemd-analyze critical-chain` | Chaine critique de demarrage |

### Cron

| Commande | Description |
|----------|-------------|
| `crontab -l` | Lister les cron jobs |
| `crontab -e` | Editer les cron jobs |
| `crontab -r` | Supprimer tous les cron jobs |
| `cat /etc/crontab` | Voir le crontab systeme |

### Timers systemd

| Commande | Description |
|----------|-------------|
| `systemctl list-timers` | Lister tous les timers |
| `systemctl list-timers --all` | Inclure les timers inactifs |
| `systemctl start timer.timer` | Demarrer un timer |
| `systemctl enable timer.timer` | Activer un timer |

### Autres

| Commande | Description |
|----------|-------------|
| `dmesg` | Messages du noyau |
| `dmesg \| tail` | Derniers messages |

### Fichiers importants

| Fichier/Repertoire | Description |
|--------------------|-------------|
| `/lib/systemd/system/` | Fichiers unit systeme |
| `/etc/systemd/system/` | Fichiers unit personnalises |
| `~/.config/systemd/user/` | Fichiers unit utilisateur |
| `/var/log/` | Logs rsyslog |
| `/var/log/syslog` | Log systeme general |
| `/var/log/auth.log` | Logs d'authentification |
| `/etc/crontab` | Crontab systeme |
| `/etc/cron.d/` | Cron jobs systeme |
| `/etc/cron.daily/` | Taches quotidiennes |

---

## Ressources

- Optimizing a systemd service for security - Bernhard Cygan
- systemd service sandboxing and security hardening 101 - Daniel Aleksandersen
- Systemd Hardening - Peter Gerber
- Using systemd features to secure services - Zbigniew Jedrzejewski-Szmek
