# Services et planification

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

Dans la leçon précédente, nous avons exploré ce que sont les processus et comment les inspecter et les gérer. Maintenant, nous allons nous concentrer sur une catégorie spéciale de processus : les **services**. Tous les services sont des processus, mais tous les processus ne sont pas des services. Comprendre les services est crucial car ils :

- contrôlent les fonctions système clés du démarrage à l'arrêt,
- offrent aux attaquants un chemin discret vers la persistence,
- deviennent souvent des points de défaillance ou d'escalade quand ils sont mal configurés.

Dans cette leçon, vous apprendrez à :

- inspecter et contrôler les services avec systemctl,
- comprendre la structure des fichiers unit systemd,
- apprendre à sécuriser vos services contre les attaques,
- détecter les tactiques de persistence basées sur les services.

---

## Qu'est-ce qu'un service ?

Contrairement aux programmes réguliers (comme un éditeur de texte) que vous ouvrez, utilisez et fermez, les **services** sont des processus de longue durée gérés par le système pour effectuer des fonctions spécifiques sans interaction directe de l'utilisateur. Ils démarrent généralement au boot et s'exécutent en arrière-plan.

### Daemon vs service

| Concept | Description |
|---------|-------------|
| **Daemon** | Processus en arrière-plan exécutant indépendamment, sans interaction utilisateur |
| **Service** | Processus en arrière-plan officiellement géré par le système d'init (systemd) |

Un service inclut :
- Définition de comment et quand il démarre
- Surveillance s'il reste actif ou redémarrage en cas de crash
- Application de contrôles de sécurité (permissions limitées)
- Intégration aux logs système et pistes d'audit

---

## Le système d'init : systemd

Le **système d'init** est le premier processus espace utilisateur démarré par le noyau (PID 1). Il est responsable de l'amorçage du système et de la gestion de tous les autres processus.

### Autres systèmes d'init

| Système | Description |
|---------|-------------|
| **SysVinit** | Traditionnel, utilise des scripts shell dans `/etc/init.d/` |
| **OpenRC** | Léger et rapide, utilisé dans Alpine Linux et Gentoo |
| **systemd** | Standard moderne sur la plupart des distributions |

### Fichiers unit

Chaque ressource ou tâche que systemd gère est définie comme une **unit**. Le **fichier unit** (ex: `.service`) est un fichier de configuration spécifiant comment systemd doit gérer ces ressources.

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
| `[Service]` | Propriétés du service : ExecStart, Type, Restart |
| `[Install]` | Utilisé par enable/disable : Also, WantedBy, RequiredBy |

**Options courantes de [Service] :**
| Option | Description |
|--------|-------------|
| `ExecStart` | Commande à exécuter |
| `Type` | Type de démarrage (simple, forking, notify, oneshot) |
| `Restart` | Comportement de redémarrage (no, on-failure, always) |
| `User` | Utilisateur sous lequel exécuter |
| `Group` | Groupe sous lequel exécuter |

---

## Gestion des services

### Utiliser systemctl

`systemctl` est la commande pour interagir avec systemd.

**Voir tous les services en cours :**
```bash
systemctl --type=service --state=running
```

**Arrêter un service :**
```bash
sudo systemctl stop cups
```

**Démarrer un service :**
```bash
sudo systemctl start cups
```

**Vérifier le statut :**
```bash
$ systemctl status cups
```

**Autres commandes importantes :**
| Commande | Description |
|----------|-------------|
| `systemctl restart service` | Redémarrer un service |
| `systemctl reload service` | Recharger la configuration sans redémarrer |
| `systemctl daemon-reload` | Relire tous les fichiers unit |
| `systemctl enable service` | Activer au démarrage |
| `systemctl disable service` | Désactiver au démarrage |

**Lister les services activés/désactivés :**
```bash
$ systemctl list-unit-files --type=service
```

> **Bonne pratique** : Désactiver les services inutiles pour réduire la surface d'attaque.

> **Sécurité - Persistence** : Les attaquants peuvent déposer un fichier unit malveillant dans `/etc/systemd/system/` ou `~/.config/systemd/user/` pour lancer un malware au démarrage.

### Utiliser service (ancienne méthode)

Avant systemctl, on utilisait `service` :
```bash
$ sudo service cups stop
$ sudo service cups start
$ sudo service cups restart
$ sudo service cups status
```

### Vérifier les logs des services

**journald** est le système de journalisation intégré à systemd. Il collecte et stocke les logs dans un format binaire structuré.

**Accéder aux logs d'un service :**
```bash
$ journalctl -u cups
```

**Options utiles :**
| Option | Description |
|--------|-------------|
| `-u service` | Logs d'un service spécifique |
| `--since "10 minutes ago"` | Logs récents |
| `-f` | Suivre en temps réel |
| `-e` | Aller à la fin |

**Trouver les services échoués :**
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

## Services activés par socket

Certains services ne démarrent que quand ils sont nécessaires. systemd écoute sur un socket et démarre automatiquement le service quand une connexion arrive.

### Qu'est-ce qu'un socket ?

Un **socket** est un point de terminaison pour la communication entre deux programmes.

| Type | Description |
|------|-------------|
| **Socket réseau** | Défini par protocole, adresse IP et port |
| **Socket UNIX** | Communication locale entre processus (ex: `/var/run/docker.sock`) |

### Configuration

- Un fichier `.socket` définit le socket d'écoute
- Un fichier `.service` correspondant définit le service à lancer

**Lister les sockets actifs :**
```bash
$ systemctl list-sockets
```

**Vérifier un socket :**
```bash
$ systemctl status cups.socket
```

---

## Sécuriser les services

Les services sont souvent le premier point d'entrée pour les attaquants car ils sont constamment en cours d'exécution et souvent accessibles via le réseau.

### Exécuter les services en tant qu'utilisateur non-root

Configurer les services pour s'exécuter sous des utilisateurs dédiés et non privilégiés :

```ini
[Service]
User=serviced
Group=serviced
```

> **Bonne pratique** : Créer un utilisateur et groupe spécifique pour chaque service.

### Restreindre les capabilities et privilèges

**Limiter les capabilities :**
```ini
CapabilityBoundingSet=CAP_SETGID CAP_SETUID
```

**Accorder des capabilities spécifiques :**
```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

**Empêcher l'acquisition de nouveaux privilèges :**
```ini
NoNewPrivileges=yes
```

### Isolation du système de fichiers

| Option | Description |
|--------|-------------|
| `ProtectSystem=full` ou `strict` | Remonte `/usr` et `/etc` en lecture seule |
| `ProtectHome=read-only` ou `yes` | Contrôle l'accès aux répertoires home |
| `ReadOnlyDirectories=` | Répertoires en lecture seule |
| `InaccessibleDirectories=` | Répertoires complètement inaccessibles |
| `TemporaryFileSystem=` | Système de fichiers temporaire |

### Analyser la sécurité avec systemd-analyze

**Analyser un service spécifique :**
```bash
$ systemd-analyze security cups
```

**Analyser tous les services :**
```bash
$ systemd-analyze security
```

Le score d'exposition va de 0.0 (très sécurisé) à 10.0 (très exposé).

> **Note** : Ce score est basé sur les fonctionnalités de sécurité systemd utilisées, pas sur la sécurité inhérente du service.

**Analyser les performances :**
```bash
# Services par temps de démarrage
$ systemd-analyze blame

# Chaîne critique de démarrage
$ systemd-analyze critical-chain
```

---

## Planification des tâches

### Cron jobs

**Cron** est un outil classique pour automatiser les tâches périodiques. Le daemon `crond` s'exécute en arrière-plan et vérifie chaque minute si des tâches doivent être exécutées.

**Structure d'une entrée crontab :**
```
minute heure jour mois jour_semaine commande
```

**Valeurs spéciales :**
| Symbole | Signification |
|---------|---------------|
| `*` | Toute valeur |
| `-` | Plage (ex: 3-6) |
| `/` | Pas (ex: */5 = toutes les 5 unités) |
| `,` | Liste (ex: 0,6 = samedi et dimanche) |

**Exemples :**
| Crontab | Signification |
|---------|---------------|
| `0 * * * *` | Chaque heure, à la minute 0 |
| `*/5 3-6 * * 0,6` | Toutes les 5 min, entre 3h et 6h, sam et dim |
| `0 2 * * *` | Tous les jours à 2h du matin |

**Commandes cron :**
| Commande | Description |
|----------|-------------|
| `crontab -l` | Lister les cron jobs de l'utilisateur |
| `crontab -e` | Éditer les cron jobs |
| `cat /etc/crontab` | Voir le crontab système |

**Répertoires cron système :**
- `/etc/cron.d/`
- `/etc/cron.daily/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`

### Timers systemd

Les **timers systemd** sont une alternative moderne à cron, avec une meilleure intégration au système.

**Configuration requise :**
1. Un fichier `.service` définissant l'action
2. Un fichier `.timer` définissant quand déclencher

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
| `OnCalendar=daily` | Tous les jours à minuit |
| `OnCalendar=Mon *-*-* 06:00:00` | Tous les lundis à 6h |
| `Persistent=true` | Exécute immédiatement si le système était éteint |

**Lister tous les timers :**
```bash
$ systemctl list-timers --all
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Service** | Processus en arrière-plan géré par le système d'init |
| **Daemon** | Processus en arrière-plan de longue durée |
| **systemd** | Système d'init moderne pour Linux |
| **Unit** | Ressource gérée par systemd (service, socket, timer...) |
| **Unit file** | Fichier de configuration d'une unit systemd |
| **systemctl** | Commande pour contrôler systemd |
| **journald** | Système de journalisation de systemd |
| **journalctl** | Commande pour lire les logs journald |
| **rsyslog** | Service de journalisation traditionnel |
| **Socket** | Point de terminaison pour la communication inter-processus |
| **Socket activation** | Démarrage d'un service à la demande via socket |
| **Cron** | Planificateur de tâches classique Unix |
| **Crontab** | Fichier de configuration cron |
| **Timer** | Unit systemd pour la planification |
| **polkit** | Service contrôlant les permissions pour les actions privilégiées |
| **Persistence** | Technique d'attaquant pour maintenir l'accès après redémarrage |

---

## Récapitulatif des commandes

### Gestion des services avec systemctl

| Commande | Description |
|----------|-------------|
| `systemctl start service` | Démarrer un service |
| `systemctl stop service` | Arrêter un service |
| `systemctl restart service` | Redémarrer un service |
| `systemctl reload service` | Recharger la configuration |
| `systemctl status service` | Voir le statut |
| `systemctl enable service` | Activer au démarrage |
| `systemctl disable service` | Désactiver au démarrage |
| `systemctl is-enabled service` | Vérifier si activé au démarrage |
| `systemctl daemon-reload` | Relire les fichiers unit |
| `systemctl --type=service` | Lister les services |
| `systemctl --failed` | Lister les services échoués |
| `systemctl list-unit-files` | Lister tous les fichiers unit |
| `systemctl cat service` | Afficher le fichier unit |

### Logs avec journalctl

| Commande | Description |
|----------|-------------|
| `journalctl` | Tous les logs |
| `journalctl -u service` | Logs d'un service |
| `journalctl -f` | Suivre en temps réel |
| `journalctl -e` | Aller à la fin |
| `journalctl --since "1 hour ago"` | Logs récents |
| `journalctl -b` | Logs depuis le démarrage |

### Sockets

| Commande | Description |
|----------|-------------|
| `systemctl list-sockets` | Lister les sockets actifs |
| `systemctl status socket.socket` | Statut d'un socket |

### Analyse

| Commande | Description |
|----------|-------------|
| `systemd-analyze security` | Analyser la sécurité de tous les services |
| `systemd-analyze security service` | Analyser un service |
| `systemd-analyze blame` | Temps de démarrage par service |
| `systemd-analyze critical-chain` | Chaîne critique de démarrage |

### Cron

| Commande | Description |
|----------|-------------|
| `crontab -l` | Lister les cron jobs |
| `crontab -e` | Éditer les cron jobs |
| `crontab -r` | Supprimer tous les cron jobs |
| `cat /etc/crontab` | Voir le crontab système |

### Timers systemd

| Commande | Description |
|----------|-------------|
| `systemctl list-timers` | Lister tous les timers |
| `systemctl list-timers --all` | Inclure les timers inactifs |
| `systemctl start timer.timer` | Démarrer un timer |
| `systemctl enable timer.timer` | Activer un timer |

### Autres

| Commande | Description |
|----------|-------------|
| `dmesg` | Messages du noyau |
| `dmesg \| tail` | Derniers messages |

### Fichiers importants

| Fichier/Répertoire | Description |
|--------------------|-------------|
| `/lib/systemd/system/` | Fichiers unit système |
| `/etc/systemd/system/` | Fichiers unit personnalisés |
| `~/.config/systemd/user/` | Fichiers unit utilisateur |
| `/var/log/` | Logs rsyslog |
| `/var/log/syslog` | Log système général |
| `/var/log/auth.log` | Logs d'authentification |
| `/etc/crontab` | Crontab système |
| `/etc/cron.d/` | Cron jobs système |
| `/etc/cron.daily/` | Tâches quotidiennes |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Lien | Description |
|------------|------|-------------|
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Services et persistence |
| TryHackMe | [Linux Hardening](https://tryhackme.com/room/dvlinuxhardening) | Durcissement des services |
| TryHackMe | [Linux Forensics](https://tryhackme.com/room/linuxforensics) | Investigation des services |
| HackTheBox | [Starting Point](https://app.hackthebox.com/starting-point) | Machines avec services vulnérables |

---

## Ressources

- Optimizing a systemd service for security - Bernhard Cygan
- systemd service sandboxing and security hardening 101 - Daniel Aleksandersen
- Systemd Hardening - Peter Gerber
- Using systemd features to secure services - Zbigniew Jedrzejewski-Szmek
