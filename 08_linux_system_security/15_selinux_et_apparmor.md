# SELinux et AppArmor

**Durée : 60 min**

## Ce que vous allez apprendre dans ce cours

Les permissions Linux traditionnelles contrôlent qui peut accéder à quoi en fonction de l'utilisateur et du groupe. Mais une fois qu'un processus s'exécute sous un certain utilisateur, il hérite de toutes les permissions de cet utilisateur. SELinux et AppArmor ajoutent une couche supplémentaire : le contrôle d'accès obligatoire (MAC), qui limite ce qu'un processus peut faire même s'il appartient à root.

Dans cette leçon, vous apprendrez :

- ce qu'est le contrôle d'accès obligatoire et pourquoi il est important,
- comment fonctionne SELinux et comment le configurer,
- comment fonctionne AppArmor et comment créer des profils,
- quand utiliser l'un ou l'autre.

---

## Contrôle d'accès obligatoire (MAC)

### Le problème avec DAC

Le modèle de permissions standard de Linux est appelé **DAC** (Discretionary Access Control). Dans ce modèle, le propriétaire d'un fichier décide qui peut y accéder. C'est flexible, mais cela signifie aussi qu'un processus compromis hérite de toutes les permissions de son propriétaire.

| Modèle | Description | Limite |
|--------|-------------|--------|
| **DAC** | Le propriétaire décide des permissions | Un processus compromis a toutes les permissions de l'utilisateur |
| **MAC** | Le système applique des politiques strictes | Les processus sont limités même s'ils sont root |

### Comment MAC résout le problème

Avec MAC, chaque processus et ressource a une **étiquette de sécurité**. Le noyau consulte une politique centrale pour décider si un accès est autorisé, indépendamment des permissions DAC traditionnelles.

**Exemple concret :**
- Un serveur web compromis sous DAC pourrait lire `/etc/shadow` si l'utilisateur `www-data` avait ce droit
- Sous MAC, même si le processus tourne en root, la politique peut interdire au processus web d'accéder à ce fichier

---

## SELinux

**SELinux** (Security-Enhanced Linux) a été développé par la NSA et est intégré dans le noyau Linux. Il est le système MAC par défaut sur Red Hat, CentOS, Fedora et leurs dérivés.

### Concepts fondamentaux

| Concept | Description |
|---------|-------------|
| **Contexte de sécurité** | Étiquette attachée à chaque processus et fichier (utilisateur:role:type:niveau) |
| **Type** | La partie la plus importante du contexte, utilisée pour les décisions d'accès |
| **Politique** | Ensemble de règles définissant quels types peuvent accéder à quels autres types |
| **Domaine** | Type associé à un processus |

### Modes de fonctionnement

| Mode | Description |
|------|-------------|
| **Enforcing** | SELinux applique la politique et bloque les violations |
| **Permissive** | SELinux log les violations mais ne bloque pas |
| **Disabled** | SELinux est complètement désactivé |

### Vérifier et changer le mode

```bash
# Vérifier le mode actuel
$ getenforce
Enforcing

# Voir le statut détaillé
$ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing

# Passer temporairement en permissif
$ sudo setenforce 0

# Revenir en enforcing
$ sudo setenforce 1
```

Pour un changement permanent, éditez `/etc/selinux/config` :

```
SELINUX=enforcing
SELINUXTYPE=targeted
```

### Voir les contextes de sécurité

```bash
# Contexte d'un fichier
$ ls -Z /var/www/html/index.html
system_u:object_r:httpd_sys_content_t:s0 /var/www/html/index.html

# Contexte d'un processus
$ ps -eZ | grep httpd
system_u:system_r:httpd_t:s0    1234 ?  00:00:00 httpd
```

### Comprendre les contextes

Le contexte `system_u:system_r:httpd_t:s0` se décompose ainsi :

| Champ | Valeur | Description |
|-------|--------|-------------|
| Utilisateur | `system_u` | Utilisateur SELinux |
| Rôle | `system_r` | Rôle SELinux |
| Type | `httpd_t` | Type/domaine (le plus important) |
| Niveau | `s0` | Niveau de sensibilité MLS |

### Gérer les contextes de fichiers

```bash
# Changer le type d'un fichier
$ sudo chcon -t httpd_sys_content_t /var/www/html/newfile.html

# Restaurer le contexte par défaut
$ sudo restorecon -v /var/www/html/newfile.html

# Restaurer récursivement
$ sudo restorecon -Rv /var/www/html/
```

### Booléens SELinux

Les booléens permettent d'activer ou désactiver des fonctionnalités spécifiques sans modifier la politique :

```bash
# Lister tous les booléens
$ getsebool -a

# Lister les booléens liés à httpd
$ getsebool -a | grep httpd

# Activer un booléen (temporaire)
$ sudo setsebool httpd_can_network_connect on

# Activer un booléen (permanent)
$ sudo setsebool -P httpd_can_network_connect on
```

### Analyser les logs SELinux

```bash
# Voir les denials récents
$ sudo ausearch -m avc -ts recent

# Utiliser sealert pour une analyse détaillée
$ sudo sealert -a /var/log/audit/audit.log

# Générer un module pour autoriser une action bloquée
$ sudo audit2allow -a -M monmodule
$ sudo semodule -i monmodule.pp
```

---

## AppArmor

**AppArmor** est une alternative à SELinux, plus simple à configurer. Il est le système MAC par défaut sur Ubuntu, Debian et SUSE.

### Différences avec SELinux

| Aspect | SELinux | AppArmor |
|--------|---------|----------|
| Approche | Basée sur les étiquettes | Basée sur les chemins |
| Complexité | Plus complexe | Plus simple |
| Granularité | Très fine | Modérée |
| Profils | Politiques globales | Profils par application |
| Distributions | Red Hat, CentOS, Fedora | Ubuntu, Debian, SUSE |

### Modes de fonctionnement

| Mode | Description |
|------|-------------|
| **Enforce** | Le profil est appliqué, violations bloquées |
| **Complain** | Les violations sont loggées mais pas bloquées |
| **Disabled** | Le profil est désactivé |

### Vérifier le statut

```bash
# Statut général
$ sudo aa-status
apparmor module is loaded.
56 profiles are loaded.
19 profiles are in enforce mode.
   /usr/bin/evince
   /usr/sbin/cups-browsed
   ...
37 profiles are in complain mode.
   ...
2 processes have profiles defined.
2 processes are in enforce mode.
   /usr/sbin/cups-browsed (1234)
   ...
```

### Gérer les modes des profils

```bash
# Passer un profil en mode complain
$ sudo aa-complain /usr/sbin/nginx

# Passer un profil en mode enforce
$ sudo aa-enforce /usr/sbin/nginx

# Désactiver un profil
$ sudo aa-disable /usr/sbin/nginx
```

### Structure des profils

Les profils AppArmor se trouvent dans `/etc/apparmor.d/`. Voici un exemple simplifié :

```bash
$ cat /etc/apparmor.d/usr.sbin.nginx
#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Lecture des fichiers de configuration
  /etc/nginx/** r,

  # Lecture du contenu web
  /var/www/** r,

  # Écriture des logs
  /var/log/nginx/** w,

  # Écriture du PID
  /run/nginx.pid rw,

  # Accès réseau
  network inet stream,
  network inet6 stream,
}
```

### Syntaxe des permissions

| Permission | Description |
|------------|-------------|
| `r` | Lecture |
| `w` | Écriture |
| `a` | Append (ajout) |
| `x` | Exécution |
| `m` | Mapping mémoire exécutable |
| `k` | Verrouillage de fichier |
| `l` | Création de liens |

### Créer un profil

```bash
# Générer un profil de base
$ sudo aa-genprof /usr/bin/myapp

# Le système demande d'exécuter l'application
# puis analyse les accès et propose des règles

# Recharger tous les profils
$ sudo systemctl reload apparmor
```

### Analyser les logs

```bash
# Voir les violations AppArmor
$ sudo dmesg | grep apparmor

# Ou dans le journal systemd
$ journalctl -k | grep apparmor

# Utiliser aa-logprof pour mettre à jour les profils
$ sudo aa-logprof
```

---

## Choisir entre SELinux et AppArmor

| Critère | SELinux | AppArmor |
|---------|---------|----------|
| Facilité d'apprentissage | Plus difficile | Plus facile |
| Flexibilité | Très haute | Modérée |
| Performance | Légèrement plus lourd | Légèrement plus léger |
| Cas d'usage | Serveurs haute sécurité | Postes de travail, serveurs standards |
| Distribution | Red Hat family | Debian family |

**Recommandation :** Utilisez le système MAC fourni par défaut avec votre distribution, sauf si vous avez des besoins spécifiques.

---

## Bonnes pratiques

### Pour SELinux

1. **Ne jamais désactiver SELinux en production** - Utilisez le mode permissif pour le débogage
2. **Utilisez les booléens** avant de modifier la politique
3. **Restaurez les contextes** après avoir déplacé des fichiers
4. **Analysez les logs** avec `sealert` et `audit2allow`

### Pour AppArmor

1. **Commencez en mode complain** pour les nouvelles applications
2. **Utilisez `aa-genprof`** pour créer des profils de base
3. **Testez les profils** avant de passer en enforce
4. **Mettez à jour les profils** avec `aa-logprof` après les mises à jour d'applications

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **MAC** | Mandatory Access Control - Contrôle d'accès obligatoire |
| **DAC** | Discretionary Access Control - Contrôle d'accès discrétionnaire |
| **SELinux** | Security-Enhanced Linux - Linux à sécurité renforcée |
| **AppArmor** | Application Armor - Armure d'application |
| **Context** | Contexte de sécurité - Étiquette attachée aux processus et fichiers |
| **Type** | Catégorie SELinux utilisée pour les décisions d'accès |
| **Domain** | Type associé à un processus en cours d'exécution |
| **Boolean** | Option on/off pour modifier le comportement de SELinux |
| **Profile** | Fichier de règles AppArmor pour une application |
| **Enforce** | Mode où les violations sont bloquées |
| **Permissive/Complain** | Mode où les violations sont loggées mais pas bloquées |
| **MLS** | Multi-Level Security - Sécurité multi-niveaux |

---

## Récapitulatif des commandes

### SELinux

| Commande | Description |
|----------|-------------|
| `getenforce` | Afficher le mode actuel |
| `setenforce 0/1` | Changer le mode temporairement |
| `sestatus` | Afficher le statut détaillé |
| `ls -Z` | Voir le contexte des fichiers |
| `ps -eZ` | Voir le contexte des processus |
| `chcon -t type fichier` | Changer le type d'un fichier |
| `restorecon -Rv chemin` | Restaurer les contextes par défaut |
| `getsebool -a` | Lister les booléens |
| `setsebool -P bool on` | Activer un booléen de façon permanente |
| `ausearch -m avc` | Rechercher les denials |
| `audit2allow -a -M module` | Générer un module de politique |

### AppArmor

| Commande | Description |
|----------|-------------|
| `aa-status` | Afficher le statut et les profils chargés |
| `aa-enforce profil` | Passer un profil en mode enforce |
| `aa-complain profil` | Passer un profil en mode complain |
| `aa-disable profil` | Désactiver un profil |
| `aa-genprof app` | Générer un nouveau profil |
| `aa-logprof` | Mettre à jour les profils depuis les logs |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/selinux/config` | Configuration SELinux |
| `/var/log/audit/audit.log` | Logs d'audit SELinux |
| `/etc/apparmor.d/` | Répertoire des profils AppArmor |
| `/var/log/syslog` | Logs AppArmor (Ubuntu) |

---

## Ressources

- SELinux Project Wiki - selinuxproject.org
- AppArmor Wiki - gitlab.com/apparmor
- Red Hat SELinux User's and Administrator's Guide
- Ubuntu AppArmor Documentation

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Contournement de MAC pour privesc |
| TryHackMe | [Linux Hardening](https://tryhackme.com/room/dvlinuxhardening) | Durcissement Linux incluant MAC |
| TryHackMe | [Red Hat Enterprise Linux](https://tryhackme.com/room/dvredhat) | Administration RHEL avec SELinux |
| HackTheBox | [Machines Linux](https://app.hackthebox.com/machines) | Scénarios avec SELinux/AppArmor |
