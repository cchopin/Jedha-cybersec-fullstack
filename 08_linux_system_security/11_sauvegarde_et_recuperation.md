# Sauvegarde et récupération

**Durée : 30 min**

## Ce que vous allez apprendre dans ce cours

Maintenant que vous savez comment assurer la confidentialité et l'intégrité de votre stockage, qu'en est-il de son accessibilité ? Des sauvegardes régulières et pertinentes garantissent que même en cas de brèche ou de défaillance système, vous pouvez récupérer les données importantes rapidement et restaurer les opérations aussi vite que possible. Dans cette leçon, vous allez :

- apprendre les principes de base de la sauvegarde,
- découvrir les outils de sauvegarde comme rsync,
- comprendre la différence entre sauvegardes complètes, incrémentales et différentielles.

---

## Principes et stratégies de sauvegarde

### Pourquoi sauvegarder ?

Les sauvegardes sont essentielles car la perte de données est inévitable. Que ce soit à cause d'une suppression accidentelle, d'une défaillance matérielle, d'un malware ou de catastrophes naturelles, aucun système n'est immunisé. Sans sauvegarde, la récupération peut être impossible ou extrêmement coûteuse. Les sauvegardes fournissent un filet de sécurité qui permet aux organisations de restaurer les opérations rapidement et de protéger les informations précieuses contre la perte permanente.

### Identifier ce qu'il faut sauvegarder

Il n'y a pas de recette magique pour répondre à tous vos besoins de sauvegarde. D'abord, vous devez identifier quelles données sont essentielles aux opérations ou à la sécurité :

| Question | Considération |
|----------|---------------|
| Quelle perte perturberait votre service ? | Bases de données, fichiers de configuration |
| Qu'est-ce qui est légalement requis de conserver ? | Logs, données utilisateurs |
| Priorités | Données utilisateurs, documents clés |

Vous pouvez aussi vouloir sauvegarder des systèmes entiers, incluant les fichiers OS, applications installées et configurations.

### Quand sauvegarder ?

Une fois que vous savez **quoi**, vous devez penser au **quand** : évaluez l'impact de la perte de chaque type de données.

| Type de données | Fréquence recommandée |
|-----------------|----------------------|
| Données à fort impact | Sauvegardes plus fréquentes, stockage sécurisé |
| Données moins critiques | Intervalles plus longs, archivage possible |

### La règle 3-2-1

Voici une bonne pratique largement recommandée pour les sauvegardes :

| Règle | Description |
|-------|-------------|
| **3 copies** | Gardez trois copies de vos données |
| **2 types de médias** | Stockez ces copies sur deux types de médias différents (ex: disque local et stockage cloud) |
| **1 copie hors site** | Assurez-vous qu'une copie est hors site (ex: cloud ou emplacement distant) |

Suivre cette règle réduit le risque de perdre toutes les copies à cause d'un point de défaillance unique, comme des défauts matériels ou des dommages environnementaux.

---

## Types de sauvegardes

Il existe trois types de sauvegarde : sauvegardes complètes, incrémentales et différentielles. Le choix entre elles dépend de la fréquence de sauvegarde nécessaire et de la rapidité de restauration requise.

### Sauvegarde complète

| Caractéristique | Description |
|-----------------|-------------|
| **Principe** | Copie toutes les données à chaque fois |
| **Avantage** | Restauration simple et rapide |
| **Inconvénient** | Prend plus de temps et d'espace |

### Sauvegarde incrémentale

| Caractéristique | Description |
|-----------------|-------------|
| **Principe** | Sauvegarde uniquement les changements depuis la dernière sauvegarde (complète ou incrémentale) |
| **Avantage** | Rapide et économique en espace |
| **Inconvénient** | Restauration plus complexe (nécessite toute la chaîne) |

### Sauvegarde différentielle

| Caractéristique | Description |
|-----------------|-------------|
| **Principe** | Sauvegarde tous les changements depuis la dernière sauvegarde complète |
| **Avantage** | Restauration plus simple que l'incrémentale |
| **Inconvénient** | Taille croissante au fil du temps |

![Types de sauvegardes](assets/backup_types.png)

---

## Sauvegarde en pratique

Plusieurs outils en ligne de commande sont couramment utilisés pour les sauvegardes dans les environnements Linux. Chacun sert un objectif différent et répond à des besoins différents.

### rsync - Synchronisation efficace

`rsync` est efficace pour synchroniser des répertoires, surtout sur le réseau. Il transfère uniquement les fichiers modifiés et peut préserver les permissions, horodatages et liens symboliques.

```bash
# Créer un dossier de sauvegarde
$ mkdir ~/backup

# Copier et préserver les attributs (-a)
$ rsync -av ~/Documents/ ~/backup

# Synchroniser avec un serveur distant
$ rsync -av ~/Documents/ user@server:/backup/
```

| Option | Description |
|--------|-------------|
| `-a` | Mode archive (préserve liens symboliques, permissions, horodatages...) |
| `-v` | Mode verbeux |
| `-z` | Compression pendant le transfert |
| `--delete` | Supprime les fichiers dans la destination qui n'existent plus dans la source |

### tar - Archives compressées

`tar` est utile pour les sauvegardes de type snapshot que vous pouvez stocker ou transférer facilement.

```bash
# Créer une archive compressée du dossier home
$ tar -czf backup-home.tar.gz /home/jedha/

# Extraire une archive
$ tar -xzf backup-home.tar.gz

# Lister le contenu d'une archive
$ tar -tzf backup-home.tar.gz
```

| Option | Description |
|--------|-------------|
| `-c` | Créer une archive |
| `-x` | Extraire une archive |
| `-z` | Compresser avec gzip |
| `-f` | Spécifier le fichier archive |
| `-v` | Mode verbeux |
| `-t` | Lister le contenu |

### dd - Copie bit à bit

`dd` est idéal pour les copies bas niveau, bit par bit, de disques ou partitions entiers. Il capture tout mais est plus lent et moins efficace en espace.

```bash
# Cloner un disque entier vers un fichier image
$ sudo dd if=/dev/ubuntu-vg/ubuntu-lv of=backup.img bs=4M status=progress
```

| Option | Description |
|--------|-------------|
| `if=` | Fichier/périphérique d'entrée |
| `of=` | Fichier/périphérique de sortie |
| `bs=` | Taille de bloc |
| `status=progress` | Afficher la progression |

### partclone - Clonage de partitions

`partclone` est un outil spécialisé pour cloner des partitions plutôt que des sauvegardes de fichiers générales. Il copie uniquement les blocs utilisés d'un système de fichiers, le rendant plus rapide et plus efficace en espace que `dd`.

```bash
# Sauvegarder une partition ext4
$ sudo partclone.ext4 -c -s /dev/sda1 -o backup.img

# Restaurer
$ sudo partclone.ext4 -r -s backup.img -o /dev/sda1
```

### Automatisation avec cron

Une fois que vous avez décidé votre politique de sauvegarde et choisi le bon outil, vous pouvez utiliser des scripts et des tâches cron pour automatiser le processus :

```bash
# Éditer le crontab
$ crontab -e

# Ajouter une sauvegarde quotidienne à 2h du matin
0 2 * * * rsync -av /home/user/important/ /backup/daily/
```

### Outils avancés

Pour des besoins plus complexes, vous pouvez utiliser des outils comme **BorgBackup** ou **Restic** : ils incluent souvent des fonctionnalités comme les snapshots, la compression et le chiffrement, réduisant le besoin de gérer ces besoins vous-même.

---

## Restauration

Restaurer une sauvegarde signifie ramener vos fichiers ou système à un état précédent et fonctionnel en utilisant les données sauvegardées. La méthode dépend de la façon dont la sauvegarde a été créée :

| Outil | Commande de restauration |
|-------|-------------------------|
| rsync | Inverser la commande rsync |
| tar | `tar -xzf archive.tar.gz` |
| dd | `sudo dd if=backup.img of=/dev/sdX` |
| Borg/Restic | Parcourir les sauvegardes et restaurer sélectivement |

> **Bonne pratique** : Testez toujours votre processus de restauration à l'avance. Une sauvegarde n'est aussi bonne que votre capacité à la récupérer !

---

## Récupérer des fichiers perdus

Bien qu'idéalement votre sauvegarde fournisse toutes les données dont vous avez besoin, les outils de récupération sont le dernier recours quand les sauvegardes sont manquantes, obsolètes ou incomplètes.

### Quand utiliser la récupération ?

| Situation | Description |
|-----------|-------------|
| Fichier exclu de la sauvegarde | Le fichier n'était pas dans la politique de sauvegarde |
| Échec de sauvegarde non détecté | La sauvegarde a échoué silencieusement |
| Perte juste avant la sauvegarde | La perte s'est produite juste avant la prochaine sauvegarde planifiée |

La récupération est plus efficace quand elle est effectuée immédiatement, avant que les données perdues ne soient écrasées par une nouvelle activité sur le disque.

### testdisk - Récupération de partitions

**testdisk** se spécialise dans la récupération de partitions perdues et la réparation de tables de partition corrompues. Si un système devient non bootable ou qu'un disque apparaît vide, testdisk peut souvent reconstruire la structure nécessaire pour rendre les données accessibles.

```bash
sudo apt install testdisk
sudo testdisk
```

### photorec - Récupération de fichiers

**photorec** est un choix puissant pour récupérer des fichiers individuels plutôt que des partitions entières. Malgré son nom, il peut récupérer plus que des photos. Il scanne les secteurs bruts du disque à la recherche de signatures de fichiers, le rendant utile même quand le système de fichiers est fortement endommagé ou a été formaté.

```bash
sudo photorec
```

> **Bonne pratique** : Que vous récupériez un fichier accidentellement supprimé ou essayiez de sauver des données d'une partition endommagée, il est critique de travailler à partir d'une **image disque** quand c'est possible. Des outils comme `dd` peuvent aider à cloner le disque affecté, préservant l'état original et permettant des tentatives de récupération répétées sans risque supplémentaire.

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Backup** | Sauvegarde - Copie de données pour la récupération |
| **Restore** | Restauration - Processus de récupération des données depuis une sauvegarde |
| **Full backup** | Sauvegarde complète - Copie de toutes les données |
| **Incremental backup** | Sauvegarde incrémentale - Copie des changements depuis la dernière sauvegarde |
| **Differential backup** | Sauvegarde différentielle - Copie des changements depuis la dernière sauvegarde complète |
| **rsync** | Outil de synchronisation de fichiers |
| **tar** | Tape Archive - Outil d'archivage |
| **dd** | Data Duplicator - Outil de copie bas niveau |
| **partclone** | Outil de clonage de partitions |
| **testdisk** | Outil de récupération de partitions |
| **photorec** | Outil de récupération de fichiers |
| **3-2-1 Rule** | Règle de sauvegarde : 3 copies, 2 médias, 1 hors site |
| **BorgBackup** | Outil de sauvegarde avec déduplication et chiffrement |
| **Restic** | Outil de sauvegarde moderne avec chiffrement |

---

## Récapitulatif des commandes

### rsync

| Commande | Description |
|----------|-------------|
| `rsync -av source/ dest/` | Synchroniser avec préservation des attributs |
| `rsync -avz source/ user@server:/dest/` | Synchroniser vers un serveur distant |
| `rsync -av --delete source/ dest/` | Synchroniser et supprimer les fichiers obsolètes |

### tar

| Commande | Description |
|----------|-------------|
| `tar -czf archive.tar.gz /chemin/` | Créer une archive compressée |
| `tar -xzf archive.tar.gz` | Extraire une archive |
| `tar -tzf archive.tar.gz` | Lister le contenu |

### dd

| Commande | Description |
|----------|-------------|
| `sudo dd if=/dev/X of=backup.img bs=4M status=progress` | Cloner un disque |
| `sudo dd if=backup.img of=/dev/X bs=4M status=progress` | Restaurer depuis une image |

### Récupération

| Commande | Description |
|----------|-------------|
| `sudo testdisk` | Récupérer des partitions perdues |
| `sudo photorec` | Récupérer des fichiers individuels |

### Automatisation

| Commande | Description |
|----------|-------------|
| `crontab -e` | Éditer les tâches cron |
| `crontab -l` | Lister les tâches cron |

---

## Ressources

- Essential Tips for Reliable Linux Backups - Jack M. Germain
- Linux Admin - Backup and Recovery - tutorialspoint
- 5 Linux backup and restore tips from the trenches - Ken Hess

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3) | Automatisation et scripts |
| TryHackMe | [Linux Forensics](https://tryhackme.com/room/linuxforensics) | Investigation et récupération |
| TryHackMe | [Disk Analysis & Autopsy](https://tryhackme.com/room/introtodiskanalysis) | Analyse et récupération de disque |
