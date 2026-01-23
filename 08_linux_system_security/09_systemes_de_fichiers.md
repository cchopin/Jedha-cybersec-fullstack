# Les systèmes de fichiers

**Durée : 40 min**

## Ce que vous allez apprendre dans ce cours

Les systèmes de fichiers définissent comment les données sont stockées, accédées, protégées et récupérées. Un système de fichiers mal configuré peut ralentir votre système, perdre des logs critiques ou laisser des surfaces d'attaque ouvertes. Dans cette leçon, vous apprendrez à :

- comparer les principaux systèmes de fichiers,
- créer et vérifier des systèmes de fichiers,
- identifier une utilisation suspecte du disque,
- sécuriser les systèmes de fichiers virtuels et montables.

À la fin, vous comprendrez pourquoi un attaquant pourrait adorer un `/tmp` non surveillé avec `noexec` manquant !

---

## Les différents systèmes de fichiers

Linux supporte plusieurs systèmes de fichiers, chacun conçu pour des besoins différents. Choisir le bon affecte les performances du système, la fiabilité et la réponse lors d'incidents.

### Systèmes de fichiers à usage général

| Système | Description |
|---------|-------------|
| **ext4** | Le plus déployé sous Linux. Stable, bien documenté, supporte le journaling. La plupart des outils de récupération le supportent, mais manque de snapshots ou compression natifs. Bon pour usage général et environnements à faible risque. |
| **XFS** | Performant avec les gros fichiers et I/O à haut débit. Utilise le journaling et passe à l'échelle sur des volumes multi-To. Réduction non supportée et outils de récupération limités. Idéal pour serveurs de logs, cibles de sauvegarde. |
| **Btrfs** | Système de fichiers moderne offrant snapshots, checksums et compression. Les snapshots aident à la récupération rapide, mais complexe et peut se comporter de manière imprévisible sous charge. |
| **FAT32** | Commun sur clés USB et médias amovibles. Supporté partout, mais manque de permissions, journaling et contrôles de sécurité. Risque sur systèmes partagés. |
| **NTFS** | Par défaut sur Windows, support Linux via ntfs-3g. Plus lent et moins fiable pour l'écriture. Utilisé dans les systèmes dual-boot ou disques partagés. |

### Tableau comparatif

| Fonctionnalité | ext4 | XFS | Btrfs | FAT32 | NTFS |
|----------------|------|-----|-------|-------|------|
| Journaling | Oui | Oui | Oui | Non | Oui |
| Snapshots | Non | Non | Oui | Non | Non |
| Compression | Non | Non | Oui | Non | Non |
| Checksums | Métadonnées uniquement | Non | Données et métadonnées | Non | Non |
| Chiffrement | Supporté (fscrypt) | Non (utiliser LUKS) | Supporté (natif) | Non | Oui |
| Support Linux | Natif, défaut | Natif, défaut RHEL | Natif, en maturation | Natif | Via ntfs-3g |
| Support Windows | Non | Non | Non | Oui | Natif |

### Systèmes de fichiers spéciaux

Ces systèmes de fichiers sont créés automatiquement par le système ou des outils spécifiques :

| Système | Description |
|---------|-------------|
| **tmpfs** | Système de fichiers en mémoire utilisé pour `/tmp`, `/run` ou conteneurs. Rapide mais volatile (données disparaissent au reboot) |
| **squashfs** | Système de fichiers compressé en lecture seule utilisé dans les CD live, firmware et conteneurs |
| **configfs, debugfs, tracefs** | Interfaces noyau exposées comme système de fichiers pour la configuration des sous-systèmes noyau ou obtenir des informations de debug |

> **Sécurité** : Il est généralement considéré comme une bonne pratique de sécurité de supprimer ou ne pas monter debugfs et tracefs sur les systèmes de production.

---

## Créer et vérifier des systèmes de fichiers

### Créer un système de fichiers avec mkfs

```bash
# Créer un périphérique plus grand pour les tests
$ dd if=/dev/zero of=bigdisk.img bs=1M count=320
$ sudo losetup --find --partscan bigdisk.img

# Créer une partition avec parted
$ sudo parted /dev/loop9
(parted) mktable gpt
(parted) mkpart
Partition name? part0
File system type? [ext2]?
Start? 1MiB
End? 100%
(parted) quit

# Formater en ext4
$ sudo mkfs.ext4 /dev/loop9p1
# Ou avec le paramètre -t
$ sudo mkfs -t ext4 /dev/loop9p1
```

Pour formater en XFS ou Btrfs, installez les paquets nécessaires :

```bash
# XFS
$ sudo apt install xfsprogs
$ sudo mkfs.xfs -f /dev/loop9p1

# Btrfs
$ sudo apt install btrfs-progs
$ sudo mkfs.btrfs -f /dev/loop9p1
```

> **Attention** : Formater un périphérique signifie effacer toutes les données déjà présentes !

### Vérifier les systèmes de fichiers

Si vous devez vérifier votre système de fichiers pour des problèmes et incohérences :

| Système de fichiers | Commande de vérification |
|---------------------|-------------------------|
| ext4 | `sudo fsck /dev/loop9p1` |
| XFS | `sudo xfs_repair /dev/loop9p1` |
| Btrfs | `sudo btrfs check /dev/loop9p1` |

> **Bonne pratique** : Planifiez une sauvegarde ou un snapshot avant de tenter de réparer un système de fichiers. Ces outils sont très utiles après des coupures de courant, arrêts non propres ou problèmes de disque suspects.

---

## Comprendre la disposition du système de fichiers Linux

Le système de fichiers Linux est un arbre de répertoires unique enraciné à `/` qui inclut les dossiers système, données utilisateur et systèmes de fichiers virtuels.

### Répertoires principaux

| Chemin | Description | Réel ou virtuel ? | Partition séparée ? |
|--------|-------------|-------------------|---------------------|
| `/` | Racine de l'arbre | Réel | N/A (couche de base) |
| `/bin`, `/sbin` | Binaires essentiels, toujours accessibles | Réel | Généralement partie de / |
| `/etc` | Fichiers de configuration système | Réel | Rarement |
| `/usr` | Applications et bibliothèques partagées en lecture seule | Réel | Souvent |
| `/home` | Répertoires utilisateurs | Réel | Souvent |
| `/var` | Logs, peut grossir rapidement | Réel | Souvent |
| `/tmp` | Fichiers temporaires, effacés au reboot | tmpfs ou réel | Souvent |
| `/boot` | Noyau, configs du bootloader | Réel | Souvent (peut être ro) |
| `/dev` | Périphériques virtuels gérés par udev | devtmpfs | Toujours séparé |
| `/proc` | Interface noyau pour infos processus | proc | Toujours séparé |
| `/sys` | Interface noyau pour infos matériel | sysfs | Toujours séparé |
| `/run` | Données runtime volatiles | tmpfs | Oui |
| `/mnt`, `/media` | Points de montage pour périphériques temporaires/externes | Réel | Généralement non |
| `/srv` | Données servies par des services (FTP, NFS) | Réel | Optionnel |

### Points clés de sécurité

| Répertoire | Considérations de sécurité |
|------------|---------------------------|
| `/etc` | Surveiller les configs malveillantes, utilisateurs, clés SSH. Les modifications ici changent le comportement système |
| `/bin`, `/sbin`, `/usr` | Devraient être immutables ou surveillés. Des binaires modifiés signifient des backdoors potentielles |
| `/home` | Peut être utilisé par un attaquant pour la persistance (aliases, scripts, crontabs). Chiffrer si nécessaire, monter avec `nodev` (optionnellement `noexec`) |
| `/var` | Les logs peuvent être effacés, inondés ou utilisés pour cacher des payloads. Utiliser une partition séparée avec limites de taille, monter avec `nosuid`, `nodev` et possiblement `noexec` |
| `/tmp` | Commun pour les payloads temporaires. Toujours monter avec `noexec`, `nodev`, `nosuid` |
| `/proc`, `/sys` | Fuient les internes du système. Si vous utilisez des conteneurs, restreindre l'accès |
| `/boot` | Devrait être monté avec `ro`, `nodev`, `nosuid`. Ne pas permettre l'écriture sauf pour mettre à jour le noyau |
| Disques externes | Toujours monter avec `nodev`, `noexec` et `nosuid` |

---

## Surveiller l'utilisation du disque

Une utilisation inattendue du disque peut faire planter des services, cacher une exfiltration ou signaler une attaque en cours. Surveiller l'espace disque et les I/O vous aide à repérer ces problèmes avant qu'ils n'escaladent.

### Vérifier l'utilisation avec df

```bash
$ df -h
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              391M  1.8M  389M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  7.6G  1.7G  82% /
tmpfs                              2.0G     0  2.0G   0% /dev/shm
/dev/nvme0n1p2                     1.7G  203M  1.4G  13% /boot
/dev/nvme0n1p1                     952M  6.4M  945M   1% /boot/efi
```

### Identifier ce qui prend de l'espace avec du

```bash
# Taille des dossiers dans /var
$ du -sh /var/*

# Trier par taille
$ du -sh /var/* | sort -h
```

### Exploration interactive avec ncdu

`ncdu` est un visualiseur interactif de `du`, excellent pour scanner de gros disques :

```bash
$ sudo apt install ncdu
$ ncdu /
```

![ncdu](assets/ncdu.png)

### Surveiller les I/O avec iotop

`iotop` affiche une vue en temps réel de l'utilisation du disque par processus :

```bash
$ sudo apt install iotop
$ sudo iotop
```

**Que surveiller :**
- Usage disque élevé : vérifier que le processus associé est censé faire cela
- Processus comme cron ou scripts utilisateur aléatoires avec I/O élevé : pourrait indiquer inondation de logs, crypto mineurs ou exfiltration de données

Vous pouvez aussi utiliser `iotop -a` pour accumuler les I/O totaux : cela aide à attraper les processus qui font de petites écritures constamment (comme des keyloggers ou beacons).

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Filesystem** | Système de fichiers - Structure permettant d'organiser les données sur un support |
| **ext4** | Fourth Extended Filesystem - Système de fichiers par défaut sur la plupart des distributions Linux |
| **XFS** | Système de fichiers hautes performances développé par SGI |
| **Btrfs** | B-tree Filesystem - Système de fichiers moderne avec fonctionnalités avancées |
| **FAT32** | File Allocation Table 32-bit - Système de fichiers simple et universel |
| **NTFS** | New Technology File System - Système de fichiers par défaut de Windows |
| **Journaling** | Journalisation - Technique qui aide à protéger contre la corruption de données |
| **Snapshot** | Instantané - Copie de l'état d'un volume à un instant T |
| **Checksum** | Somme de contrôle - Valeur calculée pour vérifier l'intégrité des données |
| **tmpfs** | Temporary Filesystem - Système de fichiers en mémoire RAM |
| **squashfs** | Système de fichiers compressé en lecture seule |
| **fsck** | File System Consistency Check - Outil de vérification de système de fichiers |

---

## Récapitulatif des commandes

### Création de systèmes de fichiers

| Commande | Description |
|----------|-------------|
| `sudo mkfs.ext4 /dev/X` | Formater en ext4 |
| `sudo mkfs.xfs /dev/X` | Formater en XFS |
| `sudo mkfs.btrfs /dev/X` | Formater en Btrfs |
| `sudo mkfs -t type /dev/X` | Formater avec un type spécifique |

### Vérification de systèmes de fichiers

| Commande | Description |
|----------|-------------|
| `sudo fsck /dev/X` | Vérifier un système de fichiers ext4 |
| `sudo xfs_repair /dev/X` | Réparer un système de fichiers XFS |
| `sudo btrfs check /dev/X` | Vérifier un système de fichiers Btrfs |

### Surveillance de l'utilisation

| Commande | Description |
|----------|-------------|
| `df -h` | Afficher l'utilisation des systèmes de fichiers montés |
| `du -sh /chemin/*` | Taille des dossiers dans un répertoire |
| `du -sh /chemin/* \| sort -h` | Trier par taille |
| `ncdu /` | Exploration interactive de l'utilisation |
| `sudo iotop` | Surveiller les I/O par processus en temps réel |
| `sudo iotop -a` | Accumuler les I/O totaux |

### Fichiers et répertoires importants

| Chemin | Description |
|--------|-------------|
| `/etc/fstab` | Configuration des montages automatiques |
| `/proc/mounts` | Montages actuels |
| `/var/log/` | Logs système |
| `/tmp/` | Fichiers temporaires |

---

## Ressources

- Classic SysAdmin: The Linux Filesystem Explained - The Linux Foundation
- Securing Linux Filesystems: Best Practices for DevOps Security - Dulanjana Lakmal

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Fundamentals Part 2](https://tryhackme.com/room/linuxfundamentalspart2) | Système de fichiers et permissions |
| TryHackMe | [Linux File System Analysis](https://tryhackme.com/room/introtodiskanalysis) | Analyse forensique des systèmes de fichiers |
| TryHackMe | [Disk Analysis & Autopsy](https://tryhackme.com/room/introtodiskanalysis) | Investigation de disque |
| HackTheBox | [Challenges Forensics](https://app.hackthebox.com/challenges) | Défis d'analyse de systèmes de fichiers |
