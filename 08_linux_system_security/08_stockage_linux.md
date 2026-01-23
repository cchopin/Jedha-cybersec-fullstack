# Le stockage Linux

**Durée : 60 min**

## Ce que vous allez apprendre dans ce cours

Des systèmes d'exploitation aux logs, des bases de données aux sauvegardes, tout ce qu'un système exécute ou mémorise dépend d'un stockage fiable et sécurisé. Dans cette leçon, vous allez explorer comment les systèmes Linux organisent et gèrent le stockage, du matériel brut jusqu'aux fichiers et répertoires accessibles aux utilisateurs. Vous apprendrez à :

- identifier et inspecter les périphériques de blocs,
- partitionner des disques,
- monter et gérer des systèmes de fichiers,
- utiliser LVM pour créer des volumes de stockage flexibles.

Un point de montage mal configuré peut sembler n'être qu'un problème de démarrage, jusqu'à ce que vous réalisiez que c'est la raison pour laquelle vos logs ont cessé d'écrire, votre sauvegarde a échoué silencieusement et vos données de réponse aux incidents ont disparu.

---

## Le modèle en couches

Pourquoi parle-t-on de "couches de stockage" ? Linux gère le stockage en utilisant une série d'abstractions en couches, chacune construite sur celle du dessous.

| Couche | Description |
|--------|-------------|
| **Périphériques de blocs** | Au niveau le plus bas, Linux interagit avec les périphériques de blocs : des unités de stockage physiques ou virtuelles comme les disques durs, SSD ou clés USB |
| **Partitions** | Sections logiques découpées dans un périphérique de blocs, permettant de séparer le stockage pour différents usages |
| **Système de fichiers** | Couche la plus haute, fournissant la structure qui permet au système et aux utilisateurs de lire, écrire et organiser les données |
| **LVM** | Couche d'abstraction au-dessus des partitions brutes, créant des volumes logiques redimensionnables |
| **Chiffrement** | Couche optionnelle (LUKS/cryptsetup) entre le périphérique et le système de fichiers pour la confidentialité |

### Pourquoi le stockage est-il important ?

Le stockage peut être utilisé de nombreuses façons pour améliorer la stabilité et la sécurité d'une machine :

**Séparation des données** : Séparer les données système, utilisateur et logs sur des partitions distinctes est une bonne pratique. Si toutes les données partagent une seule partition racine `/`, un utilisateur ou processus emballé pourrait remplir le disque, empêchant le système de démarrer ou d'écrire des logs critiques.

**Problèmes courants** : Les disques qui se remplissent sont l'un des problèmes de stockage les plus courants et perturbateurs. Quand un disque manque d'espace, les services qui en dépendent (bases de données, serveurs web, SSH) peuvent planter ou refuser de démarrer.

**Sécurité** : Du point de vue sécurité, le stockage est une surface d'attaque majeure :
- Les données sensibles laissées sur des partitions non chiffrées sont une victoire facile pour un attaquant
- Les périphériques oubliés (vieille clé USB encore montée, image loopback de debug) peuvent devenir des portes dérobées
- Les options de montage comme `noexec`, `nosuid` et `nodev` réduisent les risques de privilèges

---

## Périphériques de blocs et identification des disques

### Qu'est-ce qu'un périphérique de blocs ?

Un **périphérique de blocs** est un type de périphérique matériel sous Linux qui stocke des données en blocs de taille fixe et permet un accès aléatoire à ces blocs.

| Type | Description |
|------|-------------|
| **Disques durs (HDD)** | Utilisent des disques magnétiques rotatifs, mieux adaptés au stockage de masse |
| **SSD** | Utilisent des puces de mémoire flash sans pièces mobiles, vitesses de lecture/écriture plus rapides |
| **NVMe** | Protocole moderne pour SSD haute vitesse non connectés via SATA traditionnel |
| **Périphériques loopback** | Périphériques virtuels qui mappent un fichier régulier pour se comporter comme un vrai disque |
| **Clés USB** | Contiennent des puces de mémoire flash NAND |
| **Lecteurs CD/DVD** | La surface du disque a de minuscules creux qui reflètent le laser différemment |

Les périphériques de blocs diffèrent des **périphériques de caractères**, qui gèrent les données comme un flux continu (claviers, terminaux, imprimantes).

### Gestion par le noyau

Le noyau Linux gère les périphériques de blocs en les exposant comme des fichiers spéciaux sous le répertoire `/dev`. Ces fichiers de périphériques agissent comme des interfaces entre les outils de l'espace utilisateur et le matériel.

| Exemple | Description |
|---------|-------------|
| `/dev/sda` | Disque dur SATA |
| `/dev/nvme0n1` | SSD NVMe |
| `/dev/loop0` | Périphérique loopback |

Ce fichier spécial est différent du **point de montage** : le répertoire où un périphérique de stockage est attaché au système de fichiers pour que son contenu devienne accessible.

### La commande lsblk

`lsblk` donne une vue en arbre de tous les périphériques de blocs, montrant les points de montage, tailles et relations :

```bash
$ lsblk
NAME                      MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
loop0                       7:0    0     4K  1 loop /snap/bare/5
sr0                        11:0    1   2.7G  0 rom  /media/jedha/Ubuntu-Server
nvme0n1                   259:0    0    20G  0 disk
├─nvme0n1p1               259:1    0   953M  0 part /boot/efi
├─nvme0n1p2               259:2    0   1.8G  0 part /boot
└─nvme0n1p3               259:3    0  17.3G  0 part
  └─ubuntu--vg-ubuntu--lv 252:0    0    10G  0 lvm  /
```

**Signification des colonnes :**

| Colonne | Description |
|---------|-------------|
| `NAME` | Nom du périphérique (sda, nvme0n1, loop0) |
| `MAJ:MIN` | Numéros majeur et mineur utilisés par le noyau |
| `RM` | Si le périphérique est amovible (1) ou non (0) |
| `SIZE` | Taille totale du périphérique ou partition |
| `RO` | Si le périphérique est en lecture seule (1) ou inscriptible (0) |
| `TYPE` | Type : disk, part (partition), lvm, rom, loop |
| `MOUNTPOINTS` | Où le périphérique est monté dans le système de fichiers |

### La commande blkid

`blkid` affiche des informations détaillées sur les périphériques de blocs, incluant les UUID et types de systèmes de fichiers :

```bash
$ blkid
/dev/nvme0n1p3: UUID="RLftQH-glQj-wiiS-ErEf-z7gK-bc29-rWe4ci" TYPE="LVM2_member"
/dev/nvme0n1p1: UUID="DCB0-78C8" TYPE="vfat"
/dev/nvme0n1p2: UUID="da84daa7-0796-4e0e-9e73-32cb134633fb" TYPE="ext4"
```

| Champ | Description |
|-------|-------------|
| `UUID` | Identifiant unique pour votre périphérique |
| `TYPE` | Type de contenu (système de fichiers, LVM2_member, crypto_LUKS) |
| `BLOCK_SIZE` | Taille du plus petit bloc de données géré par le système de fichiers |

### La commande udevadm

`udevadm` est utilisé pour interroger les attributs de périphériques gérés par udev, le gestionnaire de périphériques sous Linux :

```bash
$ udevadm info --query=all --name=/dev/nvme0n1
P: /devices/pci0000:00/0000:00:17.0/nvme/nvme0/nvme0n1
M: nvme0n1
U: block
T: disk
```

Cette commande est utile pour identifier le modèle d'un périphérique ou écrire des règles udev.

---

## Partitionnement des disques

Les partitions donnent un contrôle précis sur la façon dont l'espace disque est organisé, isolé et géré. Elles permettent aussi d'utiliser différents systèmes de fichiers, options de montage ou schémas de chiffrement sur le même disque.

### Tables de partition

Derrière chaque périphérique se trouve une **table de partition** qui définit comment l'espace sur le disque est divisé :

| Type | Description |
|------|-------------|
| **MBR** (Master Boot Record) | Standard ancien, limité à 4 partitions primaires et disques de 2 To |
| **GPT** (GUID Partition Table) | Standard moderne, supporte les gros disques et nombreuses partitions, requis pour les systèmes UEFI |

Pour connaître le format de table utilisé par un disque :

```bash
$ lsblk -o NAME,PTTYPE
NAME                      PTTYPE
nvme0n1                   gpt
├─nvme0n1p1               gpt
├─nvme0n1p2               gpt
└─nvme0n1p3               gpt
```

### Format MBR avec fdisk

`fdisk` est un utilitaire texte pour créer et gérer des partitions de style MBR :

```bash
# Voir la table de partition
$ sudo fdisk -l /dev/nvme0n1

# Créer un périphérique loopback pour expérimenter
$ dd if=/dev/zero of=disk.img bs=1M count=100
$ sudo losetup --find --partscan disk.img

# Utiliser fdisk de manière interactive
$ sudo fdisk /dev/loop3
# Appuyer sur 'n' pour nouvelle partition, 'w' pour écrire
```

### GPT et MBR avec parted

`parted` est un outil flexible pour créer et gérer les tables de partition MBR et GPT :

```bash
# Voir les informations de partition
$ sudo parted /dev/loop3 print

# Créer une table GPT et une partition
$ sudo parted /dev/loop3
(parted) mklabel gpt
(parted) mkpart
Partition name? test
File system type? [ext2]?
Start? 1MiB
End? 100%
(parted) quit
```

> **Bonne pratique** : Commencer à 1 MiB assure un alignement correct, ce qui améliore les performances (surtout sur SSD).

---

## Logical Volume Manager (LVM)

LVM est une couche d'abstraction de stockage entre les disques physiques (ou partitions) et les systèmes de fichiers. Contrairement au partitionnement traditionnel, LVM introduit une couche d'abstraction qui permet de traiter le stockage de manière dynamique et ajustable.

### Composants clés

| Composant | Description |
|-----------|-------------|
| **Physical Volume (PV)** | Disque physique ou partition que LVM peut gérer |
| **Volume Group (VG)** | Pool de stockage constitué d'un ou plusieurs PV |
| **Logical Volume (LV)** | Tranche d'espace d'un groupe de volumes, se comporte comme une partition |

### Avantages de LVM

- Redimensionner les volumes (agrandir ou réduire) sans reformater ou redémarrer
- Ajouter de nouveaux disques physiques aux groupes de volumes existants
- Créer des **snapshots** (copies à un instant T) utiles pour les sauvegardes ou tests
- Séparer les volumes logiques par rôle ou type de données

### Créer et gérer des volumes

```bash
# Réinitialiser le périphérique loopback
$ sudo losetup -d /dev/loop3
$ dd if=/dev/zero of=disk.img bs=1M count=128
$ sudo losetup --find --partscan disk.img

# Créer un volume physique
$ sudo pvcreate /dev/loop3

# Créer un groupe de volumes
$ sudo vgcreate myvg /dev/loop3

# Créer un volume logique de 50 Mo
$ sudo lvcreate -L 50M -n mydata myvg

# Étendre le volume
$ sudo lvextend -L +10M /dev/myvg/mydata
```

### Formater et monter un volume LVM

```bash
# Créer un système de fichiers ext4
$ sudo mkfs.ext4 -L myvol /dev/myvg/mydata

# Monter le volume
$ sudo mkdir /mnt/my_mountpoint
$ sudo mount /dev/myvg/mydata /mnt/my_mountpoint/

# Écrire des données
$ cd /mnt/my_mountpoint
$ sudo bash -c 'echo "This is my first volume!" > hello.txt'
```

### Snapshots LVM

Les snapshots sont des copies "copy-on-write" : LVM enregistre uniquement les changements faits au volume original après la création du snapshot.

```bash
# Créer un snapshot
$ sudo lvcreate -s -L 10M -n mydata-snap /dev/myvg/mydata

# Monter le snapshot
$ sudo mkdir /mnt/snapshot
$ sudo mount /dev/myvg/mydata-snap /mnt/snapshot
```

> **Attention** : Les snapshots ne sont PAS des sauvegardes. Ils sont temporaires et reliés au volume original.

---

## Montage et persistance

### Vérifier les périphériques montés

```bash
$ df -h
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              391M  1.8M  389M   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  7.6G  1.8G  82% /
/dev/nvme0n1p2                     1.7G  203M  1.4G  13% /boot
/dev/nvme0n1p1                     952M  6.4M  945M   1% /boot/efi
```

| Type | Description |
|------|-------------|
| `tmpfs` | Systèmes de fichiers en mémoire (RAM), pas sur disque |
| `efivarfs` | Stocke les variables de firmware EFI |
| `/dev/mapper/*` | Volumes logiques LVM |

### Monter manuellement avec mount

```bash
$ sudo mount /dev/myvg/mydata /mnt/my_mountpoint

# Démonter
$ sudo umount /mnt/my_mountpoint
```

Le périphérique doit contenir un système de fichiers valide et le point de montage doit exister.

### Montages persistants avec /etc/fstab

Le fichier `/etc/fstab` est utilisé pour que les montages se fassent automatiquement au démarrage. Utilisez l'UUID du périphérique (pas le nom) pour la fiabilité :

```bash
$ blkid /dev/myvg/mydata
/dev/myvg/mydata: UUID="04a7d4a0-d85a-4344-94c0-cefc73133f91" TYPE="ext4"
```

Ajoutez cette ligne dans `/etc/fstab` :

```
UUID=04a7d4a0-d85a-4344-94c0-cefc73133f91  /mnt/my_mountpoint  ext4  defaults  0  2
```

| Champ | Description |
|-------|-------------|
| UUID | Identifiant unique du périphérique |
| Point de montage | Où monter le périphérique |
| Type | Type de système de fichiers |
| Options | Options de montage (defaults) |
| dump | 0 = pas de sauvegarde dump |
| fsck | Ordre de vérification (2 pour les partitions non-root) |

Vérifiez la syntaxe avec :

```bash
$ sudo mount -a
```

> **Attention** : Une entrée fstab mal configurée peut empêcher le système de démarrer !

### Options de montage sécurisées

| Option | Description |
|--------|-------------|
| `noexec` | Empêche l'exécution de binaires depuis le système de fichiers monté |
| `nodev` | Empêche les fichiers de périphériques d'être utilisés |
| `nosuid` | Désactive les bits setuid/setgid, empêchant l'élévation de privilèges |
| `ro` | Monte le système de fichiers en lecture seule |

Ces options sont fortement recommandées pour `/home`, `/tmp`, `/var/log` ou tout média externe ou amovible.

```bash
# Voir les options d'un système de fichiers monté
$ mount | grep /mnt/my_mountpoint

# Vue hiérarchique des montages
$ findmnt
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Block device** | Périphérique de blocs - Matériel stockant des données en blocs de taille fixe |
| **Partition** | Section logique d'un disque physique |
| **MBR** | Master Boot Record - Ancien format de table de partition |
| **GPT** | GUID Partition Table - Format moderne de table de partition |
| **LVM** | Logical Volume Manager - Gestionnaire de volumes logiques |
| **PV** | Physical Volume - Volume physique dans LVM |
| **VG** | Volume Group - Groupe de volumes dans LVM |
| **LV** | Logical Volume - Volume logique dans LVM |
| **UUID** | Universally Unique Identifier - Identifiant unique universel |
| **Mount point** | Point de montage - Répertoire où un périphérique est attaché |
| **Snapshot** | Instantané - Copie à un instant T d'un volume |
| **UEFI** | Unified Extensible Firmware Interface - Interface firmware moderne |
| **loopback** | Périphérique virtuel mappant un fichier comme un disque |
| **tmpfs** | Système de fichiers temporaire en mémoire RAM |

---

## Récapitulatif des commandes

### Identification des périphériques

| Commande | Description |
|----------|-------------|
| `lsblk` | Vue en arbre des périphériques de blocs |
| `lsblk -o NAME,PTTYPE` | Afficher le type de table de partition |
| `blkid` | Afficher UUID et types de systèmes de fichiers |
| `udevadm info --query=all --name=/dev/X` | Attributs détaillés d'un périphérique |

### Partitionnement

| Commande | Description |
|----------|-------------|
| `sudo fdisk -l /dev/X` | Lister les partitions d'un disque |
| `sudo fdisk /dev/X` | Partitionner en mode interactif (MBR) |
| `sudo parted /dev/X print` | Afficher les infos de partition |
| `sudo parted /dev/X mklabel gpt` | Créer une table GPT |
| `sudo parted /dev/X mkpart` | Créer une partition |

### Périphériques loopback

| Commande | Description |
|----------|-------------|
| `dd if=/dev/zero of=disk.img bs=1M count=100` | Créer un fichier image |
| `sudo losetup --find --partscan disk.img` | Attacher à un périphérique loopback |
| `losetup -l` | Lister les périphériques loopback actifs |
| `sudo losetup -d /dev/loopX` | Détacher un périphérique loopback |

### LVM

| Commande | Description |
|----------|-------------|
| `sudo pvcreate /dev/X` | Créer un volume physique |
| `sudo vgcreate nom /dev/X` | Créer un groupe de volumes |
| `sudo lvcreate -L 50M -n nom vg` | Créer un volume logique |
| `sudo lvextend -L +10M /dev/vg/lv` | Étendre un volume logique |
| `sudo lvcreate -s -L 10M -n snap /dev/vg/lv` | Créer un snapshot |

### Montage

| Commande | Description |
|----------|-------------|
| `df -h` | Afficher l'utilisation des systèmes de fichiers |
| `sudo mount /dev/X /mnt/point` | Monter un périphérique |
| `sudo umount /mnt/point` | Démonter |
| `sudo mount -a` | Monter tout depuis /etc/fstab |
| `findmnt` | Vue hiérarchique des montages |
| `mount \| grep point` | Voir les options de montage |

### Formatage

| Commande | Description |
|----------|-------------|
| `sudo mkfs.ext4 /dev/X` | Formater en ext4 |
| `sudo mkfs.ext4 -L label /dev/X` | Formater avec un label |

---

## Ressources

- How To Configure Storage On Linux - Mohamed Boubaker
- OPW, Linux: The block I/O layer - ari-ava
- Perform Basic Administration Tasks for Storage Devices - Justin Ellingwood
- Findmnt Command: Querying Filesystems in Linux Made Easy - Egidio Docile

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Fundamentals Part 1](https://tryhackme.com/room/linuxfundamentalspart1) | Bases de Linux incluant le système de fichiers |
| TryHackMe | [Linux Fundamentals Part 2](https://tryhackme.com/room/linuxfundamentalspart2) | Permissions et système de fichiers |
| TryHackMe | [Linux Fundamentals Part 3](https://tryhackme.com/room/linuxfundamentalspart3) | Automatisation et montages |
| TryHackMe | [Linux File System Analysis](https://tryhackme.com/room/introtodiskanalysis) | Analyse forensique du système de fichiers |
