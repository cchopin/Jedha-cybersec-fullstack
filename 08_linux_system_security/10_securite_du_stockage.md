# Sécurité du stockage

**Durée : 40 min**

## Ce que vous allez apprendre dans ce cours

Maintenant que vous comprenez comment Linux organise les données à travers les couches de stockage et les systèmes de fichiers, il est temps de s'assurer que ces données sont vraiment protégées. Dans cette leçon, vous apprendrez à défendre les données stockées contre le vol, la falsification et l'exposition accidentelle, même si un attaquant obtient un accès physique au périphérique. Vous apprendrez à :

- configurer et gérer le stockage chiffré avec LUKS,
- chiffrer des dossiers spécifiques avec des outils comme gocryptfs,
- appliquer des pratiques de suppression sécurisée,
- surveiller l'intégrité du système,
- reconnaître comment les attaquants cachent des données.

---

## Chiffrer les données au repos

Chiffrer les données au repos signifie protéger les données stockées sur disque, de sorte que même si le périphérique physique est volé ou accédé en dehors du système d'exploitation, les informations restent illisibles.

### Pourquoi chiffrer ?

Que se passe-t-il quand le laptop de votre administrateur système est volé pendant ses trajets ? La plupart des voleurs vont l'effacer et le revendre, mais que faire si le vol était ciblé pour accéder aux données de l'entreprise ?

Un mot de passe utilisateur fort n'aidera pas : un attaquant peut démarrer depuis une clé USB, contourner le système d'exploitation entièrement et accéder aux données brutes du disque. Sans chiffrement, l'attaquant peut récupérer les clés SSH, configs VPN, identifiants du navigateur et même les dumps mémoire de la partition swap, le tout sans avoir besoin du mot de passe utilisateur.

---

## Chiffrement de disque complet avec LUKS

Le chiffrement de disque complet (FDE - Full Disk Encryption) protège toutes les données sur un périphérique de stockage, incluant le système d'exploitation, fichiers utilisateur et espace swap. Sur les systèmes Linux, cela se fait couramment avec **LUKS** (Linux Unified Key Setup), qui fonctionne avec **dm-crypt**, le sous-système intégré au noyau Linux pour le chiffrement transparent des périphériques de blocs.

### Chiffrement transparent

Ce chiffrement est dit **transparent** : le chiffrement et déchiffrement se font automatiquement, sans intervention de l'utilisateur après que le système est déverrouillé. Cela signifie qu'une fois le volume chiffré déverrouillé (généralement au démarrage), le système le traite comme n'importe quel disque normal.

### Comment fonctionne LUKS ?

1. Quand vous créez un volume chiffré, LUKS génère aléatoirement une **clé maître** pour chiffrer et déchiffrer les données, puis vous demande de définir une **phrase de passe** pour chiffrer cette clé
2. LUKS crée un **en-tête spécial** pour le volume chiffré, contenant les paramètres de chiffrement, la clé maître chiffrée et un identifiant magique
3. Quand vous ouvrez le volume chiffré, vous tapez votre phrase de passe et LUKS déchiffre la clé maître avec. Ensuite dm-crypt utilise cette clé pour créer un périphérique virtuel `/dev/mapper/<nom>`, où les données sont déchiffrées de manière transparente à la lecture et chiffrées à l'écriture

> **Attention** : Si l'en-tête LUKS est perdu ou corrompu, les données deviennent irrécupérables !

### Créer un périphérique chiffré

```bash
# Créer un fichier image et l'attacher à un loopback
$ dd if=/dev/zero of=secure.img bs=1M count=100
$ sudo losetup -fP secure.img

# Initialiser un volume chiffré
$ sudo cryptsetup luksFormat /dev/loop10
# Entrez une phrase de passe

# Ouvrir le volume chiffré
$ sudo cryptsetup open /dev/loop10 secure_volume

# Formater et monter
$ sudo mkfs.ext4 /dev/mapper/secure_volume
$ sudo mkdir /mnt/secure
$ sudo mount /dev/mapper/secure_volume /mnt/secure

# Écrire des données
$ cd /mnt/secure
$ sudo bash -c 'echo "Secret hello!" > hello.txt'
```

### Fermer un volume chiffré

```bash
$ sudo umount /mnt/secure
$ sudo cryptsetup close secure_volume
$ sudo losetup -d /dev/loop10
```

### Vérifier le chiffrement

Comparons un disque non chiffré et un disque chiffré avec la commande `strings` :

```bash
# Sur le disque non chiffré
$ strings disk.img | grep -i hello
hello.txt

# Sur le disque chiffré
$ strings secure.img | grep hello
# (rien n'apparaît)
```

Quand le volume est fermé, le contenu est inaccessible à quiconque ne connaît pas la phrase de passe.

### LUKS en production

Dans la plupart des configurations réelles, le chiffrement LUKS de disque complet est configuré pendant l'installation du système :

- L'installateur donne l'option de chiffrer le disque entier ou des partitions spécifiques
- Au démarrage, le système demande automatiquement une phrase de passe avant de monter le système de fichiers racine
- Le fichier `/etc/crypttab` indique au système quels périphériques chiffrés déverrouiller au démarrage
- Le fichier `/etc/fstab` référence `/dev/mapper/cryptroot` comme périphérique à monter comme racine

---

## Chiffrement de dossiers spécifiques

Chiffrer uniquement un dossier spécifique peut être utile quand vous n'avez pas besoin du chiffrement de disque complet ou voulez isoler des données sensibles.

### Quand utiliser le chiffrement par dossier ?

- Répertoires personnels (surtout sur systèmes multi-utilisateurs)
- Postes de travail partagés
- Stockage de secrets sur des dossiers synchronisés dans le cloud

### gocryptfs

**gocryptfs** est une solution moderne et activement maintenue qui chiffre chaque fichier individuellement et permet aux utilisateurs de créer et monter leur propre système de fichiers, même sans accès root.

```bash
# Installer gocryptfs
$ sudo apt install gocryptfs

# Créer un dossier pour les secrets
$ mkdir ~/secrets

# Initialiser un dossier chiffré
$ gocryptfs -init ~/secrets
# Entrez une phrase de passe

# Créer un point d'accès et monter
$ mkdir ~/access_secrets
$ gocryptfs ~/secrets ~/access_secrets
# Entrez la phrase de passe

# Utiliser le dossier
$ cd ~/access_secrets
$ echo "This is a very secret sentence." >> secret.txt

# Démonter
$ fusermount -u ~/access_secrets
```

### LUKS vs gocryptfs : quand utiliser quoi ?

| Cas d'usage | LUKS | gocryptfs |
|-------------|------|-----------|
| Chiffrement fort pour tout le système | Oui | Non |
| Protéger OS, logs, swap et données utilisateur ensemble | Oui | Non |
| Phrase de passe au démarrage | Oui | Non |
| Chiffrer uniquement des dossiers spécifiques | Non | Oui |
| Pas besoin de repartitionner | Non | Oui |
| Accès aux fichiers chiffrés depuis une session utilisateur | Non | Oui |
| Systèmes multi-utilisateurs | Non | Oui |
| Dossiers chiffrés portables | Non | Oui |
| Ne nécessite pas root | Non | Oui |

---

## Chiffrement de la partition swap

Le swap est une zone du disque utilisée pour compléter la RAM, et peut contenir des fragments de données sensibles : mots de passe, documents ou même fichiers déchiffrés. Si laissé non chiffré, ces données peuvent être récupérées par un attaquant.

### Deux stratégies principales

| Stratégie | Description | Cas d'usage |
|-----------|-------------|-------------|
| **Chiffrement éphémère** | Swap chiffré avec une nouvelle clé aléatoire à chaque démarrage | Utilisation normale (les données ne persistent pas) |
| **Chiffrement persistant avec LUKS** | Comportement consistant et plus de contrôle | Si vous utilisez l'hibernation (le contenu entier de la RAM est sauvegardé dans le swap) |

> **Note** : Si vous chiffrez votre installation Linux complète avec LUKS et LVM pendant l'installation, le swap sera automatiquement chiffré aussi.

---

## Suppression sécurisée

Savez-vous comment supprimer des données de manière sécurisée ? Quand vous supprimez un fichier avec `rm`, seul le pointeur vers le fichier est supprimé : les données réelles restent sur le disque jusqu'à ce qu'elles soient écrasées. Cela signifie qu'elles peuvent souvent être récupérées avec des outils forensiques.

### shred : écraser les fichiers

`shred` écrase le contenu d'un fichier plusieurs fois avec des données aléatoires :

```bash
$ shred -u -z secret.txt
```

| Option | Description |
|--------|-------------|
| `-u` | Supprime le fichier après écrasement |
| `-z` | Ajoute une passe finale avec des zéros pour cacher le shredding |

> **Attention** : `shred` ne fonctionne de manière fiable que sur des fichiers réguliers. Les résultats ne sont pas garantis sur les systèmes de fichiers journalisés (comme ext4 avec journaling), les SSD (à cause du wear leveling) ou les systèmes de fichiers virtuels.

### wipe : écraser des partitions

`wipe` écrase des partitions ou périphériques entiers :

```bash
# Effacer notre volume non chiffré
$ sudo wipe /dev/loop3
$ strings disk.img | grep hello
# (rien)
```

### Sur les configurations modernes

Sur les configurations modernes, le chiffrement complet et l'effacement cryptographique sont souvent plus sûrs et plus fiables que shred. Pour les SSD, vous pouvez utiliser les outils d'effacement sécurisé fournis par le fabricant comme `nvme-cli`.

---

## Vérification de l'intégrité des fichiers

Souvenez-vous de la triade CIA ? Confidentialité, Intégrité et Accessibilité sont les piliers de la sécurité. Même si vous réussissez à chiffrer votre stockage de manière sécurisée pour assurer la confidentialité, c'est une bonne pratique de vérifier aussi son intégrité.

### AIDE (Advanced Intrusion Detection Environment)

Les outils de surveillance de l'intégrité des fichiers (FIM) comme **AIDE** surveillent le système pour les changements de fichiers non autorisés ou inattendus. Ils sont une défense clé pour détecter la falsification, les rootkits ou malwares furtifs.

**Comment ça fonctionne :**

1. AIDE crée une base de données de référence des fichiers critiques, enregistrant :
   - Chemin et permissions des fichiers
   - Horodatages
   - Propriétaire (utilisateur/groupe)
   - Taille des fichiers
   - Hashes cryptographiques

2. Vous pouvez exécuter une vérification pour scanner le système et comparer l'état actuel à la référence

3. Si des différences sont trouvées, l'outil produit un rapport détaillant ce qui a changé

### Utiliser AIDE

```bash
# Installer AIDE
$ sudo apt install aide

# Initialiser la base de données (peut prendre ~10 minutes)
$ sudo aide --init --config /etc/aide/aide.conf
# Crée /var/lib/aide/aide.db.new

# Vérifier le système contre la référence
$ sudo aide --check --config /etc/aide/aide.conf
```

> **Bonne pratique** : La base de données de référence devrait être stockée sur un média en lecture seule, ou même sur une machine différente (car un attaquant n'aurait qu'à la modifier pour rendre les alertes inutiles).

---

## Cacher des données

Toutes les techniques pour cacher des données ne concernent pas le chiffrement : les attaquants aiment parfois cacher des données en pleine vue, avec des techniques comme la stéganographie et les astuces de système de fichiers.

### Stéganographie

La stéganographie consiste à cacher des données dans des images, fichiers audio ou autres médias, afin de rendre l'exfiltration de données sensibles moins évidente. Typiquement, les données sont cachées dans des images.

```bash
# Avec steghide
$ steghide embed -cf cover.jpg -ef secret.txt
```

Les fichiers semblent normaux sauf s'ils sont analysés en profondeur.

### Conteneurs chiffrés

Les attaquants utilisent aussi le chiffrement pour cacher des données : avec des outils comme VeraCrypt, gocryptfs ou LUKS, ils peuvent stocker des données dans des volumes chiffrés. Ces volumes peuvent être déguisés en fichiers inoffensifs comme `.iso`, et sont difficiles à détecter sans connaître la clé ou l'activité de montage.

### Abus du système de fichiers

Cela fait référence à la manipulation de la façon dont les fichiers et répertoires sont nommés, placés ou structurés pour cacher des données aux utilisateurs ou outils de surveillance :

| Technique | Description |
|-----------|-------------|
| **Dotfiles et dotdirs** | Fichiers et dossiers commençant par `.` n'apparaissent pas jusqu'à `ls -a` et ressemblent souvent à des fichiers de configuration réguliers |
| **Noms innocents** | Donner aux fichiers des noms innocents ou ressemblant au système (ex: `README.txt`, `syslogd`) |
| **Sous-répertoires obscurs** | Enterrer les fichiers dans des sous-répertoires peu fréquentés |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **FDE** | Full Disk Encryption - Chiffrement de disque complet |
| **LUKS** | Linux Unified Key Setup - Standard de chiffrement de disque sous Linux |
| **dm-crypt** | Device Mapper Crypt - Sous-système noyau pour le chiffrement de périphériques |
| **Phrase de passe** | Mot de passe utilisé pour déchiffrer une clé de chiffrement |
| **cryptsetup** | Outil en ligne de commande pour gérer LUKS |
| **gocryptfs** | Outil de chiffrement de dossiers au niveau utilisateur |
| **AIDE** | Advanced Intrusion Detection Environment - Outil de vérification d'intégrité |
| **FIM** | File Integrity Monitoring - Surveillance de l'intégrité des fichiers |
| **Stéganographie** | Technique de dissimulation de données dans d'autres fichiers |
| **shred** | Commande pour écraser des fichiers de manière sécurisée |
| **wipe** | Commande pour effacer des partitions de manière sécurisée |
| **Wear leveling** | Technique SSD qui déplace les données, rendant l'effacement sécurisé difficile |

---

## Récapitulatif des commandes

### Chiffrement LUKS

| Commande | Description |
|----------|-------------|
| `sudo cryptsetup luksFormat /dev/X` | Initialiser un volume chiffré |
| `sudo cryptsetup open /dev/X nom` | Ouvrir un volume chiffré |
| `sudo cryptsetup close nom` | Fermer un volume chiffré |
| `sudo cryptsetup luksDump /dev/X` | Afficher les infos de l'en-tête LUKS |

### Chiffrement de dossiers (gocryptfs)

| Commande | Description |
|----------|-------------|
| `gocryptfs -init ~/secrets` | Initialiser un dossier chiffré |
| `gocryptfs ~/secrets ~/access` | Monter le dossier chiffré |
| `fusermount -u ~/access` | Démonter le dossier |

### Suppression sécurisée

| Commande | Description |
|----------|-------------|
| `shred -u -z fichier` | Écraser et supprimer un fichier |
| `sudo wipe /dev/X` | Effacer une partition |

### Vérification d'intégrité (AIDE)

| Commande | Description |
|----------|-------------|
| `sudo aide --init --config /etc/aide/aide.conf` | Créer la base de données de référence |
| `sudo aide --check --config /etc/aide/aide.conf` | Vérifier le système |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/crypttab` | Configuration des volumes chiffrés au démarrage |
| `/var/lib/aide/aide.db` | Base de données de référence AIDE |
| `/etc/aide/aide.conf` | Configuration AIDE |

---

## Ressources

- Install and Configure AIDE on Ubuntu 20.04 - kifarunix
- Configuration Recommendations of a GNU/Linux System - ANSSI

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Encryption - Crypto 101](https://tryhackme.com/room/encryptioncrypto101) | Introduction au chiffrement |
| TryHackMe | [Linux Forensics](https://tryhackme.com/room/linuxforensics) | Investigation forensique Linux |
| TryHackMe | [Disk Analysis & Autopsy](https://tryhackme.com/room/introtodiskanalysis) | Analyse de disque et récupération |
| HackTheBox | [Challenges Stego](https://app.hackthebox.com/challenges) | Défis de stéganographie |
