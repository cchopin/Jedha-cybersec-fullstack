# Secure Partition - RoboYak Industries

## Contexte

You've been contacted by RoboYak Industries, a startup that designs autonomous mountain herding robots. The engineering team needs a secure space to store sensitive design schematics and AI training datasets.

Your task is to provision a new encrypted partition where this data can be safely stored. The company policy also mandates disabling the execution of binaries from data directories, as a precaution against accidental malware execution.

The company has provided you with a machine with a small storage at /dev/sdb. Your mission is to ensure the new storage:

- is encrypted at rest,
- formatted with ext4,
- mounts with the correct security options,
- automatically mounts on system boot.

The robots are counting on you. Make sure those yaks don't get access to the AI blueprints.

## Etat initial

```
jedha@ubuntu:~$ lsblk
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
sda      8:0    0    32G  0 disk
├─sda1   8:1    0     1M  0 part
└─sda2   8:2    0    32G  0 part /
sdb      8:16   0     4G  0 disk
```

---

## Solution

### Etape 1 : Passer en root et installer les outils

```bash
sudo su

apt update
apt install cryptsetup e2fsprogs
```

> `cryptsetup` : outil pour gérer le chiffrement LUKS - voir [10_securite_du_stockage.md](../10_securite_du_stockage.md)

### Etape 2 : Initialiser le chiffrement LUKS sur /dev/sdb

```bash
cryptsetup luksFormat /dev/sdb
```

- Taper `YES` en majuscules pour confirmer
- Définir une phrase de passe (passphrase) solide

> LUKS (Linux Unified Key Setup) chiffre les données au repos - voir [10_securite_du_stockage.md](../10_securite_du_stockage.md#chiffrement-de-disque-complet-avec-luks)

### Etape 3 : Ouvrir le volume chiffré

```bash
cryptsetup open /dev/sdb secure_data
```

Cela crée le périphérique `/dev/mapper/secure_data`

### Etape 4 : Formater en ext4

```bash
mkfs.ext4 /dev/mapper/secure_data
```

> `mkfs.ext4` : création de système de fichiers - voir [09_systemes_de_fichiers.md](../09_systemes_de_fichiers.md#créer-un-système-de-fichiers-avec-mkfs)

### Etape 5 : Créer le point de montage et monter

```bash
mkdir /mnt/secure_data
mount /dev/mapper/secure_data /mnt/secure_data
```

> `mount` : montage de périphériques - voir [08_stockage_linux.md](../08_stockage_linux.md#monter-manuellement-avec-mount)

### Etape 6 : Récupérer l'UUID du disque chiffré

```bash
blkid /dev/sdb
```

Exemple de sortie :
```
/dev/sdb: UUID="5ff048c9-f56c-4be2-9fcb-5c6b15e022cd" TYPE="crypto_LUKS"
```

> `blkid` : identification des périphériques - voir [08_stockage_linux.md](../08_stockage_linux.md#la-commande-blkid)

### Etape 7 : Configurer le déverrouillage automatique (crypttab)

```bash
echo "secure_data UUID=5ff048c9-f56c-4be2-9fcb-5c6b15e022cd none luks" >> /etc/crypttab
```

> `none` signifie que le système demandera la passphrase au démarrage
>
> `/etc/crypttab` : configuration des volumes chiffrés au boot - voir [10_securite_du_stockage.md](../10_securite_du_stockage.md#luks-en-production)

### Etape 8 : Configurer le montage automatique (fstab) avec options de sécurité

```bash
echo "/dev/mapper/secure_data /mnt/secure_data ext4 defaults,noexec,nodev,nosuid 0 2" >> /etc/fstab
```

> `/etc/fstab` : montages persistants - voir [08_stockage_linux.md](../08_stockage_linux.md#montages-persistants-avec-etcfstab)
>
> Options `noexec,nodev,nosuid` : sécurisation des montages - voir [08_stockage_linux.md](../08_stockage_linux.md#options-de-montage-sécurisées)

### Etape 9 : Appliquer et vérifier

```bash
systemctl daemon-reload
mount -o remount /mnt/secure_data
mount | grep secure_data
```

Résultat attendu :
```
/dev/mapper/secure_data on /mnt/secure_data type ext4 (rw,nosuid,nodev,noexec,relatime)
```

---

## Options de sécurité expliquées

| Option | Description |
|--------|-------------|
| `noexec` | Empêche l'exécution de binaires (protection contre malware) |
| `nodev` | Ignore les fichiers de périphériques |
| `nosuid` | Désactive les bits SUID/SGID (empêche l'élévation de privilèges) |

---

## Erreurs courantes à éviter

### 1. Oublier le fichier destination avec `tee -a`

**Erreur :**
```bash
echo "secure_data UUID=..." | sudo tee -a
# Il manque le fichier !
```

**Correct :**
```bash
echo "secure_data UUID=..." | sudo tee -a /etc/crypttab
```

Ou plus simple avec `>>` :
```bash
echo "secure_data UUID=..." >> /etc/crypttab
```

### 2. Entrées dupliquées dans fstab/crypttab

Si tu exécutes plusieurs fois les commandes `echo >> /etc/fstab`, tu crées des doublons.

**Vérifier avant d'ajouter :**
```bash
cat /etc/fstab
cat /etc/crypttab
```

**Si doublons, éditer manuellement :**
```bash
vi /etc/fstab
# Supprimer les lignes en double
```

### 3. Ligne fstab mal formatée (retour à la ligne)

**Erreur :**
```
/dev/mapper/secure_data /mnt/secure_data ext4
  defaults,noexec,nodev,nosuid 0 2
```

**Correct (tout sur une seule ligne) :**
```
/dev/mapper/secure_data /mnt/secure_data ext4 defaults,noexec,nodev,nosuid 0 2
```

### 4. Oublier de remonter après modification de fstab

Les changements dans `/etc/fstab` ne s'appliquent pas automatiquement.

```bash
systemctl daemon-reload
mount -o remount /mnt/secure_data
```

### 5. Vérifier sans les options de sécurité

Toujours vérifier que les options sont bien appliquées :
```bash
mount | grep secure_data
# Doit afficher : noexec,nodev,nosuid
```

---

## Vérification finale

```bash
# 1. Le volume est monté avec les bonnes options
mount | grep secure_data
# -> (rw,nosuid,nodev,noexec,relatime)

# 2. Le chiffrement fonctionne (données illisibles sur le disque brut)
strings /dev/sdb | head
# -> Que du contenu chiffré (illisible)

# 3. Test noexec : créer un script et essayer de l'exécuter
echo '#!/bin/bash' > /mnt/secure_data/test.sh
echo 'echo "Hello"' >> /mnt/secure_data/test.sh
chmod +x /mnt/secure_data/test.sh
/mnt/secure_data/test.sh
# -> Permission denied (noexec fonctionne !)
```

---

## Ressources

- [08_stockage_linux.md](../08_stockage_linux.md) - Périphériques, partitions, montage, fstab
- [09_systemes_de_fichiers.md](../09_systemes_de_fichiers.md) - ext4, mkfs, disposition Linux
- [10_securite_du_stockage.md](../10_securite_du_stockage.md) - LUKS, cryptsetup, chiffrement
- [11_sauvegarde_et_recuperation.md](../11_sauvegarde_et_recuperation.md) - Backup, rsync, tar
