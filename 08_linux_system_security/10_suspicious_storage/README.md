# Suspicious Storage - Write-up

## Contexte

Retour chez RoboYak Industries où AIDE (Advanced Intrusion Detection Environment) a déclenché une alerte. L'objectif est d'analyser cette alerte pour comprendre ce qui se passe sur le système.

## Qu'est-ce qu'AIDE ?

**AIDE** (Advanced Intrusion Detection Environment) est un système de détection d'intrusion basé sur l'hôte (HIDS) pour Linux :

- Crée une base de données de référence des fichiers système (checksums, permissions, timestamps)
- Compare périodiquement l'état actuel avec cette référence
- Génère des alertes si des fichiers ont été modifiés, ajoutés ou supprimés

---

## Étape 1 : Analyse du rapport AIDE

Lancement de la vérification AIDE :

```bash
sudo aide --check --config=/etc/aide/aide.conf
```

### Fichiers suspects identifiés

Le rapport révèle plusieurs éléments critiques dans la section "Added entries" :

| Fichier | Suspicion |
|---------|-----------|
| `/home/jedha/.cache/backup.img` | Fichier image caché dans le cache utilisateur |
| `/usr/local/bin/backup.sh` | Nouveau script de backup |
| `/usr/sbin/sshd` | Installation du serveur SSH |

Les binaires SSH (`/usr/bin/ssh`, `/usr/bin/scp`, etc.) ont également été modifiés (nouveaux hashs MD5).

---

## Étape 2 : Analyse du script malveillant

```bash
cat /usr/local/bin/backup.sh
```

**Contenu :**
```bash
#!/bin/bash
cp /etc/shadow /mnt/.backupfiles/
cp -r /home/jedha/Documents /mnt/.backupfiles/
```

**Analyse :** Ce script exfiltre :
- `/etc/shadow` → Les hashs des mots de passe de tous les utilisateurs
- `/home/jedha/Documents` → Les documents personnels de l'utilisateur

Les données sont copiées vers un répertoire caché `/mnt/.backupfiles/` (le point le rend invisible avec `ls` standard).

---

## Étape 3 : Analyse du fichier backup.img

```bash
file /home/jedha/.cache/backup.img
```

**Résultat :**
```
/home/jedha/.cache/backup.img: LUKS encrypted file, ver 2 [...]
```

C'est un **conteneur LUKS chiffré** de 512 Mo ! L'attaquant stocke les données volées dans un conteneur chiffré pour éviter la détection.

```bash
cryptsetup luksDump /home/jedha/.cache/backup.img
```

Révèle un conteneur LUKS2 avec chiffrement AES-XTS-PLAIN64.

---

## Étape 4 : Recherche du mot de passe

Analyse des logs système :

```bash
grep -r "backup" /var/log/ 2>/dev/null | head -20
```

Les logs révèlent l'existence d'un service `systemd-cryptsetup@backupfiles.service`, indiquant une configuration automatique.

Vérification de la configuration crypttab :

```bash
cat /etc/crypttab
```

**Résultat :**
```
backupfiles     /home/jedha/.cache/backup.img   /root/test.txt  luks,noauto
```

Le fichier de clé est `/root/test.txt` :

```bash
cat /root/test.txt
```

**Mot de passe : `1234`**

---

## Étape 5 : Accès aux données volées

Ouverture du conteneur LUKS :

```bash
echo "1234" | cryptsetup luksOpen /home/jedha/.cache/backup.img backupfiles
mkdir -p /mnt/backup_decrypted
mount /dev/mapper/backupfiles /mnt/backup_decrypted
ls -la /mnt/backup_decrypted/
```

**Contenu découvert :**
```
drwxr-xr-x 4 root root  4096 May 26  2025 .
drwxr-xr-x 4 root root  4096 Jan 23 16:57 ..
drwxr-xr-x 2 root root  4096 May 26  2025 Documents
drwx------ 2 root root 16384 May 26  2025 lost+found
-rw-r----- 1 root root  1381 May 26  2025 shadow
```

Les données volées :
- `shadow` → Copie du fichier `/etc/shadow`
- `Documents/` → Copie des documents de l'utilisateur

---

## Étape 6 : Identification du mécanisme de persistance

Recherche du trigger :

```bash
grep -r "backup.sh" /etc/ 2>/dev/null
systemctl list-unit-files | grep -i backup
ls -la /etc/systemd/system/ | grep -i backup
```

**Fichiers de persistance découverts :**

### backup.timer (le trigger)

```bash
cat /etc/systemd/system/backup.timer
```

```ini
[Unit]
Description=Backup Data

[Timer]
OnBootSec=1min
OnUnitActiveSec=1h
Unit=backup.service

[Install]
WantedBy=timers.target
```

### backup.service

```bash
cat /etc/systemd/system/backup.service
```

```ini
[Unit]
Description=Backup Data

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup.sh
ExecStartPre=/usr/bin/systemctl start systemd-cryptsetup@backupfiles.service
ExecStartPre=/usr/bin/systemctl start mnt-.backupfiles.mount
ExecStopPost=/usr/bin/umount /mnt/.backupfiles
ExecStopPost=/usr/bin/systemctl stop systemd-cryptsetup@backupfiles.service
```

---

## Résumé de l'attaque

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHAÎNE D'ATTAQUE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  backup.timer (TRIGGER)                                         │
│       │                                                         │
│       ├── OnBootSec=1min     → Exécution 1 min après boot       │
│       ├── OnUnitActiveSec=1h → Répétition toutes les heures     │
│       │                                                         │
│       └── Lance: backup.service                                 │
│                    │                                            │
│                    ├── 1. Monte le conteneur LUKS               │
│                    ├── 2. Monte /mnt/.backupfiles               │
│                    ├── 3. Exécute backup.sh                     │
│                    │       ├── Copie /etc/shadow                │
│                    │       └── Copie /home/jedha/Documents      │
│                    ├── 4. Démonte /mnt/.backupfiles             │
│                    └── 5. Ferme le conteneur LUKS               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Tableau récapitulatif

| Élément | Chemin | Description |
|---------|--------|-------------|
| **Script malveillant** | `/usr/local/bin/backup.sh` | Copie shadow + Documents |
| **Conteneur chiffré** | `/home/jedha/.cache/backup.img` | LUKS 512 Mo |
| **Mot de passe** | `/root/test.txt` | `1234` |
| **Configuration LUKS** | `/etc/crypttab` | Montage automatique |
| **Timer (trigger)** | `/etc/systemd/system/backup.timer` | Déclenche toutes les heures |
| **Service** | `/etc/systemd/system/backup.service` | Orchestre l'exfiltration |
| **Point de montage** | `/mnt/.backupfiles/` | Répertoire caché |
| **Données volées** | Dans le conteneur | shadow, Documents |

---

## Réponses aux questions

1. **Quel outil a détecté l'intrusion ?** → AIDE (Advanced Intrusion Detection Environment)

2. **Quel est le nom du fichier qui déclenche le script ?** → `backup.timer`

3. **Quelles données sont exfiltrées ?** → `/etc/shadow` et `/home/jedha/Documents`

4. **Quel type de chiffrement est utilisé ?** → LUKS2 avec AES-XTS-PLAIN64

5. **Quel est le mot de passe du conteneur ?** → `1234`

---

## Mesures de remédiation

```bash
# 1. Arrêter et désactiver le timer
systemctl stop backup.timer
systemctl disable backup.timer

# 2. Supprimer les fichiers malveillants
rm /etc/systemd/system/backup.timer
rm /etc/systemd/system/backup.service
rm /etc/systemd/system/mnt-.backupfiles.mount
rm /usr/local/bin/backup.sh
rm /root/test.txt

# 3. Supprimer l'entrée crypttab
sed -i '/backupfiles/d' /etc/crypttab

# 4. Fermer et supprimer le conteneur
umount /mnt/backup_decrypted
cryptsetup luksClose backupfiles
rm /home/jedha/.cache/backup.img

# 5. Recharger systemd
systemctl daemon-reload

# 6. Changer tous les mots de passe (shadow compromis !)
passwd root
passwd jedha
# ... pour tous les utilisateurs

# 7. Mettre à jour la base AIDE
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 8. Investiguer la source de l'intrusion initiale
# Vérifier les logs SSH, les comptes créés, etc.
```
