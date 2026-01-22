# Utilisateurs et permissions

**Duree : 50 min**

## Ce que vous allez apprendre dans ce cours

Comprendre les utilisateurs et les groupes sous Linux est crucial car ils constituent le fondement du modele de securite et de permissions du systeme. Ils controlent qui peut acceder aux fichiers, executer des commandes et utiliser les ressources systeme. Dans cette lecon, vous allez :

- voir les concepts d'utilisateur et de groupe,
- revoir les principales commandes de gestion des utilisateurs,
- decouvrir le composant PAM,
- (re)apprendre les permissions de fichiers sous Linux.

---

## Utilisateurs et groupes

Il existe trois types d'utilisateurs sous Linux :

| Type | Description |
|------|-------------|
| **Utilisateurs reguliers** | Acces limite aux ressources, necessitent des privileges eleves (via sudo) pour les taches administratives |
| **Utilisateurs systeme** | Crees pour executer des services specifiques (ex: postgres pour PostgreSQL). Ces comptes n'ont generalement pas de capacite de connexion |
| **Utilisateur root** | Superutilisateur avec acces illimite au systeme. Peut modifier n'importe quel fichier, installer des logiciels et gerer tous les utilisateurs |

Les utilisateurs sont organises en **groupes** : collections d'utilisateurs permettant aux administrateurs de gerer les permissions collectivement plutot qu'individuellement.

### Fichiers de gestion des utilisateurs

| Fichier | Contenu |
|---------|---------|
| `/etc/passwd` | Informations utilisateur : nom, UID, GID, repertoire home, shell |
| `/etc/shadow` | Mots de passe haches et informations de connexion |
| `/etc/group` | Liste des groupes avec leurs membres |

**Structure d'une entree `/etc/passwd` :**

![Structure de /etc/passwd](assets/etc_passwd.png)

**Structure d'une entree `/etc/shadow` :**

![Structure de /etc/shadow](assets/CYBFS-M08D01-etc-shadow.png)

**Structure d'une entree `/etc/group` :**

![Structure de /etc/group](assets/etc_group.png)

### UID et GID

- Chaque utilisateur a un **UID** (User ID) unique
- UID 1-500 : generalement reserves aux utilisateurs systeme
- UID >= 1000 : utilisateurs reguliers (sur Ubuntu)
- Quand vous creez un utilisateur, un groupe du meme nom est cree (groupe primaire)
- Les autres groupes sont des **groupes supplementaires**

### Le groupe sudoers

Le groupe **sudo** (ou **wheel** sur CentOS/RedHat) est un groupe special qui accorde a ses membres la capacite d'executer des commandes avec des privileges eleves via la commande `sudo`.

Le fichier `/etc/sudoers` definit quels utilisateurs ou groupes peuvent executer des commandes en tant qu'autres utilisateurs (generalement root). Ce fichier doit etre edite avec `visudo`.

Exemple de configuration :
```
# Specification des privileges utilisateur
root ALL=(ALL:ALL) ALL

# Permettre aux membres du groupe sudo d'executer toute commande
%sudo ALL=(ALL:ALL) ALL

# Permettre aux membres du groupe admin
%admin ALL=(ALL) ALL
```

Pour voir les dernieres commandes sudo :
```bash
$ journalctl -e | grep sudo
```

---

## Commandes de gestion des utilisateurs

| Commande | Description |
|----------|-------------|
| `useradd` ou `adduser` | Creer un nouveau compte |
| `usermod` | Modifier les attributs d'un utilisateur (groupes, etc.) |
| `userdel` | Supprimer un compte |
| `groupadd` | Creer un groupe |
| `groupmod` | Modifier un groupe |
| `groupdel` | Supprimer un groupe |
| `groups utilisateur` | Voir les groupes d'un utilisateur |
| `id utilisateur` | Afficher UID, GID et groupes |
| `su` | Changer d'utilisateur |

---

## Authentification utilisateur

### PAM : gestion centralisee de l'authentification

PAM (Pluggable Authentication Modules) est une bibliotheque qui valide les identifiants utilisateur/mot de passe. Elle verifie contre le stockage securise des mots de passe (`/etc/shadow`).

Lors d'une connexion, voici ce qui se passe :

1. L'application de connexion declenche la pile PAM configuree pour ce service (depuis `/etc/pam.d/login`, `/etc/pam.d/su`, etc.)
2. PAM lit le fichier de configuration depuis `/etc/pam.d`
3. PAM execute les modules suivants :
   - **account** : valide que le compte est en bon etat (expirations, limites)
   - **authentication** : verifie l'identite (demande de mot de passe)
   - **password** : actions liees aux changements de mot de passe
   - **session** : taches de debut et fin de session (logs, nettoyage)
4. Si la connexion reussit, l'application utilise `setuid()` pour passer a l'UID de l'utilisateur

### Configuration PAM

Avec PAM, vous pouvez :

**Appliquer des politiques de mot de passe avec `pam_pwquality.so` :**
```
password requisite pam_pwquality.so retry=3 minlen=12
```

**Limiter les tentatives de connexion avec `pam_tally2.so` :**
```
auth required pam_tally.so onerr=fail deny=3 no_magic_root
```

**Activer l'authentification a deux facteurs** avec des modules comme `pam_google_authenticator.so` ou `pam_oath.so`.

---

## Proprietaires et permissions de fichiers

### Visualiser les permissions

```bash
$ touch fichier.txt
$ ls -l
-rw-rw-r-- 1 jedha jedha 0 Apr 13 12:29 fichier.txt
```

![Explication de la sortie ls -l](assets/permissions.png)

### Les permissions RWX

Les permissions `rw-rw-r--` representent trois ensembles pour :
- **user (u)** : le proprietaire du fichier
- **group (g)** : le groupe proprietaire
- **others (o)** : tous les autres utilisateurs

Ce trio est parfois appele "UGO". Chacun peut avoir les permissions :

| Permission | Signification |
|------------|---------------|
| `r` (read) | Lecture |
| `w` (write) | Ecriture |
| `x` (execute) | Execution |

### Proprietaire et groupe proprietaire

Dans l'exemple `jedha jedha`, le premier est l'utilisateur proprietaire, le second est le groupe proprietaire.

### Comment le noyau verifie les permissions

1. Chaque processus s'execute sous un UID et GID, herites de l'utilisateur qui l'execute
2. Quand un processus accede a un fichier, le noyau compare l'UID/GID du processus avec les metadonnees du fichier
3. Logique appliquee :
   - Si UID processus == UID fichier → utiliser les bits utilisateur
   - Sinon si GID processus == GID fichier → utiliser les bits groupe
   - Sinon → utiliser les bits autres
4. Si aucun bit ne correspond a l'action demandee, le noyau retourne une erreur (EACCES)

---

## Commandes de gestion des permissions

### chown - Changer le proprietaire

```bash
# Changer le proprietaire
$ sudo chown john fichier.txt

# Changer le groupe proprietaire
$ sudo chown :developers fichier.txt

# Changer les deux
$ sudo chown john:developers fichier.txt
```

### chmod - Changer les permissions

#### Mode symbolique

Trois composants :
1. Qui : `u` (user), `g` (group), `o` (others), `a` (all)
2. Action : `+` (ajouter), `-` (retirer), `=` (definir)
3. Permission : `r`, `w`, `x`

```bash
# Ajouter execution au proprietaire, retirer ecriture au groupe, lecture seule aux autres
$ chmod u+x,g-w,o=r fichier
```

#### Mode numerique

Chaque chiffre est une somme des bits de permission :

| Permission | Valeur |
|------------|--------|
| `---` | 0 |
| `--x` | 1 |
| `-w-` | 2 |
| `-wx` | 3 |
| `r--` | 4 |
| `r-x` | 5 |
| `rw-` | 6 |
| `rwx` | 7 |

```bash
# 754 = rwx (7) pour user, r-x (5) pour group, r-- (4) pour others
$ chmod 754 fichier.txt
```

---

## SUID et SGID

### SUID (Set User ID)

Quand le bit SUID est defini sur un executable, le processus s'execute avec les privileges du proprietaire du fichier, pas de l'utilisateur qui l'execute.

Exemple : `/usr/bin/sudo`
```bash
$ ls -l /usr/bin/sudo
-rwsr-xr-x 1 root root 335120 Apr 8 2024 /usr/bin/sudo
```

Le `s` au lieu de `x` indique le bit SUID. Grace a cela, `sudo` s'execute avec l'UID effectif 0 (root).

### SGID (Set Group ID)

- Sur les executables : le processus s'execute avec les permissions du groupe du fichier
- Sur les repertoires : les nouveaux fichiers heritent du groupe du repertoire

### Le sticky bit

Permission speciale utilisee principalement sur les repertoires partages. Quand il est defini, seul le proprietaire du fichier (ou root) peut supprimer ou renommer les fichiers.

Exemple : `/tmp`
```
drwxrwxrwt
```

Le `t` a la fin indique le sticky bit.

---

## ACLs : permissions a grain fin

Les listes de controle d'acces (ACL) etendent le modele de permissions de base en permettant a plusieurs utilisateurs et groupes d'avoir des droits d'acces personnalises sur un seul fichier.

```bash
# Voir les ACLs
$ getfacl fichier.txt

# Donner l'acces en lecture a john
$ sudo setfacl -m u:john:r fichier.txt
```

---

## Les permissions de fichiers ne font pas tout

Les permissions de fichiers sont essentielles mais ne couvrent pas toutes les actions :

| Domaine | Mecanisme |
|---------|-----------|
| **Processus** | Envoyer des signaux, changer les priorites, utiliser ptrace |
| **Reseau** | Lier aux ports privilegies (<1024), ouvrir des sockets raw |
| **Capabilities** | Les capabilities Linux divisent les privileges root en unites discretes |
| **Modules de securite** | SELinux et AppArmor appliquent des politiques obligatoires |
| **Operations systeme** | Monter des systemes de fichiers, charger des modules noyau |

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **UID** | User ID - Identifiant unique de l'utilisateur |
| **GID** | Group ID - Identifiant unique du groupe |
| **PAM** | Pluggable Authentication Modules - Modules d'authentification enfichables |
| **SUID** | Set User ID - Bit special permettant l'execution avec les privileges du proprietaire |
| **SGID** | Set Group ID - Bit special pour les privileges de groupe |
| **ACL** | Access Control List - Liste de controle d'acces |
| **UGO** | User, Group, Others - Les trois categories de permissions |
| **Sticky bit** | Bit special empechant la suppression de fichiers par des non-proprietaires |
| **Root** | Superutilisateur avec tous les privileges (UID 0) |
| **Sudoers** | Fichier definissant qui peut utiliser sudo et comment |

---

## Recapitulatif des commandes

### Gestion des utilisateurs

| Commande | Description |
|----------|-------------|
| `useradd nom` | Creer un utilisateur |
| `adduser nom` | Creer un utilisateur (interactif) |
| `usermod -aG groupe user` | Ajouter un utilisateur a un groupe |
| `userdel nom` | Supprimer un utilisateur |
| `passwd nom` | Changer le mot de passe |
| `su - utilisateur` | Changer d'utilisateur |
| `sudo commande` | Executer en tant que root |
| `id` | Afficher UID, GID et groupes |
| `groups` | Afficher les groupes |
| `whoami` | Afficher l'utilisateur courant |

### Gestion des groupes

| Commande | Description |
|----------|-------------|
| `groupadd nom` | Creer un groupe |
| `groupmod -n nouveau ancien` | Renommer un groupe |
| `groupdel nom` | Supprimer un groupe |

### Permissions

| Commande | Description |
|----------|-------------|
| `ls -l` | Afficher les permissions |
| `chmod 755 fichier` | Changer les permissions (numerique) |
| `chmod u+x fichier` | Ajouter execution au proprietaire |
| `chown user:group fichier` | Changer proprietaire et groupe |
| `chown user fichier` | Changer le proprietaire |
| `chown :group fichier` | Changer le groupe |

### ACLs

| Commande | Description |
|----------|-------------|
| `getfacl fichier` | Voir les ACLs d'un fichier |
| `setfacl -m u:user:rwx fichier` | Definir une ACL pour un utilisateur |
| `setfacl -m g:group:rx fichier` | Definir une ACL pour un groupe |
| `setfacl -x u:user fichier` | Supprimer une ACL |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/passwd` | Informations des utilisateurs |
| `/etc/shadow` | Mots de passe haches |
| `/etc/group` | Informations des groupes |
| `/etc/sudoers` | Configuration sudo |
| `/etc/pam.d/` | Configuration PAM |

---

## Ressources

- Working With Users and Groups - Engineer Man (Youtube)
- How to interpret Linux user info
- Linux PAM Tutorial - Linux Code
- Check Linux file permissions with ls - rackspace.com
