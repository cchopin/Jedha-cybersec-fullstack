# Le systeme Linux

**Duree : 30 min**

## Ce que vous allez apprendre dans ce cours

Commencons par presenter le systeme d'exploitation Linux : son histoire, ses composants principaux et comment il organise et interagit avec les ressources. Dans cette lecon, vous allez :

- enfin connaitre la difference entre Unix et Linux,
- identifier les composants principaux du systeme Linux,
- choisir votre distribution preferee parmi les 600 disponibles,
- comprendre ce qui se passe quand vous executez une commande shell.

---

## Introduction a Linux

Linux est un systeme d'exploitation open source cree en 1991 par Linus Torvalds. Il est compose du noyau Linux (kernel), qui est le composant central responsable de la gestion des ressources materielles, et de divers autres composants logiciels qui en font un systeme d'exploitation complet.

Generalement, vous rencontrerez Linux sous forme de **distribution** : en soi, le systeme Linux fournit un environnement minimal et manque de fonctionnalites conviviales, donc ce qui est utilise est en realite une distribution. Une distribution Linux (souvent abregee "distro") est une version packagee du systeme Linux qui inclut :

- le noyau Linux,
- un systeme de gestion de paquets,
- des logiciels supplementaires tels que des environnements de bureau, des navigateurs web...

Voici quelques distributions Linux courantes :

| Distribution | Description |
|--------------|-------------|
| **Debian** | Une des premieres distributions, avec un fort engagement envers les principes du logiciel libre et une gestion de projet democratique |
| **Ubuntu** | Derivee de Debian, une des distributions les plus populaires grace a son interface conviviale et son support communautaire |
| **Kali Linux** | Basee sur Debian, concue pour les tests d'intrusion, le hacking ethique et l'investigation numerique |
| **Alpine Linux** | Distribution legere proche de l'experience Linux de base, souvent utilisee pour la conteneurisation grace a sa taille minimale |

La flexibilite et l'evolutivite de Linux en font un systeme tres polyvalent : vous pouvez l'installer sur un ordinateur personnel comme Windows, mais aussi sur un serveur web, une TV connectee, un routeur, un telephone mobile (Android est base sur le noyau Linux) ou un supercalculateur.

### Unix, GNU et Linux

Vous avez peut-etre entendu que Linux est un systeme de type Unix, ou meme vu Linux appele GNU/Linux. Voici une breve lecon d'histoire :

- **Unix** : systeme d'exploitation developpe en 1969, servant de fondation a de nombreux systemes modernes comme Linux et macOS. C'est le premier OS base sur le langage C. C'est un systeme proprietaire.

- **Projet GNU** : initie en 1983 par Richard Stallman pour creer un systeme d'exploitation libre de type Unix. Ce projet a produit des outils critiques comme le compilateur GCC et Bash, mais manquait de composants bas niveau.

- **Linux** : le noyau Linux a comble ce vide, et ce que nous appelons Linux est en fait une combinaison des outils GNU et du noyau Linux pour former le systeme GNU/Linux.

---

## De quoi est compose Linux ?

Du plus bas niveau aux composants de plus haut niveau, voici les elements d'un systeme Linux :

![Composants de Linux](assets/Linux_components.png)

| Composant | Description |
|-----------|-------------|
| **Bootloader** | Premier logiciel qui s'execute au demarrage, son role principal est de charger et demarrer le noyau. Exemple : GRUB |
| **Kernel (noyau)** | Coeur du systeme, gere les ressources materielles (CPU, memoire, peripheriques). Fonctions cles : gestion des processus, gestion memoire, pilotes de peripheriques, operations sur les fichiers, reseau |
| **Systeme d'init** | Premier processus demarre par le noyau et dernier a se terminer. Gere tous les autres processus. Les systemes modernes utilisent **systemd** |
| **Daemons** | Processus en arriere-plan qui executent des taches specifiques (services reseau, journalisation...) |
| **Serveur graphique** | Gere les elements graphiques et les affiche a l'ecran. Exemple : X Window System (X11) |
| **Environnement de bureau** | Fournit une interface utilisateur complete (bureau, barre des taches, icones). Exemples : GNOME, KDE, XFCE |
| **Applications** | Logiciels pour les utilisateurs (editeurs de texte, navigateurs, lecteurs video...) |

### Espace utilisateur vs espace noyau

Les parties de Linux "au-dessus" du noyau (environnement de bureau, applications) sont appelees **espace utilisateur** (userspace ou userland). Les applications dans l'espace utilisateur ne peuvent pas acceder directement au materiel ou effectuer des operations privilegiees. Elles communiquent avec le noyau via des **appels systeme** (syscalls).

Cette division offre plusieurs avantages :

- **Stabilite** : les plantages des programmes utilisateur n'affectent pas le systeme entier
- **Securite** : les processus utilisateur ont des permissions restreintes
- **Flexibilite** : les utilisateurs peuvent executer diverses applications sans interference

### Le cas de `touch file.txt`

Voici ce qui se passe quand vous executez `touch file.txt` :

![Diagramme touch file.txt](assets/touch_file.png)

1. Le shell cherche le binaire `touch` via la variable `$PATH` (ex: `/usr/bin/touch`)
2. Le processus shell utilise l'appel systeme `fork()` pour creer un processus enfant
3. Le noyau verifie si l'utilisateur a les permissions d'execution et de lecture sur ce binaire
4. Si tout est correct, le noyau cree le processus
5. Le processus `touch` s'execute dans l'espace utilisateur, verifie si `file.txt` existe et utilise le syscall `open()` pour le creer
6. Le noyau resout le chemin de `file.txt` et utilise le VFS (Virtual Filesystem Switch) pour selectionner le pilote de systeme de fichiers approprie
7. Le noyau retourne un descripteur de fichier au processus `touch`
8. Le processus `touch` se termine et on revient au processus shell

**Concepts cles a retenir :**
- Les **permissions** sont capitales pour securiser votre systeme
- Les **processus** executent les taches dans le systeme
- Les **systemes de fichiers** et le stockage sont cruciaux pour l'investigation de securite
- Le **noyau** est au centre de tout

---

## Tout est un fichier

Le concept "tout est un fichier" dans Linux est un principe fondamental herite d'Unix. Cela signifie que toutes les ressources systeme (fichiers reguliers, repertoires, peripheriques, processus, sockets) sont representees comme des fichiers dans le systeme de fichiers.

Cette abstraction simplifie l'interaction avec les composants systeme en fournissant une maniere unifiee d'y acceder : ouvrir, lire, ecrire et fermer.

Exemples :

| Chemin | Description |
|--------|-------------|
| `/proc/` | Contient un repertoire par processus en cours, avec des fichiers comme `status` (metadonnees) ou `exe` (lien vers le binaire) |
| `/dev/` | Contient les fichiers de peripheriques, comme `/dev/sda` pour un disque de stockage |
| `/run/` | Contient souvent les sockets reseau |

### Demonstration

```bash
# Afficher le pseudo-terminal utilise
$ tty
/dev/pts/0

# Depuis un autre terminal (/dev/pts/1), envoyer un message au premier
$ echo "hello" > /dev/pts/0
```

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **OS** | Operating System - Systeme d'exploitation |
| **Kernel** | Noyau - Composant central du systeme qui gere le materiel |
| **Distro** | Distribution - Version packagee de Linux |
| **GNU** | GNU's Not Unix - Projet de systeme libre initie par Richard Stallman |
| **GRUB** | GRand Unified Bootloader - Chargeur de demarrage populaire |
| **Daemon** | Processus en arriere-plan executant des taches specifiques |
| **Syscall** | System Call - Appel systeme, interface entre espace utilisateur et noyau |
| **VFS** | Virtual Filesystem Switch - Couche d'abstraction des systemes de fichiers |
| **PID** | Process ID - Identifiant unique d'un processus |
| **Userspace/Userland** | Espace utilisateur - Partie du systeme au-dessus du noyau |
| **X11/X Window** | Serveur graphique pour Linux |
| **GNOME/KDE/XFCE** | Environnements de bureau populaires |

---

## Recapitulatif des commandes

| Commande | Description |
|----------|-------------|
| `tty` | Affiche le pseudo-terminal actuel |
| `echo "texte" > /dev/pts/X` | Envoie du texte vers un autre terminal |

---

## Ressources

- Linux Explained - zenarmor.com
- Syscalls - Wizard Zines
- Behind the Scenes: What happens when you execute a command in the shell? - Sergio Pietri
- UNIX and Linux System Administration Handbook - Evi et al.
