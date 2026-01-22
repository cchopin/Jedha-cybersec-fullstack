# Les executables

**Duree : 45 min**

## Ce que vous allez apprendre dans ce cours

Dans la lecon precedente, nous avons explore comment fonctionnent les processus et comment les surveiller et les controler. Mais chaque processus commence par une chose : un fichier executable. Ces binaires, qu'il s'agisse de programmes compiles ou de scripts, sont le code reellement execute. Dans cette lecon, vous apprendrez :

- quels sont les differents types d'executables,
- comment le systeme identifie l'executable necessaire a partir des variables d'environnement,
- les outils courants pour l'analyse binaire de base,
- comment gerer et assurer l'authenticite des paquets.

---

## Qu'est-ce qu'un executable ?

Un **fichier executable** est un fichier informatique contenant une serie d'instructions que le systeme d'exploitation peut executer directement pour effectuer des taches ou lancer des applications. Ces fichiers sont des formes "pretes a l'execution" de programmes :
- Soit compiles depuis du code source en code machine (executables binaires)
- Soit des scripts avec des instructions pour un interpreteur (Bash, Python)

---

## Programmes binaires

Les **programmes binaires** sont des fichiers executables contenant des instructions encodees en code machine, que le processeur peut directement interpreter et executer.

Ces programmes sont le produit final de la **compilation** du code source ecrit dans des langages comme C, C++ ou Java, dans un format correspondant au systeme d'exploitation et a l'architecture materielle cible.

> **Note** : Si vous avez compile votre code pour Linux, vous ne pouvez pas l'executer directement sur Windows.

### Format ELF

La plupart des binaires incluent un **en-tete** qui identifie le type de fichier et fournit les metadonnees necessaires au systeme. Linux utilise le format **ELF** (Executable and Linkable Format).

```bash
$ file /usr/bin/ls
/usr/bin/ls: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1,
for GNU/Linux 3.7.0, stripped
```

Cette sortie indique :
- Executable compile pour architecture ARM 64-bit
- Lie dynamiquement (utilise des bibliotheques partagees)
- Pour un noyau Linux version 3.7.0 minimum

### Processus de creation

1. **Compilateur** : traduit le code source en code machine
2. **Linker (editeur de liens)** : combine votre code et les bibliotheques en un seul binaire

![Processus de compilation](assets/compilation.png)

### Bibliotheques (libraries)

Une **bibliotheque** est une collection de code precompile que les programmes peuvent utiliser pour effectuer des taches courantes (afficher un message, fonctions mathematiques).

| Type | Description |
|------|-------------|
| **Statique** | Code inclus dans le binaire, executable autonome mais plus gros |
| **Dynamique/Partagee** | Metadonnees ajoutees, bibliotheques chargees a l'execution |

**Emplacements courants des bibliotheques :**
| Chemin | Contenu |
|--------|---------|
| `/lib` et `/lib64` | Bibliotheques systeme essentielles |
| `/usr/lib` et `/usr/lib64` | Bibliotheques pour logiciels installes |
| `/usr/local/lib` | Bibliotheques compilees localement |

**Voir les bibliotheques utilisees par un binaire :**
```bash
$ ldd /usr/bin/ls
```

### Chargement et execution

- **Binaire statique** : le noyau le charge directement en memoire
- **Binaire dynamique** : le **loader** (chargeur dynamique) mappe le binaire, resout et charge les bibliotheques partagees, puis execute le programme

---

## Scripts interpretes

Les **scripts interpretes** sont des fichiers texte contenant du code source dans un langage de script (Bash, Python, Perl) pouvant etre executes directement depuis la ligne de commande.

Contrairement aux binaires, ces scripts sont lus et executes par un **interpreteur** ligne par ligne, ce qui les rend generalement plus lents que les programmes compiles.

**Execution d'un script :**
```bash
# Avec shebang dans le script
$ ./mon_script.sh

# Sans shebang, en specifiant l'interpreteur
$ python3 monscript.py
```

Le script doit avoir la permission d'execution pour que le systeme sache qu'il peut etre execute comme un programme.

---

## Decouverte des executables et environnement

### La variable PATH

Quand vous tapez `touch file.txt`, comment le systeme trouve-t-il l'executable correspondant ?

Le shell utilise la variable d'environnement **PATH** pour localiser les executables. C'est une liste de repertoires separes par des deux-points, parcourus dans l'ordre.

```bash
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

$ which touch
/usr/bin/touch
```

**Modifier le PATH :**
```bash
$ export PATH="/tmp:$PATH"
```

> **Securite - PATH hijacking** : Si un attaquant peut reecrire votre PATH et placer un binaire malveillant `ls` dans `/tmp`, ce binaire sera execute a la place du vrai `ls`.

### Autres variables d'environnement importantes

| Variable | Description | Risque |
|----------|-------------|--------|
| `LD_LIBRARY_PATH` | Repertoires pour les bibliotheques partagees | Peut etre detourne pour charger des bibliotheques malveillantes |
| `LD_PRELOAD` | Bibliotheques a charger avant toutes les autres | Permet de remplacer des fonctions a l'execution |
| `PYTHONPATH` | Repertoires pour les modules Python | Peut remplacer des modules standards |

---

## Analyse binaire

L'analyse binaire permet de comprendre le comportement d'un executable, verifier sa legitimite ou enqueter sur des compromissions. Voici quelques commandes utiles sans avoir besoin de lire le code machine.

### Identifier avec file

`file` identifie le type d'un fichier en inspectant son contenu (pas son extension).

```bash
$ file fichier.txt
fichier.txt: ASCII text

$ file /usr/bin/gettext.sh
/usr/bin/gettext.sh: POSIX shell script, ASCII text executable

$ file /usr/bin/ls
/usr/bin/ls: ELF 64-bit LSB pie executable, ARM aarch64...
```

### Afficher les dependances avec ldd

`ldd` liste les bibliotheques partagees requises par un binaire.

```bash
$ ldd /usr/bin/ping
    linux-vdso.so.1 (0x0000fa7895f8a000)
    libcap.so.2 => /lib/aarch64-linux-gnu/libcap.so.2
    libidn2.so.0 => /lib/aarch64-linux-gnu/libidn2.so.0
    libc.so.6 => /lib/aarch64-linux-gnu/libc.so.6
    /lib/ld-linux-aarch64.so.1
```

**Interpretation :**
| Bibliotheque | Description |
|--------------|-------------|
| `linux-vdso.so.1` | Objet virtuel fourni par le noyau |
| `libc.so.6` | Bibliotheque C standard |
| `libcap.so.2` | Support des capabilities |
| `/lib/ld-linux-*.so.1` | Chargeur dynamique |

> **Alerte securite** : Si un binaire systeme comme `/bin/ls` est lie a un chemin non standard (ex: `/tmp/libc.so.6`), c'est un signal d'alarme majeur.

> **Attention** : Ne jamais utiliser `ldd` sur des executables non fiables ! Utilisez plutot `objdump` ou `readelf` :
> ```bash
> $ objdump -p /usr/bin/ping | grep NEEDED
> $ readelf -d /usr/bin/ping
> ```

### Rechercher du texte avec strings

`strings` extrait le texte ASCII et UTF-8 lisible des fichiers binaires.

```bash
$ strings /usr/bin/ls | head
```

Peut reveler :
- Chemins de fichiers codes en dur
- Messages d'erreur
- Numeros de version
- URLs suspectes
- Identifiants potentiellement integres

> **Limitation** : Ne detecte que le texte en clair, pas les donnees chiffrees ou obfusquees.

### Tracer les appels avec strace et ltrace

**strace** surveille les appels systeme et signaux d'un processus :
```bash
$ strace ls
execve("/usr/bin/ls", ["ls"], 0xfffffc191010 /* 26 vars */) = 0
brk(NULL)                               = 0xb381e88fd000
...
```

**ltrace** trace les appels aux fonctions de bibliotheques :
```bash
$ ltrace ls
```

**Ce qu'on peut detecter :**
- Acces a des fichiers sensibles (`/etc/passwd`)
- Connexions reseau inattendues
- Processus enfants suspects
- Appels a `setuid` ou `chmod`

---

## Gestion des paquets avec apt

La plupart des logiciels sous Linux sont installes via des **paquets**. Les distributions basees sur Debian/Ubuntu utilisent **APT** (Advanced Package Tool).

### Commandes de base

| Commande | Description |
|----------|-------------|
| `sudo apt install paquet` | Installer un paquet |
| `sudo apt update` | Telecharger les dernieres metadonnees |
| `sudo apt upgrade` | Mettre a jour les paquets installes |
| `apt list --installed` | Lister les paquets installes |
| `apt search nom` | Rechercher un paquet |
| `apt show paquet` | Afficher les infos d'un paquet |
| `apt-cache policy paquet` | Verifier l'origine d'un paquet |

### Sources des paquets

APT recupere les paquets depuis des depots definis dans :
- `/etc/apt/sources.list` (ancien format)
- `/etc/apt/sources.list.d/` (fichiers individuels)

**Exemple de configuration :**
```
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

| Champ | Description |
|-------|-------------|
| `Types` | Type de paquet (deb) |
| `URIs` | URL du depot |
| `Suites` | Version de la distribution |
| `Components` | Categories (main, restricted, universe, multiverse) |
| `Signed-By` | Cle GPG pour la verification |

### Assurer l'authenticite des paquets

| Mecanisme | Description |
|-----------|-------------|
| **Verification GPG** | Signature numerique du fichier Release |
| **Validation des checksums** | Hashes SHA256 pour chaque paquet |
| **Configuration des depots** | Seuls les depots listes sont utilises |

**Bonnes pratiques :**
- Ne jamais ignorer un avertissement sur des paquets non authentifies
- Eviter les depots non officiels ou non fiables
- Verifier regulierement les fichiers sources

**Verifier l'integrite des fichiers installes :**
```bash
$ sudo debsums -s
```

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **ELF** | Executable and Linkable Format - Format binaire standard sous Linux |
| **Compiler** | Compilateur - Traduit le code source en code machine |
| **Linker** | Editeur de liens - Combine le code et les bibliotheques en un binaire |
| **Library** | Bibliotheque - Collection de code precompile reutilisable |
| **Static linking** | Liaison statique - Bibliotheques incluses dans le binaire |
| **Dynamic linking** | Liaison dynamique - Bibliotheques chargees a l'execution |
| **Loader** | Chargeur dynamique - Charge les bibliotheques a l'execution |
| **Shebang** | `#!` - Indique l'interpreteur pour les scripts |
| **PATH** | Variable listant les repertoires d'executables |
| **LD_LIBRARY_PATH** | Variable pour les chemins de bibliotheques |
| **LD_PRELOAD** | Variable pour precharger des bibliotheques |
| **APT** | Advanced Package Tool - Gestionnaire de paquets Debian/Ubuntu |
| **GPG** | GNU Privacy Guard - Outil de chiffrement et signature |
| **Checksum** | Somme de controle pour verifier l'integrite |
| **PATH hijacking** | Attaque exploitant une variable PATH mal configuree |

---

## Recapitulatif des commandes

### Identification de fichiers

| Commande | Description |
|----------|-------------|
| `file fichier` | Identifier le type d'un fichier |
| `which commande` | Trouver le chemin d'un executable |
| `type commande` | Afficher le type d'une commande |

### Analyse des dependances

| Commande | Description |
|----------|-------------|
| `ldd binaire` | Lister les bibliotheques partagees (attention securite!) |
| `objdump -p binaire \| grep NEEDED` | Alternative securisee a ldd |
| `readelf -d binaire` | Afficher les dependances dynamiques |

### Analyse de contenu

| Commande | Description |
|----------|-------------|
| `strings binaire` | Extraire les chaines lisibles |
| `strings -n 8 binaire` | Chaines d'au moins 8 caracteres |
| `hexdump -C binaire \| head` | Afficher en hexadecimal |

### Tracage

| Commande | Description |
|----------|-------------|
| `strace commande` | Tracer les appels systeme |
| `strace -p PID` | Tracer un processus existant |
| `strace -f commande` | Suivre les processus enfants |
| `ltrace commande` | Tracer les appels de bibliotheques |

### Variables d'environnement

| Commande | Description |
|----------|-------------|
| `echo $PATH` | Afficher le PATH |
| `export PATH="/chemin:$PATH"` | Ajouter au PATH |
| `printenv` | Afficher toutes les variables |

### Gestion des paquets (apt)

| Commande | Description |
|----------|-------------|
| `sudo apt update` | Mettre a jour les metadonnees |
| `sudo apt upgrade` | Mettre a jour les paquets |
| `sudo apt install paquet` | Installer un paquet |
| `sudo apt remove paquet` | Supprimer un paquet |
| `apt search terme` | Rechercher un paquet |
| `apt show paquet` | Informations sur un paquet |
| `apt list --installed` | Lister les paquets installes |
| `apt-cache policy paquet` | Verifier l'origine |
| `sudo debsums -s` | Verifier l'integrite des fichiers |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/apt/sources.list` | Sources des paquets (ancien) |
| `/etc/apt/sources.list.d/` | Sources des paquets (fichiers) |
| `/lib`, `/usr/lib` | Bibliotheques systeme |
| `/usr/local/lib` | Bibliotheques locales |

---

## Ressources

- The 101 of ELF files on Linux - Michael Boelen
- What is the LD_PRELOAD Trick? - baeldung
- Manage Shared Libraries - borosan
- Attacks against GPG signed APT repositories - packagecloud
