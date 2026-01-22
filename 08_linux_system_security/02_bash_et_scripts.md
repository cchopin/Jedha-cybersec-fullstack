# Bash et scripts

**Duree : 45 min**

## Ce que vous allez apprendre dans ce cours

Dans cette lecon, nous allons revoir les commandes bash et les scripts. Vous allez decouvrir :

- comment rediriger la sortie ou l'entree de vos commandes,
- comment compresser des fichiers,
- ce que sont les liens de fichiers et comment les gerer,
- et bien d'autres astuces sur bash.

---

## Commandes Bash

Vous devriez deja etre familier avec les commandes bash de base. Voici un rappel des commandes essentielles :

![Jeu des commandes bash](assets/flip_game.png)

Les commandes de base a connaitre : `pwd`, `cd`, `touch`, `cp`, `ls`, `echo`, `mkdir`, `cat`.

### Redirections d'entree et de sortie

Vous connaissez deja comment rediriger la sortie de vos commandes avec `>` et `|`. Voici d'autres exemples de redirections.

#### `2>` - Rediriger la sortie d'erreur standard (stderr)

Vous pouvez utiliser `2>` et `2>>` pour rediriger ou ajouter les messages d'erreur vers un fichier specifique :

```bash
$ ls fichierinexistant 2> error.log
```

Cette redirection est souvent utilisee par les attaquants pour masquer les erreurs :

```bash
$ ./exploit.sh 2>/dev/null
```

#### `&>` - Rediriger stdout et stderr

Vous pouvez rediriger a la fois la sortie standard et la sortie d'erreur avec `&>` :

```bash
$ ./script.sh &> output.log
```

Equivalent a :

```bash
$ ./script.sh > output.log 2>&1
```

#### `<` - Rediriger l'entree

Plusieurs facons de rediriger l'entree vers une commande :

```bash
# Depuis un fichier
$ sort < noms.txt

# Here document (<<) - plusieurs lignes
$ sort <<EOF
Nimona
Alice
John
Bob
EOF

# Here string (<<<) - une seule ligne
$ grep waldo <<< "Ou est waldo dans cette phrase?"
```

**Resume des redirections d'entree :**
| Symbole | Usage |
|---------|-------|
| `<` | Depuis un fichier |
| `<<` | Bloc de plusieurs lignes (here document) |
| `<<<` | Une seule chaine (here string) |

---

### Expressions regulieres pour grep et sed

Les expressions regulieres (regex) sont des motifs utilises pour faire correspondre des combinaisons de caracteres dans du texte.

| Symbole | Signification |
|---------|---------------|
| `.` | Correspond a n'importe quel caractere unique |
| `*` | Correspond a zero ou plusieurs du caractere precedent |
| `^` | Correspond au debut d'une ligne |
| `$` | Correspond a la fin d'une ligne |
| `[abc]` | Correspond a un des caracteres a, b ou c |
| `[^abc]` | Correspond a tout caractere sauf a, b ou c |

Exemple : le motif `^[A-Z][a-z]*$` recherche toute ligne contenant uniquement une majuscule suivie de minuscules (comme un prenom).

```bash
# Supprimer toutes les lignes commencant par # (commentaires)
$ sed '/^#/d' script.py
```

> **Attention** : `*` en bash (wildcard) et `*` en regex ont des significations differentes !
> - `grep 'http' *` : cherche "http" dans tous les fichiers du repertoire
> - `grep 'http.*pdf' log.txt` : cherche une URL commencant par http et finissant par pdf

---

### Archiver et compresser des fichiers

#### tar - Archiver des fichiers

`tar` combine plusieurs fichiers en une seule archive sans les compresser :

```bash
# Creer une archive
$ tar -cvf archive.tar fichier1.txt fichier2.txt

# Extraire une archive
$ tar -xvf archive.tar
```

#### gzip - Compresser des fichiers

`gzip` compresse un seul fichier avec l'algorithme Deflate :

```bash
# Compresser
$ gzip archive.tar
# Resultat : archive.tar.gz

# Decompresser
$ gzip -d archive.tar.gz

# Decompresser et extraire en une commande
$ tar -xvzf archive.tar.gz
```

#### bzip2 - Compression plus elevee

`bzip2` compresse plus efficacement que gzip, mais est plus lent :

```bash
# Compresser
$ bzip2 archive.tar

# Decompresser
$ bunzip2 archive.tar.bz2
```

---

### Gerer les liens de fichiers

Les liens permettent de referencer des fichiers a plusieurs endroits sans dupliquer leur contenu.

#### Lien physique (hard link)

Cree un autre nom pour le meme contenu de fichier. Supprimer l'original ne supprime pas les donnees tant qu'un lien physique existe :

```bash
$ ln rapport.txt rapport_copie.txt
```

**Utilisation** : organiser les memes fichiers de differentes manieres sans duplication.

#### Lien symbolique (symlink)

Pointe vers un autre fichier ou repertoire. Si la cible est supprimee, le symlink est casse :

```bash
$ ln -s /var/log/syslog dernier-log
```

**Utilisation typique** : bibliotheques partagees en Linux :

```
lrwxrwxrwx. 1 root root 16 Dec 2 15:24 /usr/lib64/libcurl.so -> libcurl.so.4.2.0
```

---

### Acceder a la documentation systeme

```bash
# Ouvrir la page de manuel d'une commande
$ man ls
```

---

### head et tail

Pour manipuler de gros fichiers, utilisez `head` (debut) et `tail` (fin) :

```bash
# Afficher les 5 dernieres lignes et suivre les nouvelles
$ tail -n 5 -f /var/log/syslog
```

---

## Variables d'environnement

Les variables d'environnement sont des valeurs dynamiques qui affectent le comportement de votre shell et du systeme.

```bash
# Voir toutes les variables
$ printenv

# Voir une variable specifique
$ echo $PATH

# Definir une variable temporaire
$ MY_VAR="Hello"
$ echo $MY_VAR

# Exporter pour les sous-processus
$ export MY_VAR
```

**Variables courantes :**

| Variable | Description |
|----------|-------------|
| `PATH` | Liste des repertoires ou le shell cherche les executables |
| `HOME` | Pointe vers votre repertoire personnel |
| `USER` | Affiche votre nom d'utilisateur |

> **Securite** : Un `PATH` mal configure peut permettre a un attaquant d'executer des binaires malveillants. Des variables comme `LD_PRELOAD` ou des secrets exposes (cles API, mots de passe) peuvent etre exploites.

---

## Scripts Bash

### Shebang

La ligne au debut d'un script indiquant quel interpreteur utiliser :

```bash
#!/usr/bin/env bash
```

Utiliser `env` est plus portable car il recherche bash dans le `PATH` de l'utilisateur.

Pour Python :
```bash
#!/usr/bin/env python3
```

### La commande set

`set` peut modifier les attributs du shell pour rendre vos scripts plus robustes :

| Option | Effet |
|--------|-------|
| `set -e` | Quitte immediatement si une commande echoue |
| `set -x` | Affiche toutes les commandes executees (debug) |
| `set -u` | Traite les variables non definies comme des erreurs |
| `set -o pipefail` | Fait echouer le pipeline si une commande echoue |

```bash
#!/usr/bin/env bash
set -e
```

### Exit et codes de sortie

Chaque commande retourne un code de sortie : `0` = succes, autre = echec.

```bash
# Verifier le code de la derniere commande
$ ls /chemin/inexistant
$ echo $?
2

# Quitter un script avec un code specifique
exit 1
```

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **Bash** | Bourne Again SHell - Interpreteur de commandes par defaut sur la plupart des systemes Linux |
| **stdin** | Standard Input - Entree standard (fichier descripteur 0) |
| **stdout** | Standard Output - Sortie standard (fichier descripteur 1) |
| **stderr** | Standard Error - Sortie d'erreur standard (fichier descripteur 2) |
| **Pipe** | Tube (`\|`) - Connecte la sortie d'une commande a l'entree d'une autre |
| **Regex** | Regular Expression - Expression reguliere, motif de recherche |
| **Shebang** | `#!` - Indique l'interpreteur a utiliser pour un script |
| **Hard link** | Lien physique - Pointe directement vers les donnees du fichier |
| **Symlink** | Symbolic link - Lien symbolique, pointe vers le chemin du fichier |
| **Here document** | Bloc de texte multi-ligne utilise comme entree (`<<`) |
| **Here string** | Chaine unique utilisee comme entree (`<<<`) |

---

## Recapitulatif des commandes

### Redirections

| Commande | Description |
|----------|-------------|
| `cmd > fichier` | Rediriger stdout vers un fichier (ecrase) |
| `cmd >> fichier` | Rediriger stdout vers un fichier (ajoute) |
| `cmd 2> fichier` | Rediriger stderr vers un fichier |
| `cmd &> fichier` | Rediriger stdout et stderr vers un fichier |
| `cmd < fichier` | Utiliser un fichier comme entree |
| `cmd1 \| cmd2` | Pipe - sortie de cmd1 vers entree de cmd2 |

### Archivage et compression

| Commande | Description |
|----------|-------------|
| `tar -cvf archive.tar fichiers` | Creer une archive tar |
| `tar -xvf archive.tar` | Extraire une archive tar |
| `tar -xvzf archive.tar.gz` | Extraire une archive tar compressee gzip |
| `gzip fichier` | Compresser avec gzip |
| `gzip -d fichier.gz` | Decompresser gzip |
| `bzip2 fichier` | Compresser avec bzip2 |
| `bunzip2 fichier.bz2` | Decompresser bzip2 |

### Liens

| Commande | Description |
|----------|-------------|
| `ln fichier lien` | Creer un lien physique |
| `ln -s cible lien` | Creer un lien symbolique |

### Texte et recherche

| Commande | Description |
|----------|-------------|
| `grep 'motif' fichier` | Rechercher un motif dans un fichier |
| `sed 's/ancien/nouveau/g' fichier` | Remplacer du texte |
| `head -n X fichier` | Afficher les X premieres lignes |
| `tail -n X fichier` | Afficher les X dernieres lignes |
| `tail -f fichier` | Suivre les nouvelles lignes en temps reel |

### Variables et environnement

| Commande | Description |
|----------|-------------|
| `printenv` | Afficher toutes les variables d'environnement |
| `echo $VAR` | Afficher la valeur d'une variable |
| `export VAR=valeur` | Definir et exporter une variable |

### Documentation

| Commande | Description |
|----------|-------------|
| `man commande` | Afficher le manuel d'une commande |

---

## Ressources

- GameShell: a "game" to teach the Unix shell - Pierre Hyvernat
- BashGuide - Lhunath
- The Shell - Missing Semester (Youtube)
