# Les processus Linux

**Duree : 70 min**

## Ce que vous allez apprendre dans ce cours

Hier, nous avons explore comment les permissions definissent qui peut acceder aux fichiers, executer des commandes et modifier les ressources systeme. Mais ce ne sont pas les utilisateurs qui font le travail directement : les processus agissent en leur nom. Dans cette lecon, vous apprendrez a :

- identifier les processus actifs,
- les controler avec des signaux et des priorites,
- inspecter les details d'un processus,
- limiter les ressources consommees par un processus.

---

## Qu'est-ce qu'un processus ?

Un **processus** sous Linux est une instance d'un programme en cours d'execution par le systeme d'exploitation. Quand vous executez une commande, lancez une application ou executez un script, Linux cree un processus pour gerer cette tache et lui attribue un **PID** (Process ID) unique.

### Programme vs processus

| Concept | Description |
|---------|-------------|
| **Programme** | Ensemble passif d'instructions et de donnees stockees sur disque |
| **Processus** | Execution active de ces instructions, avec registres CPU et regions memoire (heap, stack) |

### Environnement de processus

Un processus possede :
- Son propre espace d'adressage
- Ses fichiers ouverts
- Ses variables d'environnement
- Ses ressources systeme

![Environnement de processus](assets/Process_environment.png)

Cette isolation garantit que les processus n'interferent pas entre eux.

### Creation d'un processus

Un nouveau processus est cree quand un processus existant fait une copie exacte de lui-meme :
- Le nouveau processus est le **processus enfant**
- L'original est le **processus parent**

**Exemple avec `touch file.txt` :**

![Diagramme touch file.txt](assets/touch_file1.png)

1. `bash` utilise l'appel systeme `fork()` pour creer un processus enfant
2. La famille d'appels systeme `exec()` remplace le programme bash par `touch`
3. `touch` s'execute : utilise memoire et CPU, interagit avec le noyau
4. Une fois termine, `touch` appelle `exit()`, envoyant un signal au parent
5. Le parent nettoie le processus avec l'appel systeme `wait()`

### Threads vs processus

| Concept | Description |
|---------|-------------|
| **Processus** | Instance d'un programme avec son propre espace memoire |
| **Thread** | Unite d'execution plus petite au sein d'un processus, partageant la memoire |

Les threads sont plus legers et efficaces pour le traitement parallele.

---

## Surveiller les processus

### La commande ps

`ps` (process status) donne un instantane des processus en cours. C'est un outil non interactif.

```bash
# Processus du shell courant
$ ps

# Tous les processus en format detaille
$ ps aux
```

**Signification des options :**
- `a` : processus de tous les utilisateurs
- `u` : format oriente utilisateur
- `x` : inclut les processus sans terminal

**Explication des colonnes de ps aux :**

![Sortie de ps aux](assets/ps_aux.png)

**Combiner ps et grep :**
```bash
$ ps aux | grep ssh
```

### Etats des processus (STAT)

| Etat | Symbole | Description |
|------|---------|-------------|
| Running | `R` | En cours d'execution ou pret a s'executer |
| Sleeping | `S` | En attente d'un evenement (entree utilisateur, donnees reseau...) |
| Disk Sleep | `D` | Sommeil non interruptible (attente I/O) - ne peut pas etre tue |
| Stopped | `T` | Arrete, souvent pour debogage |
| Zombie | `Z` | Termine mais le parent n'a pas collecte son statut de sortie |
| Dead | `X` | Rare, processus plus en cours mais pas completement nettoye |

**Drapeaux supplementaires :**
| Drapeau | Signification |
|---------|---------------|
| `<` | Haute priorite (plus de temps CPU) |
| `N` | Basse priorite |
| `L` | Pages verrouillees en memoire |
| `s` | Leader de session |
| `+` | En premier plan |

### top et htop

Contrairement a `ps`, `top` et `htop` offrent une vue en temps reel, rafraichie toutes les quelques secondes.

**Commande top :**
```bash
$ top
```

![Sortie de top](assets/top.png)

**Raccourcis dans top :**
| Touche | Action |
|--------|--------|
| `P` | Trier par CPU |
| `M` | Trier par memoire |
| `k` | Tuer un processus (entrer PID) |
| `Shift+f` | Suivre un processus |
| `q` | Quitter |

**htop** est une alternative amelioree avec :
- Barres d'utilisation colorees
- Support souris
- F5 pour l'arbre des processus
- F3 pour rechercher
- F9 pour tuer

### pgrep et pidof

**pgrep** - Recherche par motif :
```bash
$ pgrep ssh
1990
268844

# Avec noms de processus
$ pgrep -l ssh

# Correspondance sur la ligne de commande complete
$ pgrep -lf systemd
```

**pidof** - Recherche par nom exact :
```bash
$ pidof sshd
268911 268846 268844
```

### Que surveiller ?

#### Utilisation elevee des ressources
- CPU eleve : application emballee, code inefficace, attaque DoS
- RAM elevee : fuites memoire, swap excessif

```bash
$ ps aux --sort=-%cpu | head
```

#### Processus non reactifs ou bloques
- Processus en etat `D` (Disk Sleep) ou `Z` (Zombie)
- Peuvent causer l'epuisement des ressources

```bash
# Identifier les zombies
$ ps aux | awk '$8=="Z"'
```

#### Problemes de securite
- Processus inconnus ou deguises
- Relations parent-enfant suspectes
- Programmes executant depuis `/tmp` ou autres repertoires non standards

```bash
# Executables suspects
$ ps aux | grep '/tmp\|/dev\|/home'

# Processus bash
$ ps aux | grep '[b]ash'

# Surveiller les nouveaux processus
$ watch 'ps -eo pid,ppid,cmd --sort=start_time | tail'
```

> **Processus deguises** : Les attaquants nomment souvent leurs processus malveillants pour ressembler a des processus legitimes (kworker, sshd, cron) ou utilisent des fautes de frappe subtiles.

---

## Controler les processus

### Envoyer des signaux avec kill et killall

Les **signaux** sont une forme de communication inter-processus (IPC) pour notifier qu'un evenement s'est produit.

**Envoyer un signal avec kill :**
```bash
# SIGTERM par defaut (termine proprement)
$ kill 279494

# Signal specifique
$ kill -s SIGKILL 279530
```

**Tuer par nom avec killall :**
```bash
$ killall firefox
```

**Signaux courants :**
| Signal | Numero | Description |
|--------|--------|-------------|
| SIGTERM | 15 | Demande de terminer proprement |
| SIGKILL | 9 | Force la terminaison (ne peut pas etre ignore) |
| SIGINT | 2 | Envoye avec Ctrl+C |
| SIGHUP | 1 | Deconnexion du terminal / recharger la configuration |

```bash
# Lister tous les signaux
$ kill -l
```

### Jobs en arriere-plan et premier plan

Quand vous executez une commande avec `&`, elle s'execute en arriere-plan :

```bash
$ sleep 1000 &
[1] 279494
```

**Gestion des jobs :**
| Action | Commande |
|--------|----------|
| Lancer en arriere-plan | `commande &` |
| Suspendre | `Ctrl+Z` |
| Reprendre en arriere-plan | `bg` |
| Ramener en premier plan | `fg %[job_id]` |
| Lister les jobs | `jobs` |

### Changer les priorites : nice et renice

Le **scheduler** du noyau decide quel processus obtient du temps CPU. La valeur de **niceness** (NI) influence cette decision.

| Valeur nice | Signification |
|-------------|---------------|
| -20 | Priorite la plus haute (moins "gentil") |
| 0 | Par defaut |
| 19 | Priorite la plus basse (plus "gentil") |

**Definir la priorite au lancement :**
```bash
$ nice -n 10 sleep 1000 &
```

**Modifier un processus en cours :**
```bash
$ renice -n 5 -p 279887
```

> Seul root peut definir des valeurs negatives (priorite plus haute).

---

## Internes des processus

### Inspecter via /proc

Chaque processus a un repertoire sous `/proc` nomme d'apres son PID, contenant des fichiers avec des informations en temps reel.

| Fichier | Contenu |
|---------|---------|
| `/proc/[pid]/status` | Resume lisible : nom, etat, PID, PPID |
| `/proc/[pid]/cmdline` | Ligne de commande complete (separee par \0) |
| `/proc/[pid]/environ` | Variables d'environnement (separees par \0) |
| `/proc/[pid]/cwd` | Lien vers le repertoire de travail |
| `/proc/[pid]/exe` | Lien vers le binaire execute |
| `/proc/[pid]/fd/` | Descripteurs de fichiers ouverts |

```bash
$ cat /proc/280027/status
$ ll /proc/280027/exe
$ ll /proc/280027/fd
```

> `/proc/` est un pseudo-systeme de fichiers : pas stocke sur disque, genere a la volee par le noyau.

### Daemons et hierarchies de processus

La plupart des processus font partie d'une hierarchie parent-enfant, commencant par **systemd** (PID 1), le premier processus espace utilisateur lance par le noyau.

```bash
$ ps --forest
$ pstree
```

Un **daemon** est un processus en arriere-plan de longue duree, typiquement :
- Detache de tout terminal
- Cree une nouvelle session (devient leader de session)
- Ferme stdin/stdout/stderr ou les redirige vers /dev/null
- Fork et laisse le parent se terminer

Exemple : `sshd` - le daemon OpenSSH.

### Processus zombie et orphelin

| Type | Description |
|------|-------------|
| **Zombie** | Processus termine dont le parent n'a pas lu le statut de sortie. Visible avec etat `Z`. Ne consomme pas de ressources mais encombre la table des processus. |
| **Orphelin** | Processus dont le parent est mort. Automatiquement re-parent a systemd. |

---

## Capabilities et limites

### Linux Capabilities : getcap, setcap

Les **capabilities** divisent le modele de privileges root en unites specifiques, permettant d'attribuer des permissions precises sans acces root complet.

**Voir les capabilities d'un executable :**
```bash
$ getcap /usr/bin/ping
/usr/bin/ping cap_net_raw=ep
```

**Valeurs des capabilities :**
| Valeur | Signification |
|--------|---------------|
| `p` (permitted) | Le processus peut utiliser cette capability |
| `e` (effective) | Le processus utilise cette capability |
| `i` (inheritable) | La capability est passee lors de exec() |

**Definir une capability :**
```bash
$ sudo setcap cap_net_bind_service=+ep /usr/local/bin/my_server
```

**Capabilities courantes :**
| Capability | Description |
|------------|-------------|
| CAP_NET_BIND_SERVICE | Lier aux ports < 1024 |
| CAP_NET_RAW | Utiliser les raw sockets (ping) |
| CAP_SYS_PTRACE | Tracer d'autres processus |
| CAP_CHOWN | Changer le proprietaire des fichiers |
| CAP_DAC_OVERRIDE | Contourner les permissions de fichiers |
| CAP_SETUID | Changer l'UID du processus |
| CAP_SYS_ADMIN | Super-pouvoir - nombreuses actions privilegiees |

### Limites de ressources : ulimit

`ulimit` affiche ou definit les limites de ressources pour les processus.

```bash
# Voir la limite des fichiers ouverts
$ ulimit -n
1024
```

**Options courantes :**
| Option | Limite |
|--------|--------|
| `-n` | Nombre max de descripteurs de fichiers ouverts |
| `-u` | Nombre max de processus par utilisateur |
| `-v` | Taille max de memoire virtuelle (KB) |
| `-t` | Temps CPU max (secondes) |

**Modifier les limites d'un processus en cours :**
```bash
$ sudo prlimit --pid 278697 --nofile=1024:4096
```

**Voir les limites d'un processus :**
```bash
$ cat /proc/278697/limits
```

**Limites permanentes dans `/etc/security/limits.conf` :**
```
julia   hard   nproc   100
julia   soft   nofile  1024
```

---

## Glossaire des sigles et definitions

| Sigle/Terme | Definition |
|-------------|------------|
| **PID** | Process ID - Identifiant unique d'un processus |
| **PPID** | Parent Process ID - PID du processus parent |
| **UID/GID** | User/Group ID sous lequel le processus s'execute |
| **Thread** | Unite d'execution au sein d'un processus, partageant la memoire |
| **Daemon** | Processus en arriere-plan de longue duree |
| **Zombie** | Processus termine dont le parent n'a pas collecte le statut |
| **Orphelin** | Processus dont le parent est mort |
| **Signal** | Notification asynchrone envoyee a un processus |
| **Nice/Niceness** | Valeur influencant la priorite d'un processus (-20 a 19) |
| **Scheduler** | Composant du noyau decidant quel processus obtient du temps CPU |
| **IPC** | Inter-Process Communication - Communication inter-processus |
| **Capability** | Privilege specifique pouvant etre accorde sans acces root complet |
| **ulimit** | Limites de ressources pour les processus |
| **fork()** | Appel systeme creant un processus enfant |
| **exec()** | Appel systeme remplacant le programme d'un processus |

---

## Recapitulatif des commandes

### Surveillance des processus

| Commande | Description |
|----------|-------------|
| `ps` | Instantane des processus du shell courant |
| `ps aux` | Tous les processus en detail |
| `ps aux --sort=-%cpu` | Trier par utilisation CPU |
| `ps --forest` | Afficher l'arbre des processus |
| `top` | Vue en temps reel des processus |
| `htop` | Version amelioree de top |
| `pgrep motif` | Trouver PID par motif |
| `pgrep -l motif` | Avec noms de processus |
| `pidof nom` | Trouver PID par nom exact |

### Controle des processus

| Commande | Description |
|----------|-------------|
| `kill PID` | Envoyer SIGTERM (terminer proprement) |
| `kill -9 PID` | Envoyer SIGKILL (forcer la terminaison) |
| `kill -s SIGNAL PID` | Envoyer un signal specifique |
| `killall nom` | Tuer tous les processus par nom |
| `jobs` | Lister les jobs du shell |
| `bg` | Reprendre en arriere-plan |
| `fg` | Ramener en premier plan |
| `Ctrl+C` | Envoyer SIGINT (interrompre) |
| `Ctrl+Z` | Suspendre le processus |

### Priorite

| Commande | Description |
|----------|-------------|
| `nice -n 10 commande` | Lancer avec priorite reduite |
| `renice -n 5 -p PID` | Modifier la priorite d'un processus |

### Inspection /proc

| Commande | Description |
|----------|-------------|
| `cat /proc/PID/status` | Statut du processus |
| `cat /proc/PID/cmdline` | Ligne de commande |
| `cat /proc/PID/environ` | Variables d'environnement |
| `ls -l /proc/PID/fd` | Fichiers ouverts |
| `ls -l /proc/PID/exe` | Lien vers l'executable |
| `cat /proc/PID/limits` | Limites de ressources |

### Capabilities et limites

| Commande | Description |
|----------|-------------|
| `getcap fichier` | Voir les capabilities d'un fichier |
| `setcap cap=+ep fichier` | Definir une capability |
| `ulimit -a` | Afficher toutes les limites |
| `ulimit -n` | Limite de fichiers ouverts |
| `prlimit --pid PID` | Voir/modifier les limites d'un processus |

### Divers

| Commande | Description |
|----------|-------------|
| `pstree` | Arbre des processus |
| `kill -l` | Lister tous les signaux |

---

## Ressources

- The Essential Guide to Understanding Linux Process Status - Rahul
- Understanding Priority Levels in Linux - Jose Agustin Barrachina
- Chapter 4: Processes - David A Rusling
