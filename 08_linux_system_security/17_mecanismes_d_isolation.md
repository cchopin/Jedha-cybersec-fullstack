# Mécanismes d'isolation

**Durée : 50 min**

## Ce que vous allez apprendre dans ce cours

L'isolation est le fondement de la sécurité des conteneurs. Dans cette leçon, vous allez approfondir les mécanismes du noyau Linux qui permettent de créer des environnements isolés. Vous apprendrez :

- comment fonctionnent les namespaces en détail,
- comment les cgroups limitent les ressources,
- ce que sont les capabilities Linux,
- comment seccomp filtre les appels système.

---

## Les namespaces en détail

Les namespaces sont le mécanisme principal d'isolation sous Linux. Chaque namespace isole une ressource système spécifique.

### Types de namespaces

| Namespace | Flag | Description |
|-----------|------|-------------|
| **PID** | `CLONE_NEWPID` | Isole les ID de processus |
| **NET** | `CLONE_NEWNET` | Isole la pile réseau |
| **MNT** | `CLONE_NEWNS` | Isole les points de montage |
| **UTS** | `CLONE_NEWUTS` | Isole le hostname et domainname |
| **IPC** | `CLONE_NEWIPC` | Isole les objets IPC |
| **USER** | `CLONE_NEWUSER` | Isole les UID/GID |
| **CGROUP** | `CLONE_NEWCGROUP` | Isole la hiérarchie cgroup |
| **TIME** | `CLONE_NEWTIME` | Isole les horloges (kernel 5.6+) |

### Visualiser les namespaces

```bash
# Voir les namespaces d'un processus
$ ls -la /proc/$$/ns/
total 0
lrwxrwxrwx 1 user user 0 Jun  1 10:00 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 ipc -> ipc:[4026531839]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 mnt -> mnt:[4026531840]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 net -> net:[4026531992]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 pid -> pid:[4026531836]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 user -> user:[4026531837]
lrwxrwxrwx 1 user user 0 Jun  1 10:00 uts -> uts:[4026531838]

# Comparer deux processus
$ sudo ls -la /proc/1/ns/
$ sudo ls -la /proc/$(docker inspect -f '{{.State.Pid}}' nginx)/ns/
```

### Créer des namespaces avec unshare

```bash
# Créer un nouveau namespace PID
$ sudo unshare --pid --fork --mount-proc /bin/bash
# Dans ce shell, 'ps aux' ne montre que les processus du namespace

# Créer un nouveau namespace réseau
$ sudo unshare --net /bin/bash
# Dans ce shell, 'ip a' ne montre que l'interface loopback

# Créer un nouveau namespace UTS (hostname)
$ sudo unshare --uts /bin/bash
$ hostname nouveau-nom  # Ne change que dans ce namespace
```

### Entrer dans un namespace existant avec nsenter

```bash
# Entrer dans les namespaces d'un conteneur Docker
$ docker run -d --name test nginx
$ CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' test)

# Entrer dans le namespace PID
$ sudo nsenter -t $CONTAINER_PID -p ps aux

# Entrer dans le namespace réseau
$ sudo nsenter -t $CONTAINER_PID -n ip addr

# Entrer dans tous les namespaces
$ sudo nsenter -t $CONTAINER_PID -a /bin/bash
```

### Namespace PID

Le namespace PID isole l'arbre des processus :

```bash
# Sur l'hôte
$ ps aux | head -5
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11532 ?        Ss   10:00   0:01 /sbin/init

# Dans un nouveau namespace PID
$ sudo unshare --pid --fork --mount-proc /bin/bash
$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   7236  3980 pts/0    S    10:05   0:00 /bin/bash
```

### Namespace USER

Le namespace USER permet de mapper les UID/GID :

```bash
# Créer un user namespace où root est mappé à un utilisateur non-privilégié
$ unshare --user --map-root-user /bin/bash

# Dans ce namespace, on est root (UID 0)
$ id
uid=0(root) gid=0(root) groups=0(root)

# Mais sur l'hôte, c'est toujours l'utilisateur original
```

---

## Les cgroups en détail

Les **Control Groups** (cgroups) permettent de limiter, comptabiliser et isoler les ressources.

### Cgroups v1 vs v2

| Aspect | Cgroups v1 | Cgroups v2 |
|--------|------------|------------|
| Structure | Hiérarchies multiples | Hiérarchie unifiée |
| Montage | `/sys/fs/cgroup/<controller>/` | `/sys/fs/cgroup/` |
| Adoption | Plus ancien, encore courant | Plus récent, recommandé |

### Contrôleurs cgroups

| Contrôleur | Ressource contrôlée |
|------------|---------------------|
| **cpu** | Temps CPU |
| **cpuset** | Affinité CPU |
| **memory** | Mémoire RAM et swap |
| **blkio/io** | Bande passante disque |
| **pids** | Nombre de processus |
| **devices** | Accès aux périphériques |

### Manipuler les cgroups manuellement

```bash
# Créer un cgroup (v2)
$ sudo mkdir /sys/fs/cgroup/mongroupe

# Limiter la mémoire à 100MB
$ echo $((100 * 1024 * 1024)) | sudo tee /sys/fs/cgroup/mongroupe/memory.max

# Limiter le CPU à 50%
$ echo "50000 100000" | sudo tee /sys/fs/cgroup/mongroupe/cpu.max

# Ajouter un processus au cgroup
$ echo $$ | sudo tee /sys/fs/cgroup/mongroupe/cgroup.procs

# Voir l'utilisation mémoire
$ cat /sys/fs/cgroup/mongroupe/memory.current
```

### Cgroups avec Docker

```bash
# Limiter la mémoire
$ docker run -m 256m nginx

# Limiter le CPU (0.5 CPU)
$ docker run --cpus=0.5 nginx

# Limiter le nombre de processus
$ docker run --pids-limit=100 nginx

# Voir les limites d'un conteneur
$ docker stats nginx
```

---

## Les capabilities Linux

Les capabilities divisent les privilèges root en unités distinctes, permettant un contrôle plus fin.

### Pourquoi les capabilities ?

Traditionnellement, Linux distinguait deux types de processus :
- **Privilégiés** (UID 0) : peuvent tout faire
- **Non-privilégiés** : limités par les permissions

Les capabilities permettent d'accorder des privilèges spécifiques sans donner tous les pouvoirs de root.

### Capabilities courantes

| Capability | Description |
|------------|-------------|
| `CAP_NET_BIND_SERVICE` | Lier des ports < 1024 |
| `CAP_NET_RAW` | Utiliser des sockets raw (ping) |
| `CAP_NET_ADMIN` | Configuration réseau |
| `CAP_SYS_ADMIN` | Opérations d'administration (dangereux) |
| `CAP_SYS_PTRACE` | Tracer des processus (debug) |
| `CAP_DAC_OVERRIDE` | Ignorer les permissions DAC |
| `CAP_CHOWN` | Changer le propriétaire des fichiers |
| `CAP_SETUID` | Changer l'UID |
| `CAP_KILL` | Envoyer des signaux à n'importe quel processus |
| `CAP_MKNOD` | Créer des fichiers spéciaux |

### Voir les capabilities

```bash
# Capabilities d'un processus
$ cat /proc/$$/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000000000
CapEff:    0000000000000000
CapBnd:    000001ffffffffff
CapAmb:    0000000000000000

# Décoder les capabilities
$ capsh --decode=000001ffffffffff

# Capabilities d'un fichier
$ getcap /usr/bin/ping
/usr/bin/ping cap_net_raw=ep
```

### Gérer les capabilities des fichiers

```bash
# Ajouter une capability à un exécutable
$ sudo setcap cap_net_bind_service=+ep /usr/local/bin/myserver

# Supprimer les capabilities
$ sudo setcap -r /usr/local/bin/myserver

# Lister les fichiers avec capabilities
$ sudo getcap -r / 2>/dev/null
```

### Capabilities avec Docker

```bash
# Docker retire certaines capabilities par défaut
# Voir les capabilities par défaut
$ docker run --rm alpine sh -c 'cat /proc/1/status | grep Cap'

# Retirer toutes les capabilities
$ docker run --cap-drop=ALL nginx

# Ajouter une capability spécifique
$ docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Ajouter toutes les capabilities (dangereux)
$ docker run --cap-add=ALL nginx
```

---

## Seccomp (Secure Computing)

**Seccomp** filtre les appels système qu'un processus peut effectuer, réduisant la surface d'attaque.

### Modes seccomp

| Mode | Description |
|------|-------------|
| **Strict** | Seuls `read()`, `write()`, `exit()` et `sigreturn()` sont autorisés |
| **Filter** | Liste personnalisée d'appels système autorisés/refusés |

### Profil seccomp par défaut de Docker

Docker applique un profil seccomp par défaut qui bloque environ 44 appels système dangereux, incluant :

| Appel système | Raison du blocage |
|---------------|-------------------|
| `mount` | Pourrait modifier les montages de l'hôte |
| `reboot` | Pourrait redémarrer l'hôte |
| `ptrace` | Pourrait tracer d'autres processus |
| `kexec_load` | Pourrait charger un nouveau noyau |
| `keyctl` | Accès au keyring du noyau |

### Vérifier seccomp avec Docker

```bash
# Voir si seccomp est activé
$ docker info | grep -i seccomp
 Security Options: seccomp

# Lancer avec le profil par défaut (implicite)
$ docker run nginx

# Lancer sans seccomp (dangereux)
$ docker run --security-opt seccomp=unconfined nginx

# Utiliser un profil personnalisé
$ docker run --security-opt seccomp=mon-profil.json nginx
```

### Créer un profil seccomp personnalisé

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": ["read", "write", "exit", "exit_group"],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": ["execve"],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

### Actions seccomp

| Action | Description |
|--------|-------------|
| `SCMP_ACT_ALLOW` | Autoriser l'appel système |
| `SCMP_ACT_ERRNO` | Refuser et retourner une erreur |
| `SCMP_ACT_KILL` | Terminer le processus |
| `SCMP_ACT_TRACE` | Notifier un traceur ptrace |
| `SCMP_ACT_LOG` | Logger et autoriser |

---

## Combinaison des mécanismes

En production, tous ces mécanismes sont utilisés ensemble pour une défense en profondeur :

```
+--------------------------------------------------+
|                    Conteneur                      |
+--------------------------------------------------+
        |           |           |           |
   Namespaces   Cgroups   Capabilities  Seccomp
        |           |           |           |
+--------------------------------------------------+
|                  Noyau Linux                      |
+--------------------------------------------------+
```

### Exemple de configuration Docker sécurisée

```bash
$ docker run \
  --user 1000:1000 \           # Utilisateur non-root
  --cap-drop=ALL \              # Retirer toutes les capabilities
  --cap-add=NET_BIND_SERVICE \  # Ajouter seulement ce qui est nécessaire
  --security-opt=no-new-privileges \  # Empêcher l'escalade
  --read-only \                 # Système de fichiers en lecture seule
  --tmpfs /tmp \                # Seul /tmp est writable
  -m 256m \                     # Limite mémoire
  --cpus=0.5 \                  # Limite CPU
  --pids-limit=100 \            # Limite de processus
  nginx
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Namespace** | Espace de noms - Mécanisme d'isolation des ressources |
| **Cgroup** | Control Group - Mécanisme de limitation des ressources |
| **Capability** | Privilège spécifique divisible de root |
| **Seccomp** | Secure Computing - Filtrage des appels système |
| **PID namespace** | Isolation des identifiants de processus |
| **NET namespace** | Isolation de la pile réseau |
| **MNT namespace** | Isolation des points de montage |
| **USER namespace** | Isolation des UID/GID |
| **unshare** | Commande pour créer de nouveaux namespaces |
| **nsenter** | Commande pour entrer dans des namespaces existants |
| **CAP_SYS_ADMIN** | Capability dangereuse donnant de nombreux privilèges |
| **SCMP_ACT_ALLOW** | Action seccomp autorisant un appel système |

---

## Récapitulatif des commandes

### Namespaces

| Commande | Description |
|----------|-------------|
| `ls -la /proc/$$/ns/` | Voir les namespaces du shell actuel |
| `unshare --pid --fork bash` | Créer un nouveau namespace PID |
| `unshare --net bash` | Créer un nouveau namespace réseau |
| `unshare --user --map-root-user bash` | Créer un user namespace |
| `nsenter -t PID -a bash` | Entrer dans tous les namespaces d'un processus |
| `lsns` | Lister les namespaces du système |

### Cgroups

| Commande | Description |
|----------|-------------|
| `cat /sys/fs/cgroup/cgroup.controllers` | Voir les contrôleurs disponibles |
| `mkdir /sys/fs/cgroup/groupe` | Créer un cgroup |
| `echo PID > /sys/fs/cgroup/groupe/cgroup.procs` | Ajouter un processus |
| `echo 100M > memory.max` | Limiter la mémoire |
| `docker run -m 256m image` | Limiter la mémoire Docker |
| `docker stats` | Voir l'utilisation des ressources |

### Capabilities

| Commande | Description |
|----------|-------------|
| `cat /proc/$$/status \| grep Cap` | Voir les capabilities du shell |
| `capsh --decode=HEX` | Décoder les capabilities |
| `getcap fichier` | Voir les capabilities d'un fichier |
| `setcap cap=+ep fichier` | Ajouter une capability |
| `docker run --cap-drop=ALL image` | Retirer toutes les capabilities |
| `docker run --cap-add=CAP image` | Ajouter une capability |

### Seccomp

| Commande | Description |
|----------|-------------|
| `docker info \| grep seccomp` | Vérifier le support seccomp |
| `docker run --security-opt seccomp=unconfined` | Désactiver seccomp |
| `docker run --security-opt seccomp=profil.json` | Utiliser un profil personnalisé |

---

## Ressources

- Linux Namespaces - man7.org
- Control Groups v2 - kernel.org
- Linux Capabilities - man7.org
- Seccomp BPF - kernel.org

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) | Exploitation des capabilities |
| TryHackMe | [Container Hardening](https://tryhackme.com/room/dvcontainerhardening) | Mécanismes d'isolation |
| TryHackMe | [Docker Rodeo](https://tryhackme.com/room/dvdockerrodeo) | Évasion de conteneurs |
| HackTheBox | [Challenges Linux](https://app.hackthebox.com/challenges) | Défis d'isolation |
