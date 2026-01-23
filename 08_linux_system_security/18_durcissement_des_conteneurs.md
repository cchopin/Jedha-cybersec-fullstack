# Durcissement des conteneurs

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

Maintenant que vous comprenez les mécanismes d'isolation, il est temps d'apprendre comment les utiliser efficacement pour sécuriser vos conteneurs. Dans cette leçon, vous apprendrez :

- comment créer des images sécurisées,
- les bonnes pratiques de configuration des conteneurs,
- comment utiliser les user namespaces,
- comment auditer et surveiller les conteneurs.

---

## Sécuriser les images

La sécurité d'un conteneur commence par son image. Une image mal conçue peut introduire des vulnérabilités avant même que le conteneur ne démarre.

### Principes de base

| Principe | Description |
|----------|-------------|
| **Images minimales** | Utiliser des images de base légères (alpine, distroless) |
| **Mises à jour** | Garder les packages à jour |
| **Sources fiables** | Utiliser uniquement des images officielles ou vérifiées |
| **Scanner les images** | Analyser les vulnérabilités avant déploiement |

### Choisir une image de base

| Image | Taille | Cas d'usage |
|-------|--------|-------------|
| `ubuntu` | ~77MB | Développement, compatibilité |
| `debian:slim` | ~50MB | Production, stabilité |
| `alpine` | ~5MB | Production, minimalisme |
| `distroless` | ~2MB | Production haute sécurité |
| `scratch` | 0MB | Binaires statiques Go/Rust |

### Exemple de Dockerfile sécurisé

```dockerfile
# Utiliser une image minimale avec version fixe
FROM alpine:3.19

# Créer un utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Installer uniquement les dépendances nécessaires
RUN apk add --no-cache python3

# Copier l'application
COPY --chown=appuser:appgroup app.py /app/

# Définir le répertoire de travail
WORKDIR /app

# Passer à l'utilisateur non-root
USER appuser

# Exposer le port nécessaire
EXPOSE 8080

# Définir la commande de démarrage
CMD ["python3", "app.py"]
```

### Bonnes pratiques Dockerfile

| Pratique | Mauvais | Bon |
|----------|---------|-----|
| Image de base | `FROM ubuntu:latest` | `FROM alpine:3.19` |
| Utilisateur | (root par défaut) | `USER appuser` |
| Packages | `apt install curl wget vim` | `apk add --no-cache curl` |
| Secrets | `ENV PASSWORD=secret` | Utiliser Docker secrets |
| Multi-stage | Image avec outils de build | Build séparé du runtime |

### Multi-stage builds

Les builds multi-étapes permettent de séparer l'environnement de compilation de l'image finale :

```dockerfile
# Étape 1 : Build
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /app

# Étape 2 : Runtime
FROM alpine:3.19
COPY --from=builder /app /app
USER nobody
ENTRYPOINT ["/app"]
```

### Scanner les images

```bash
# Avec Trivy
$ trivy image monimage:tag
$ trivy image --severity HIGH,CRITICAL monimage:tag

# Avec Docker Scout
$ docker scout cves monimage:tag

# Avec Grype
$ grype monimage:tag
```

---

## Configuration sécurisée des conteneurs

### Ne pas exécuter en root

```bash
# Mauvais : root par défaut
$ docker run nginx

# Bon : utilisateur spécifique
$ docker run --user 1000:1000 nginx

# Bon : utilisateur défini dans l'image
$ docker run nginx  # Si USER est défini dans le Dockerfile
```

### Retirer les capabilities inutiles

```bash
# Retirer toutes les capabilities et ajouter seulement le nécessaire
$ docker run \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  nginx
```

### Système de fichiers en lecture seule

```bash
# Monter le rootfs en lecture seule
$ docker run --read-only nginx

# Ajouter des volumes temporaires pour les écritures nécessaires
$ docker run \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/cache/nginx \
  nginx
```

### Empêcher l'escalade de privilèges

```bash
# Empêcher l'acquisition de nouveaux privilèges
$ docker run --security-opt=no-new-privileges nginx

# Cette option empêche :
# - setuid/setgid
# - execve avec capabilities élevées
# - changement de domaine SELinux
```

### Limiter les ressources

```bash
# Limiter la mémoire
$ docker run -m 256m nginx

# Limiter le CPU
$ docker run --cpus=0.5 nginx

# Limiter le nombre de processus
$ docker run --pids-limit=100 nginx

# Combinaison
$ docker run \
  -m 256m \
  --cpus=0.5 \
  --pids-limit=100 \
  nginx
```

### Réseau isolé

```bash
# Créer un réseau dédié
$ docker network create --internal backend

# Lancer le conteneur dans le réseau isolé
$ docker run --network backend myapp

# Pas d'accès à Internet depuis ce réseau
```

---

## User namespaces

Les **user namespaces** permettent de mapper root dans le conteneur à un utilisateur non-privilégié sur l'hôte.

### Pourquoi utiliser les user namespaces ?

| Scénario | Sans user namespace | Avec user namespace |
|----------|---------------------|---------------------|
| Root dans conteneur | Root sur l'hôte | Utilisateur normal sur l'hôte |
| Évasion de conteneur | Accès root complet | Accès utilisateur limité |

### Activer les user namespaces avec Docker

1. Configurer le daemon Docker (`/etc/docker/daemon.json`) :

```json
{
  "userns-remap": "default"
}
```

2. Redémarrer Docker :

```bash
$ sudo systemctl restart docker
```

3. Vérifier la configuration :

```bash
# Vérifier le mapping
$ cat /etc/subuid
dockremap:100000:65536

$ cat /etc/subgid
dockremap:100000:65536
```

### Vérifier les user namespaces

```bash
# Lancer un conteneur
$ docker run -d --name test alpine sleep 1000

# Trouver le PID sur l'hôte
$ docker inspect -f '{{.State.Pid}}' test
12345

# Vérifier l'UID réel
$ ps -p 12345 -o uid,user
  UID USER
100000 dockremap
```

---

## Profils de sécurité

### AppArmor avec Docker

```bash
# Lancer avec le profil AppArmor par défaut
$ docker run nginx

# Utiliser un profil personnalisé
$ docker run --security-opt apparmor=mon-profil nginx

# Désactiver AppArmor (non recommandé)
$ docker run --security-opt apparmor=unconfined nginx
```

### SELinux avec Docker

```bash
# Lancer avec SELinux (si configuré)
$ docker run nginx

# Ajouter des labels SELinux
$ docker run --security-opt label=type:container_t nginx

# Désactiver SELinux (non recommandé)
$ docker run --security-opt label=disable nginx
```

### Seccomp personnalisé

Créer un profil restrictif (`profil-restrictif.json`) :

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {
            "names": [
                "accept", "accept4", "arch_prctl", "bind", "brk",
                "clone", "close", "connect", "dup", "dup2", "epoll_create",
                "epoll_ctl", "epoll_wait", "execve", "exit", "exit_group",
                "fcntl", "fstat", "futex", "getcwd", "getdents64",
                "getpid", "getppid", "getsockname", "getsockopt",
                "listen", "lseek", "mmap", "mprotect", "munmap",
                "nanosleep", "open", "openat", "pipe", "poll", "read",
                "recvfrom", "recvmsg", "rt_sigaction", "rt_sigprocmask",
                "sendmsg", "sendto", "setsockopt", "shutdown", "socket",
                "stat", "write"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

```bash
$ docker run --security-opt seccomp=profil-restrictif.json nginx
```

---

## Docker Compose sécurisé

Exemple de `docker-compose.yml` avec bonnes pratiques :

```yaml
version: '3.8'

services:
  web:
    image: nginx:alpine
    read_only: true
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
      - /var/cache/nginx
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.1'
          memory: 128M
    networks:
      - frontend
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3

  app:
    image: myapp:latest
    read_only: true
    user: "1000:1000"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - frontend
      - backend

  db:
    image: postgres:15-alpine
    user: "70:70"  # postgres user
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true  # Pas d'accès externe

volumes:
  db-data:
```

---

## Audit et surveillance

### Surveiller les événements Docker

```bash
# Suivre les événements en temps réel
$ docker events

# Filtrer par type
$ docker events --filter type=container

# Filtrer par événement
$ docker events --filter event=start --filter event=stop
```

### Auditer avec auditd

```bash
# Surveiller le socket Docker
$ sudo auditctl -w /var/run/docker.sock -p rwxa -k docker_socket

# Surveiller les binaires Docker
$ sudo auditctl -w /usr/bin/docker -p x -k docker_exec

# Rechercher les événements
$ sudo ausearch -k docker_socket
```

### Outils de sécurité

| Outil | Description |
|-------|-------------|
| **Trivy** | Scanner de vulnérabilités |
| **Falco** | Détection d'intrusion runtime |
| **Sysdig** | Surveillance et forensics |
| **Docker Bench** | Audit des bonnes pratiques |
| **Anchore** | Analyse de conformité des images |

### Docker Bench for Security

```bash
# Lancer l'audit Docker Bench
$ docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

---

## Checklist de durcissement

### Image

- [ ] Utiliser une image de base minimale
- [ ] Fixer les versions des images et packages
- [ ] Scanner les vulnérabilités
- [ ] Utiliser des builds multi-étapes
- [ ] Définir un USER non-root
- [ ] Ne pas inclure de secrets dans l'image

### Runtime

- [ ] Exécuter en tant qu'utilisateur non-root
- [ ] Retirer toutes les capabilities inutiles
- [ ] Activer `no-new-privileges`
- [ ] Monter le rootfs en lecture seule
- [ ] Limiter les ressources (CPU, mémoire, PIDs)
- [ ] Utiliser des réseaux isolés
- [ ] Activer les profils seccomp/AppArmor

### Hôte

- [ ] Activer les user namespaces
- [ ] Restreindre l'accès au socket Docker
- [ ] Activer l'audit Docker
- [ ] Mettre à jour Docker régulièrement

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Hardening** | Durcissement - Renforcement de la sécurité |
| **Distroless** | Images sans distribution, seulement l'application |
| **Multi-stage build** | Build en plusieurs étapes pour séparer compilation et runtime |
| **User namespace** | Espace de noms mappant les UID/GID |
| **Read-only rootfs** | Système de fichiers racine en lecture seule |
| **no-new-privileges** | Option empêchant l'escalade de privilèges |
| **Docker Bench** | Outil d'audit des bonnes pratiques Docker |
| **Trivy** | Scanner de vulnérabilités pour conteneurs |
| **Falco** | Outil de détection d'intrusion pour conteneurs |
| **Content Trust** | Signature et vérification des images Docker |

---

## Récapitulatif des commandes

### Configuration sécurisée

| Commande | Description |
|----------|-------------|
| `docker run --user 1000:1000` | Exécuter en tant qu'utilisateur spécifique |
| `docker run --cap-drop=ALL` | Retirer toutes les capabilities |
| `docker run --cap-add=CAP` | Ajouter une capability spécifique |
| `docker run --read-only` | Système de fichiers en lecture seule |
| `docker run --tmpfs /tmp` | Ajouter un volume temporaire |
| `docker run --security-opt=no-new-privileges` | Empêcher l'escalade |
| `docker run -m 256m` | Limiter la mémoire |
| `docker run --cpus=0.5` | Limiter le CPU |
| `docker run --pids-limit=100` | Limiter les processus |

### Audit et analyse

| Commande | Description |
|----------|-------------|
| `docker events` | Suivre les événements Docker |
| `trivy image image:tag` | Scanner une image |
| `docker scout cves image:tag` | Analyser les CVE |
| `docker inspect conteneur` | Voir la configuration |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/docker/daemon.json` | Configuration du daemon Docker |
| `/etc/subuid`, `/etc/subgid` | Mapping des user namespaces |
| `Dockerfile` | Définition de l'image |
| `docker-compose.yml` | Configuration multi-conteneurs |

---

## Ressources

- CIS Docker Benchmark - cisecurity.org
- Docker Security Best Practices - docker.com
- NIST Application Container Security Guide
- Sysdig Container Security Guide

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Container Hardening](https://tryhackme.com/room/dvcontainerhardening) | Durcissement des conteneurs |
| TryHackMe | [Docker Rodeo](https://tryhackme.com/room/dvdockerrodeo) | Sécurité Docker offensive |
| TryHackMe | [Intro to Docker](https://tryhackme.com/room/dvintrotodocker) | Introduction à Docker |
| HackTheBox | [Machines Docker](https://app.hackthebox.com/machines) | Scénarios de sécurité conteneurs |
