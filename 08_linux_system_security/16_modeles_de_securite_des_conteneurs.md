# Modèles de sécurité des conteneurs

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

Les conteneurs ont révolutionné la façon dont les applications sont déployées et gérées. Mais avec cette flexibilité viennent des questions de sécurité importantes. Dans cette leçon, vous apprendrez :

- ce que sont les conteneurs et comment ils diffèrent des machines virtuelles,
- les technologies du noyau qui permettent l'isolation des conteneurs,
- les modèles de sécurité de Docker et LXC,
- les risques de sécurité courants liés aux conteneurs.

---

## Qu'est-ce qu'un conteneur ?

Un conteneur est un environnement isolé qui partage le noyau du système hôte mais possède son propre système de fichiers, réseau et espace de processus.

### Conteneurs vs Machines virtuelles

| Aspect | Conteneur | Machine virtuelle |
|--------|-----------|-------------------|
| **Isolation** | Niveau processus | Niveau matériel |
| **Noyau** | Partagé avec l'hôte | Noyau propre |
| **Démarrage** | Secondes | Minutes |
| **Taille** | Mégaoctets | Gigaoctets |
| **Overhead** | Minimal | Significatif |
| **Sécurité** | Isolation logicielle | Isolation matérielle |

### Schéma d'architecture

```
Machine Virtuelle                    Conteneur
+------------------+                 +------------------+
|   Application    |                 |   Application    |
+------------------+                 +------------------+
|   Bibliothèques  |                 |   Bibliothèques  |
+------------------+                 +------------------+
|   OS Invité      |                 |                  |
+------------------+                 +------------------+
|   Hyperviseur    |                 | Runtime conteneur|
+------------------+                 +------------------+
|   OS Hôte        |                 |   OS Hôte        |
+------------------+                 +------------------+
|   Matériel       |                 |   Matériel       |
+------------------+                 +------------------+
```

---

## Technologies d'isolation du noyau

Les conteneurs reposent sur plusieurs fonctionnalités du noyau Linux pour créer l'isolation.

### Namespaces

Les **namespaces** isolent les ressources système pour chaque conteneur, lui donnant sa propre vue du système.

| Namespace | Description | Exemple |
|-----------|-------------|---------|
| **PID** | Isole les ID de processus | Le conteneur voit ses processus comme PID 1, 2, 3... |
| **NET** | Isole les interfaces réseau | Le conteneur a sa propre interface eth0 |
| **MNT** | Isole les points de montage | Le conteneur a son propre système de fichiers racine |
| **UTS** | Isole le hostname | Le conteneur peut avoir son propre hostname |
| **IPC** | Isole la communication inter-processus | Files de messages, sémaphores isolés |
| **USER** | Isole les UID/GID | Root dans le conteneur peut être un utilisateur non-privilégié sur l'hôte |
| **CGROUP** | Isole la vue des cgroups | Le conteneur ne voit que ses propres cgroups |

### Cgroups (Control Groups)

Les **cgroups** limitent et comptabilisent les ressources utilisées par les conteneurs.

| Ressource | Description |
|-----------|-------------|
| **CPU** | Limite le temps CPU |
| **Mémoire** | Limite la RAM et le swap |
| **I/O** | Limite la bande passante disque |
| **Réseau** | Limite la bande passante réseau |
| **PIDs** | Limite le nombre de processus |

```bash
# Voir les cgroups d'un conteneur Docker
$ cat /sys/fs/cgroup/memory/docker/<container_id>/memory.limit_in_bytes

# Limiter la mémoire d'un conteneur Docker
$ docker run -m 512m nginx
```

### Union File Systems

Les conteneurs utilisent des systèmes de fichiers en couches (comme OverlayFS) pour partager efficacement les images de base tout en permettant des modifications isolées.

```
+------------------+
|  Couche écriture | (modifications du conteneur)
+------------------+
|  Couche image 3  | (application)
+------------------+
|  Couche image 2  | (dépendances)
+------------------+
|  Couche image 1  | (OS de base)
+------------------+
```

---

## Docker

Docker est la plateforme de conteneurisation la plus populaire. Elle simplifie la création, le déploiement et la gestion des conteneurs.

### Architecture Docker

| Composant | Description |
|-----------|-------------|
| **Docker Daemon** | Service qui gère les conteneurs (dockerd) |
| **Docker CLI** | Interface en ligne de commande |
| **Docker Images** | Templates en lecture seule pour créer des conteneurs |
| **Docker Containers** | Instances exécutables des images |
| **Docker Registry** | Dépôt pour stocker et distribuer les images |

### Modèle de sécurité Docker

Docker implémente plusieurs couches de sécurité :

| Couche | Description |
|--------|-------------|
| **Namespaces** | Isolation des processus, réseau, etc. |
| **Cgroups** | Limitation des ressources |
| **Capabilities** | Privilèges root divisés en unités |
| **Seccomp** | Filtrage des appels système |
| **AppArmor/SELinux** | Contrôle d'accès obligatoire |

### Commandes de base Docker

```bash
# Lancer un conteneur
$ docker run -d --name web nginx

# Lister les conteneurs
$ docker ps

# Exécuter une commande dans un conteneur
$ docker exec -it web /bin/bash

# Voir les logs
$ docker logs web

# Arrêter un conteneur
$ docker stop web

# Supprimer un conteneur
$ docker rm web
```

### Le socket Docker

Le socket Docker (`/var/run/docker.sock`) est un point d'accès critique :

```bash
# Qui peut accéder au socket ?
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Jun  1 10:00 /var/run/docker.sock
```

> **Attention** : L'accès au socket Docker équivaut à l'accès root sur l'hôte. Ne jamais exposer le socket à des conteneurs non fiables !

---

## LXC (Linux Containers)

**LXC** est une technologie de conteneurisation plus ancienne, offrant des conteneurs "système" plus proches des machines virtuelles.

### Docker vs LXC

| Aspect | Docker | LXC |
|--------|--------|-----|
| **Focus** | Conteneurs d'application | Conteneurs système |
| **Init** | Processus unique | Système init complet |
| **Cas d'usage** | Microservices, CI/CD | Environnements de dev, serveurs |
| **Facilité** | Plus simple | Plus complexe |
| **Images** | Docker Hub | Templates manuels |

### Commandes LXC de base

```bash
# Créer un conteneur
$ sudo lxc-create -n monconteneur -t ubuntu

# Démarrer un conteneur
$ sudo lxc-start -n monconteneur

# Se connecter au conteneur
$ sudo lxc-attach -n monconteneur

# Lister les conteneurs
$ sudo lxc-ls --fancy

# Arrêter un conteneur
$ sudo lxc-stop -n monconteneur

# Supprimer un conteneur
$ sudo lxc-destroy -n monconteneur
```

### Configuration LXC

Les fichiers de configuration LXC se trouvent dans `/var/lib/lxc/<nom>/config` :

```bash
# Exemple de configuration
lxc.rootfs.path = dir:/var/lib/lxc/monconteneur/rootfs
lxc.uts.name = monconteneur
lxc.net.0.type = veth
lxc.net.0.link = lxcbr0
lxc.net.0.flags = up
```

---

## Risques de sécurité des conteneurs

### 1. Évasion de conteneur

L'évasion de conteneur se produit quand un processus malveillant brise l'isolation pour accéder à l'hôte ou à d'autres conteneurs.

| Vecteur | Description |
|---------|-------------|
| Vulnérabilités du noyau | Bugs permettant de sortir des namespaces |
| Mauvaise configuration | Privilèges excessifs, volumes dangereux |
| Socket Docker exposé | Accès root via l'API Docker |
| Capabilities excessives | CAP_SYS_ADMIN, CAP_NET_ADMIN |

### 2. Images malveillantes

| Risque | Description |
|--------|-------------|
| Malware dans l'image | Code malveillant inclus dans l'image |
| Vulnérabilités connues | Packages non mis à jour |
| Secrets exposés | Clés API, mots de passe dans l'image |
| Images non vérifiées | Provenance inconnue |

### 3. Attaques sur le runtime

| Attaque | Description |
|---------|-------------|
| Denial of Service | Épuisement des ressources de l'hôte |
| Cryptomining | Utilisation non autorisée du CPU |
| Lateral movement | Propagation entre conteneurs |
| Exfiltration de données | Vol de données via le réseau |

### 4. Mauvaises configurations courantes

```bash
# DANGEREUX : Conteneur privilégié
$ docker run --privileged nginx

# DANGEREUX : Accès au socket Docker
$ docker run -v /var/run/docker.sock:/var/run/docker.sock nginx

# DANGEREUX : Montage de la racine hôte
$ docker run -v /:/host nginx

# DANGEREUX : Réseau hôte
$ docker run --network host nginx

# DANGEREUX : Désactiver toutes les protections
$ docker run --security-opt apparmor=unconfined --cap-add=ALL nginx
```

---

## Vérifier la sécurité d'un conteneur

### Inspecter un conteneur Docker

```bash
# Voir la configuration de sécurité
$ docker inspect --format='{{.HostConfig.Privileged}}' <container>
$ docker inspect --format='{{.HostConfig.CapAdd}}' <container>
$ docker inspect --format='{{.HostConfig.SecurityOpt}}' <container>

# Voir les montages
$ docker inspect --format='{{.Mounts}}' <container>
```

### Scanner les images

```bash
# Avec Trivy
$ trivy image nginx:latest

# Avec Docker Scout (intégré à Docker)
$ docker scout cves nginx:latest
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Container** | Conteneur - Environnement isolé partageant le noyau hôte |
| **VM** | Virtual Machine - Machine virtuelle avec son propre noyau |
| **Namespace** | Espace de noms - Mécanisme d'isolation des ressources |
| **Cgroup** | Control Group - Mécanisme de limitation des ressources |
| **Docker** | Plateforme de conteneurisation populaire |
| **LXC** | Linux Containers - Technologie de conteneurs système |
| **Image** | Template en lecture seule pour créer des conteneurs |
| **Registry** | Dépôt d'images de conteneurs |
| **OverlayFS** | Système de fichiers en couches pour conteneurs |
| **Runtime** | Logiciel exécutant les conteneurs (containerd, runc) |
| **Escape** | Évasion - Sortie non autorisée d'un conteneur |
| **Privileged** | Mode où le conteneur a accès complet à l'hôte |

---

## Récapitulatif des commandes

### Docker

| Commande | Description |
|----------|-------------|
| `docker run -d image` | Lancer un conteneur en arrière-plan |
| `docker ps` | Lister les conteneurs actifs |
| `docker ps -a` | Lister tous les conteneurs |
| `docker exec -it nom cmd` | Exécuter une commande dans un conteneur |
| `docker logs nom` | Voir les logs d'un conteneur |
| `docker stop nom` | Arrêter un conteneur |
| `docker rm nom` | Supprimer un conteneur |
| `docker images` | Lister les images |
| `docker rmi image` | Supprimer une image |
| `docker inspect nom` | Voir les détails d'un conteneur |

### LXC

| Commande | Description |
|----------|-------------|
| `lxc-create -n nom -t template` | Créer un conteneur |
| `lxc-start -n nom` | Démarrer un conteneur |
| `lxc-attach -n nom` | Se connecter à un conteneur |
| `lxc-ls --fancy` | Lister les conteneurs |
| `lxc-stop -n nom` | Arrêter un conteneur |
| `lxc-destroy -n nom` | Supprimer un conteneur |

### Vérification de sécurité

| Commande | Description |
|----------|-------------|
| `docker inspect --format='{{.HostConfig.Privileged}}' nom` | Vérifier si privilégié |
| `trivy image image:tag` | Scanner une image |

---

## Ressources

- Docker Security Best Practices - docker.com
- LXC/LXD Documentation - linuxcontainers.org
- Container Security by Liz Rice - O'Reilly
- NIST Application Container Security Guide

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Intro to Docker](https://tryhackme.com/room/dvintrotodocker) | Introduction à Docker |
| TryHackMe | [Docker Rodeo](https://tryhackme.com/room/dvdockerrodeo) | Exploitation de conteneurs Docker |
| TryHackMe | [Container Hardening](https://tryhackme.com/room/dvcontainerhardening) | Durcissement des conteneurs |
| HackTheBox | [Machines Docker](https://app.hackthebox.com/machines) | Machines avec scénarios de conteneurs |
