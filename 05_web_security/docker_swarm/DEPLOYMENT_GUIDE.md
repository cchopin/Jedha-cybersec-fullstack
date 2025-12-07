# Guide de Déploiement - Employee Hive Directory

## Description

Ce guide décrit le déploiement de l'application Employee Hive Directory sur un cluster Docker Swarm composé de 3 nœuds (1 manager et 2 workers).

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Swarm Cluster                    │
├─────────────────┬─────────────────┬─────────────────────────┤
│     Manager     │     Worker1     │        Worker2          │
│   192.168.2.3   │   192.168.2.4   │      192.168.2.5        │
├─────────────────┼─────────────────┼─────────────────────────┤
│   PostgreSQL    │   hive_app      │      hive_app           │
│   (hive_db)     │   (réplica 1)   │      (réplica 2)        │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### Composants

| Service | Image | Réplicas | Emplacement |
|---------|-------|----------|-------------|
| db | postgres:14-alpine | 1 | Manager uniquement |
| app | jedha/hive-directory | 2 | Workers |

---

## Prérequis

- macOS avec Homebrew installé
- Multipass (`brew install multipass`)
- Connexion internet pour télécharger les images Docker

---

## Phase 1 : Création de l'infrastructure

### 1.1 Installation de Multipass

```bash
brew install multipass
```

### 1.2 Création des machines virtuelles

```bash
# Création du manager
multipass launch --name manager --cpus 1 --memory 2G --disk 10G

# Création des workers
multipass launch --name worker1 --cpus 1 --memory 2G --disk 10G
multipass launch --name worker2 --cpus 1 --memory 2G --disk 10G
```

### 1.3 Vérification des VMs

```bash
multipass list
```

Résultat attendu :
```
Name                    State             IPv4             Image
manager                 Running           192.168.2.3      Ubuntu 24.04 LTS
worker1                 Running           192.168.2.4      Ubuntu 24.04 LTS
worker2                 Running           192.168.2.5      Ubuntu 24.04 LTS
```

---

## Phase 2 : Installation de Docker

### 2.1 Installation sur le Manager

```bash
multipass shell manager
```

```bash
sudo apt update
sudo apt install -y docker.io
docker --version
sudo usermod -aG docker $USER
exit
```

Reconnexion pour appliquer les droits :
```bash
multipass shell manager
```

### 2.2 Installation sur Worker1

```bash
multipass shell worker1
```

```bash
sudo apt update
sudo apt install -y docker.io
docker --version
sudo usermod -aG docker $USER
exit
```

### 2.3 Installation sur Worker2

```bash
multipass shell worker2
```

```bash
sudo apt update
sudo apt install -y docker.io
docker --version
sudo usermod -aG docker $USER
exit
```

---

## Phase 3 : Configuration du Swarm

### 3.1 Initialisation du Swarm sur le Manager

```bash
multipass shell manager
```

```bash
# Récupération de l'IP du manager
MANAGER_IP=$(hostname -I | awk '{print $1}')
echo $MANAGER_IP

# Initialisation du swarm
docker swarm init --advertise-addr $MANAGER_IP
```

Conserver la commande `docker swarm join` affichée. Exemple :
```
docker swarm join --token SWMTKN-1-xxx...xxx 192.168.2.3:2377
```

### 3.2 Jonction des Workers

Sur Worker1 :
```bash
multipass shell worker1
docker swarm join --token SWMTKN-1-xxx...xxx 192.168.2.3:2377
```

Sur Worker2 :
```bash
multipass shell worker2
docker swarm join --token SWMTKN-1-xxx...xxx 192.168.2.3:2377
```

### 3.3 Vérification du cluster

Sur le Manager :
```bash
docker node ls
```

Résultat attendu :
```
ID                            HOSTNAME   STATUS    AVAILABILITY   MANAGER STATUS   ENGINE VERSION
9vd0i55m72ml7h4od7rm72a3c *   manager    Ready     Active         Leader           28.2.2
kht1hj6tvuvrs9b6hwule6gpe     worker1    Ready     Active                          28.2.2
jx349galsq2yqufyuk35wdgnw     worker2    Ready     Active                          28.2.2
```

---

## Phase 4 : Configuration de l'application

### 4.1 Fichier docker-compose.yaml

Créer le fichier `docker-compose.yaml` avec le contenu suivant :

```yaml
version: '3.8'
services:
  db:
    image: postgres:14-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=hive_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      placement:
        constraints:
          - node.role == manager

  app:
    image: jedha/hive-directory
    ports:
      - target: 5000
        published: 8080
        mode: host
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_HOST: db
      POSTGRES_PORT: 5432
      POSTGRES_DB: hive_db
      SECRET_KEY: a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
    deploy:
      replicas: 2
    depends_on:
      - db

volumes:
  postgres_data:
```

### 4.2 Description de la configuration

**Service db (PostgreSQL) :**
- Image : `postgres:14-alpine`
- Volume persistant pour les données
- Healthcheck pour vérifier la disponibilité
- Contrainte de placement : uniquement sur le manager

**Service app (Employee Hive Directory) :**
- Image : `jedha/hive-directory`
- Port 8080 exposé en mode host (évite le conflit avec AirDrop sur le port 5000)
- 2 réplicas pour la haute disponibilité
- Variables d'environnement pour la connexion à PostgreSQL

---

## Phase 5 : Déploiement

### 5.1 Transfert du fichier vers le Manager

```bash
multipass transfer docker-compose.yaml manager:/home/ubuntu/
```

### 5.2 Vérification du fichier

```bash
multipass shell manager
cat docker-compose.yaml
```

### 5.3 Déploiement de la stack

```bash
docker stack deploy -c docker-compose.yaml hive
```

---

## Phase 6 : Vérification

### 6.1 État des services

```bash
docker service ls
```

Résultat attendu :
```
ID             NAME       MODE         REPLICAS   IMAGE                         PORTS
nqvi0djpsyw7   hive_app   replicated   2/2        jedha/hive-directory:latest
ozilgpcvug44   hive_db    replicated   1/1        postgres:14-alpine
```

### 6.2 Détail des tâches

```bash
# Vérifier PostgreSQL (doit être sur le manager)
docker service ps hive_db

# Vérifier l'application (2 réplicas sur les workers)
docker service ps hive_app
```

### 6.3 Logs des services

```bash
# Logs de la base de données
docker service logs hive_db

# Logs de l'application
docker service logs hive_app
```

---

## Phase 7 : Test de l'application

### 7.1 Accès via navigateur

L'application est accessible sur le port 8080 des workers :

- http://192.168.2.4:8080 (Worker1)
- http://192.168.2.5:8080 (Worker2)

### 7.2 Test en ligne de commande

```bash
curl http://192.168.2.4:8080
curl http://192.168.2.5:8080
```

---

## Commandes utiles

### Gestion du Swarm

```bash
# Liste des nœuds
docker node ls

# Informations sur le swarm
docker info

# Régénérer le token worker
docker swarm join-token worker
```

### Gestion des services

```bash
# Liste des services
docker service ls

# Détail d'un service
docker service ps <service_name>

# Logs d'un service
docker service logs <service_name>

# Mise à jour du nombre de réplicas
docker service scale hive_app=3
```

### Gestion de la stack

```bash
# Déployer/mettre à jour
docker stack deploy -c docker-compose.yaml hive

# Liste des stacks
docker stack ls

# Services d'une stack
docker stack services hive

# Supprimer une stack
docker stack rm hive
```

### Gestion des VMs Multipass

```bash
# Liste des VMs
multipass list

# Connexion à une VM
multipass shell <nom>

# Arrêt d'une VM
multipass stop <nom>

# Suppression d'une VM
multipass delete <nom> && multipass purge
```

---

## Dépannage

### L'application ne répond pas

1. Vérifier que les services tournent : `docker service ls`
2. Vérifier les logs : `docker service logs hive_app`
3. Vérifier la connectivité réseau entre les nœuds

### Erreur "could not translate host name db"

Cette erreur est normale au démarrage initial. Docker Swarm redémarre automatiquement les conteneurs jusqu'à ce que le réseau overlay soit prêt.

### Réinitialisation complète

```bash
# Supprimer la stack
docker stack rm hive

# Sur les workers
docker swarm leave

# Sur le manager
docker swarm leave --force

# Supprimer les VMs
multipass delete manager worker1 worker2
multipass purge
```
