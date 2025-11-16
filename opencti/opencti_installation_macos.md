# Documentation d'installation OpenCTI sur macOS

## Table des matières

1. [Introduction](#introduction)
2. [Prérequis](#prérequis)
3. [Architecture et composants](#architecture-et-composants)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Vérification de l'installation](#vérification-de-linstallation)
7. [Gestion des services](#gestion-des-services)
8. [Configuration post-installation](#configuration-post-installation)
9. [Troubleshooting](#troubleshooting)
10. [Sécurité](#sécurité)
11. [Sauvegarde et restauration](#sauvegarde-et-restauration)
12. [Mise à jour](#mise-à-jour)
13. [Ressources utiles](#ressources-utiles)

---

## Introduction

### Qu'est-ce qu'OpenCTI ?

OpenCTI (Open Cyber Threat Intelligence) est une plateforme open-source conçue pour gérer, stocker et visualiser les informations de Cyber Threat Intelligence (CTI). Développée par Luatix, elle permet aux organisations de centraliser leurs données de menaces cyber et de les corréler avec les informations de l'écosystème global de cybersécurité.

### Fonctionnalités principales

- **Gestion centralisée** des indicateurs de compromission (IoC)
- **Visualisation graphique** des relations entre entités
- **Intégration** avec de nombreuses sources de threat intelligence
- **Import/Export** de données au format STIX 2.1
- **Connecteurs** pour automatiser la collecte de données
- **API REST** complète pour l'intégration avec d'autres outils

---

## Prérequis

### Configuration matérielle recommandée

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| **Processeur** | 4 cœurs | 8 cœurs ou plus |
| **RAM** | 8 GB | 16 GB ou plus |
| **Stockage** | 50 GB | 100 GB SSD |
| **Réseau** | Connexion Internet stable | Connexion haut débit |

### Système d'exploitation

- **macOS** 11 (Big Sur) ou supérieur
- Compatible avec les Macs Intel et Apple Silicon (M1/M2/M3)

### Logiciels requis

#### 1. Docker Desktop pour Mac

Docker Desktop est essentiel pour faire fonctionner OpenCTI. Il fournit un environnement containerisé pour tous les services.

**Installation via le site officiel :**
1. Téléchargez Docker Desktop depuis [docker.com](https://www.docker.com/products/docker-desktop)
2. Ouvrez le fichier `.dmg` téléchargé
3. Glissez Docker.app dans le dossier Applications
4. Lancez Docker Desktop

**Installation via Homebrew (alternative) :**
```bash
brew install --cask docker
```

**Configuration Docker Desktop :**
1. Ouvrez Docker Desktop
2. Allez dans Préférences → Resources
3. Allouez au minimum :
   - **CPU** : 4 cœurs
   - **Memory** : 8 GB
   - **Swap** : 2 GB
   - **Disk** : 50 GB

#### 2. Git

Git est généralement préinstallé sur macOS. Pour vérifier :

```bash
git --version
```

Si Git n'est pas installé :

```bash
# Via Homebrew
brew install git

# Ou via Xcode Command Line Tools
xcode-select --install
```

#### 3. Homebrew (optionnel mais recommandé)

Homebrew facilite l'installation de logiciels sur macOS.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

## Architecture et composants

OpenCTI utilise une architecture microservices composée de plusieurs conteneurs Docker :

### Composants principaux

| Composant | Rôle | Port |
|-----------|------|------|
| **OpenCTI** | Application web principale | 8080 |
| **Elasticsearch** | Moteur de recherche et stockage | 9200 |
| **Redis** | Cache et file d'attente | 6379 |
| **RabbitMQ** | Message broker | 5672, 15672 |
| **MinIO** | Stockage S3 compatible | 9000 |
| **Workers** | Traitement asynchrone | - |

### Connecteurs optionnels

- **Import STIX** : Import de fichiers STIX
- **Import Document** : Import de documents
- **Export CSV/TXT/STIX** : Export de données
- **Analysis** : Analyse de fichiers
- **XTM Composer** : Gestion avancée des données

### Schéma d'architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Navigateur Web                        │
│                   (localhost:8080)                       │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  OpenCTI Platform                        │
│              (Application principale)                    │
└─────┬─────────┬──────────┬──────────┬───────────────────┘
      │         │          │          │
      ▼         ▼          ▼          ▼
┌──────────┐ ┌──────┐ ┌──────────┐ ┌──────┐
│ElasticSearch│Redis│ │RabbitMQ │ │MinIO │
│  (Données) │(Cache)│(Messages)│ (S3) │
└──────────┘ └──────┘ └──────────┘ └──────┘
      │
      ▼
┌─────────────────────────────────────────┐
│         Workers (1, 2, 3)               │
│     (Traitement asynchrone)             │
└─────────────────────────────────────────┘
```

---

## Installation

### Étape 1 : Préparation de l'environnement

Créez un dossier dédié pour OpenCTI :

```bash
# Créer le dossier principal
mkdir ~/opencti
cd ~/opencti
```

### Étape 2 : Clonage du dépôt

Récupérez les fichiers Docker Compose officiels :

```bash
# Cloner le dépôt officiel
git clone https://github.com/OpenCTI-Platform/docker.git

# Se déplacer dans le dossier
cd docker

# Optionnel : vérifier la dernière version stable
git tag -l
# git checkout <version> si vous voulez une version spécifique
```

### Étape 3 : Configuration du fichier .env

Le fichier `.env` contient toutes les variables de configuration pour OpenCTI.

```bash
# Copier le fichier exemple
cp .env.sample .env
```

Éditez le fichier `.env` :

```bash
# Utiliser nano (ou vim, code, etc.)
nano .env
```

#### Variables obligatoires à modifier

```bash
# === IDENTIFIANTS ADMIN ===
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=VotreMotDePasseSecurise123!
OPENCTI_ADMIN_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  # Générer avec: uuidgen

# === BASE URL ===
OPENCTI_BASE_URL=http://localhost:8080

# === TOKENS DE SÉCURITÉ ===
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=VotreMotDePasseMinIO123!
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=VotreMotDePasseRabbitMQ123!

# === CONFIGURATION ELASTICSEARCH ===
ELASTIC_MEMORY_SIZE=4G  # Ajuster selon votre RAM disponible
```

#### Génération des tokens et mots de passe

```bash
# Générer un UUID pour OPENCTI_ADMIN_TOKEN
uuidgen

# Générer des mots de passe aléatoires sécurisés
openssl rand -base64 32
```

#### Configuration avancée (optionnelle)

```bash
# === WORKERS ===
WORKER_LOG_LEVEL=info  # debug, info, warning, error

# === CONNECTEURS ===
CONNECTOR_HISTORY_ENABLE=true
CONNECTOR_EXPORT_FILE_STIX_ENABLE=true
CONNECTOR_EXPORT_FILE_CSV_ENABLE=true
CONNECTOR_IMPORT_FILE_STIX_ENABLE=true
CONNECTOR_IMPORT_DOCUMENT_ENABLE=true
```

### Étape 4 : Démarrage des services

Lancez tous les conteneurs Docker :

```bash
# Démarrer tous les services en arrière-plan
docker compose up -d

# Suivre les logs en temps réel (optionnel)
docker compose logs -f
```

**Note pour Mac Apple Silicon (M1/M2/M3) :**
Vous verrez des avertissements concernant la compatibilité de plateforme (linux/amd64 vs linux/arm64). C'est normal et n'affecte pas le fonctionnement grâce à l'émulation Rosetta 2.

### Étape 5 : Temps de démarrage

Le premier démarrage peut prendre **5 à 15 minutes** selon :
- Vitesse de connexion Internet (téléchargement des images Docker)
- Puissance de votre Mac
- Initialisation d'Elasticsearch

---

## Configuration

### Structure des fichiers

```
~/opencti/docker/
├── .env                    # Configuration principale
├── docker-compose.yml      # Orchestration des services
├── data/                   # Données persistantes
│   ├── elasticsearch/
│   ├── redis/
│   └── rabbitmq/
└── volumes/
    └── minio/
```

### Variables d'environnement importantes

#### Section Plateforme

```bash
OPENCTI_PLATFORM_TITLE=OpenCTI
OPENCTI_PLATFORM_THEME=dark  # dark ou light
OPENCTI_PLATFORM_LANGUAGE=fr  # en, fr, es, de, etc.
OPENCTI_PLATFORM_LOGIN_BANNER="Plateforme de Threat Intelligence"
```

#### Section Base de données

```bash
ELASTICSEARCH_MEMORY_SIZE=4G
ELASTICSEARCH_JAVA_OPTS=-Xms4g -Xmx4g
```

#### Section Connecteurs

Pour activer/désactiver des connecteurs spécifiques :

```bash
# Import de fichiers STIX
CONNECTOR_IMPORT_FILE_STIX=true

# Import de documents (PDF, DOCX, etc.)
CONNECTOR_IMPORT_DOCUMENT=true

# Export CSV
CONNECTOR_EXPORT_FILE_CSV=true

# Export STIX
CONNECTOR_EXPORT_FILE_STIX=true
```

---

## Vérification de l'installation

### Vérifier l'état des conteneurs

```bash
# Lister tous les conteneurs
docker compose ps

# Vérifier les conteneurs en cours d'exécution
docker ps

# Vérifier la santé des conteneurs
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"
```

**Résultat attendu :**
Tous les conteneurs doivent avoir le statut `Up` et `healthy`.

```
NAME                                    STATUS              HEALTH
opencti-opencti-1                       Up 2 minutes        healthy
opencti-elasticsearch-1                 Up 2 minutes        healthy
opencti-redis-1                         Up 2 minutes        healthy
opencti-rabbitmq-1                      Up 2 minutes        healthy
opencti-minio-1                         Up 2 minutes        healthy
opencti-worker-1                        Up 2 minutes
opencti-worker-2                        Up 2 minutes
opencti-worker-3                        Up 2 minutes
```

### Vérifier les logs

```bash
# Logs de l'application principale
docker compose logs opencti

# Logs d'un service spécifique
docker compose logs elasticsearch

# Logs en temps réel de tous les services
docker compose logs -f

# Dernières 100 lignes
docker compose logs --tail=100
```

### Accéder à l'interface web

1. Ouvrez votre navigateur
2. Accédez à : **http://localhost:8080**
3. Connectez-vous avec :
   - **Email** : `admin@opencti.io` (ou celui configuré dans .env)
   - **Password** : Le mot de passe défini dans `OPENCTI_ADMIN_PASSWORD`

### Premier accès réussi

Vous devriez voir :
- Le tableau de bord OpenCTI
- Un écran de bienvenue pour configurer votre profil
- Les menus de navigation (Dashboard, Data, Analysis, etc.)

---

## Gestion des services

### Commandes de base

#### Démarrer OpenCTI

```bash
cd ~/opencti/docker
docker compose up -d
```

#### Arrêter OpenCTI

```bash
# Arrêter sans supprimer les conteneurs
docker compose stop

# Arrêter et supprimer les conteneurs (garde les données)
docker compose down

# Arrêter et supprimer TOUT (conteneurs + volumes + données)
docker compose down -v  # ⚠️ ATTENTION : supprime toutes les données !
```

#### Redémarrer OpenCTI

```bash
# Redémarrer tous les services
docker compose restart

# Redémarrer un service spécifique
docker compose restart opencti
docker compose restart elasticsearch
```

#### Voir les logs

```bash
# Tous les logs
docker compose logs

# Logs en temps réel
docker compose logs -f

# Logs d'un service spécifique
docker compose logs opencti
docker compose logs -f elasticsearch

# Dernières X lignes
docker compose logs --tail=50 opencti
```

#### Vérifier l'utilisation des ressources

```bash
# Utilisation CPU/RAM par conteneur
docker stats

# Espace disque utilisé
docker system df

# Détails des volumes
docker volume ls
```

### Gestion des workers

Les workers traitent les tâches asynchrones (imports, enrichissements, etc.).

```bash
# Voir l'état des workers
docker compose ps | grep worker

# Redémarrer un worker spécifique
docker compose restart worker-1

# Augmenter le nombre de workers (éditer docker-compose.yml)
# Puis :
docker compose up -d --scale worker=5
```

### Nettoyage et maintenance

```bash
# Nettoyer les images Docker non utilisées
docker image prune -a

# Nettoyer les volumes non utilisés
docker volume prune

# Nettoyer tout (images, conteneurs, volumes inutilisés)
docker system prune -a --volumes  # ⚠️ Prudence !

# Voir l'espace libérable
docker system df
```

---

## Configuration post-installation

### Personnalisation de l'interface

#### Changer la langue

1. Connectez-vous à OpenCTI
2. Cliquez sur votre profil (coin supérieur droit)
3. **Settings** → **Parameters** → **Language**
4. Sélectionnez votre langue (Français, English, etc.)

#### Changer le thème

1. **Settings** → **Parameters** → **Theme**
2. Choisissez entre Dark ou Light

### Configuration des connecteurs

Les connecteurs permettent d'automatiser l'import de données depuis diverses sources.

#### Connecteurs par défaut installés

- **Import File STIX** : Import de fichiers STIX 2.x
- **Import Document** : Import de PDF, DOCX, etc.
- **Export File CSV** : Export de données en CSV
- **Export File STIX** : Export au format STIX
- **Export File TXT** : Export en texte brut

#### Ajouter des connecteurs supplémentaires

Liste des connecteurs disponibles : [OpenCTI Ecosystem](https://www.notion.so/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)

**Exemples de connecteurs populaires :**
- **MITRE ATT&CK** : Import du framework ATT&CK
- **CVE** : Import des CVE
- **AlienVault OTX** : Threat intelligence d'AlienVault
- **VirusTotal** : Enrichissement via VirusTotal
- **Shodan** : Données d'exposition Internet

Pour ajouter un connecteur, éditez le fichier `docker-compose.yml` et ajoutez la configuration du connecteur souhaité.

### Gestion des utilisateurs

#### Créer un nouvel utilisateur

1. **Settings** → **Users**
2. Cliquez sur le bouton **+** (Add)
3. Remplissez les informations :
   - Nom
   - Email
   - Mot de passe
   - Rôle (Admin, User, etc.)
4. **Create**

#### Rôles et permissions

- **Administrator** : Accès complet
- **Editor** : Peut créer et modifier des données
- **Viewer** : Accès en lecture seule
- **Connector** : Pour les connecteurs uniquement

### Configuration des organisations

1. **Settings** → **Organizations**
2. Créez votre organisation
3. Assignez des utilisateurs à l'organisation

### Configuration de l'API

OpenCTI expose une API GraphQL complète.

#### Générer un token API

1. **Settings** → **Profile** → **Tokens**
2. Cliquez sur **Add**
3. Donnez un nom au token
4. Copiez et sauvegardez le token (il ne sera plus visible après)

#### Tester l'API

```bash
# Exemple avec curl
curl -X POST http://localhost:8080/graphql \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ me { name email } }"}'
```

---

## Troubleshooting

### Problèmes courants et solutions

#### 1. OpenCTI ne démarre pas

**Symptôme :** `docker compose up` échoue ou les conteneurs s'arrêtent immédiatement.

**Solutions :**

```bash
# Vérifier les logs
docker compose logs opencti
docker compose logs elasticsearch

# Vérifier que Docker Desktop est lancé
open -a Docker

# Vérifier les ressources allouées à Docker
# Docker Desktop → Preferences → Resources
# Minimum : 8GB RAM, 4 CPU cores

# Réinitialiser complètement
docker compose down -v
docker compose up -d
```

#### 2. Elasticsearch ne démarre pas

**Symptôme :** Le conteneur `elasticsearch` redémarre en boucle.

**Solutions :**

```bash
# Vérifier les logs Elasticsearch
docker compose logs elasticsearch

# Augmenter la mémoire allouée dans .env
ELASTIC_MEMORY_SIZE=4G

# Redémarrer
docker compose restart elasticsearch
```

**Erreur `max virtual memory areas vm.max_map_count [65530] is too low` :**

Sur macOS, cette erreur est généralement automatiquement gérée par Docker Desktop. Si le problème persiste :

```bash
# Redémarrer Docker Desktop
```

#### 3. Impossible de se connecter à l'interface web

**Symptôme :** `localhost:8080` ne répond pas.

**Solutions :**

```bash
# Vérifier que le conteneur OpenCTI est bien démarré
docker compose ps opencti

# Vérifier les logs
docker compose logs opencti

# Vérifier que le port 8080 n'est pas utilisé par une autre application
lsof -i :8080

# Attendre que l'initialisation soit complète (peut prendre 5-10 min)
docker compose logs -f opencti | grep "Application started"
```

#### 4. Erreurs de plateforme (linux/amd64 vs linux/arm64)

**Symptôme :** Avertissements sur la plateforme lors du `docker compose up`.

**Solution :**
Ces avertissements sont **normaux** sur Mac avec Apple Silicon (M1/M2/M3). Docker utilise Rosetta 2 pour l'émulation et tout fonctionne correctement. Vous pouvez ignorer ces messages.

#### 5. Performances lentes

**Symptôme :** L'interface est lente, les imports prennent du temps.

**Solutions :**

```bash
# Augmenter les ressources Docker
# Docker Desktop → Preferences → Resources
# Recommandé : 16GB RAM, 8 CPU cores

# Augmenter la mémoire Elasticsearch dans .env
ELASTIC_MEMORY_SIZE=6G

# Ajouter plus de workers dans docker-compose.yml
docker compose up -d --scale worker=5

# Vérifier l'utilisation des ressources
docker stats
```

#### 6. Données perdues après redémarrage

**Symptôme :** Les données disparaissent après un `docker compose down`.

**Solution :**
Ne jamais utiliser `docker compose down -v` qui supprime les volumes (données).

```bash
# Commande sûre pour arrêter
docker compose down

# Les données sont stockées dans les volumes Docker
docker volume ls | grep opencti
```

#### 7. Problèmes de connexion RabbitMQ

**Symptôme :** Les workers ne peuvent pas se connecter à RabbitMQ.

**Solutions :**

```bash
# Vérifier RabbitMQ
docker compose logs rabbitmq

# Redémarrer RabbitMQ
docker compose restart rabbitmq

# Accéder à l'interface RabbitMQ
open http://localhost:15672
# Login: opencti / Mot de passe configuré dans .env
```

#### 8. Elasticsearch "Cluster health is RED"

**Symptôme :** Elasticsearch signale un état de cluster RED.

**Solutions :**

```bash
# Vérifier l'état du cluster
curl http://localhost:9200/_cluster/health?pretty

# Redémarrer Elasticsearch
docker compose restart elasticsearch

# En dernier recours : réinitialiser les données Elasticsearch
docker compose down
docker volume rm opencti_esdata
docker compose up -d
```

### Commandes de diagnostic

```bash
# État complet du système
docker compose ps
docker stats --no-stream
docker system df

# Vérifier la connectivité réseau
docker compose exec opencti ping elasticsearch
docker compose exec opencti ping redis
docker compose exec opencti ping rabbitmq

# Vérifier les ports
lsof -i :8080
lsof -i :9200
lsof -i :5672

# Espace disque
df -h
docker system df -v
```

---

## Sécurité

### Bonnes pratiques de sécurité

#### 1. Mots de passe forts

Utilisez toujours des mots de passe complexes pour :
- `OPENCTI_ADMIN_PASSWORD`
- `MINIO_ROOT_PASSWORD`
- `RABBITMQ_DEFAULT_PASS`

```bash
# Générer un mot de passe sécurisé
openssl rand -base64 32
```

#### 2. Changement régulier des tokens

Changez régulièrement :
- `OPENCTI_ADMIN_TOKEN`
- Les tokens API des utilisateurs

#### 3. Limitation d'accès réseau

**Pour un usage local uniquement :**
L'installation par défaut est sécurisée car accessible uniquement via `localhost`.

**Pour une exposition sur le réseau :**

```bash
# Ne PAS exposer directement sur Internet sans reverse proxy
# Utiliser un reverse proxy (Nginx, Caddy, Traefik) avec HTTPS

# Exemple de configuration avec Traefik (à ajouter dans docker-compose.yml)
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.opencti.rule=Host(`opencti.votredomaine.com`)"
  - "traefik.http.routers.opencti.entrypoints=websecure"
  - "traefik.http.routers.opencti.tls.certresolver=letsencrypt"
```

#### 4. Mise à jour régulière

Gardez OpenCTI et ses dépendances à jour :

```bash
cd ~/opencti/docker
git pull
docker compose pull
docker compose up -d
```

#### 5. Surveillance des logs

Surveillez régulièrement les logs pour détecter des activités suspectes :

```bash
# Surveiller les tentatives de connexion
docker compose logs opencti | grep "authentication"

# Surveiller les erreurs
docker compose logs --since 1h | grep ERROR
```

#### 6. Sauvegarde chiffrée

Chiffrez toujours vos sauvegardes :

```bash
# Exemple avec OpenSSL
tar czf - ~/opencti-backup | openssl enc -aes-256-cbc -salt -out opencti-backup.tar.gz.enc
```

#### 7. Pare-feu

Configurez le pare-feu macOS pour n'autoriser que les connexions nécessaires :

```bash
# Activer le pare-feu macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

### Configuration HTTPS (production)

Pour une installation en production, configurez HTTPS avec un certificat SSL :

#### Option 1 : Avec Caddy (recommandé pour sa simplicité)

Créez un fichier `Caddyfile` :

```
opencti.votredomaine.com {
    reverse_proxy localhost:8080
}
```

#### Option 2 : Avec Nginx

Créez un fichier de configuration Nginx :

```nginx
server {
    listen 443 ssl http2;
    server_name opencti.votredomaine.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Sauvegarde et restauration

### Stratégie de sauvegarde

OpenCTI stocke ses données dans plusieurs volumes Docker :
- **Elasticsearch** : Base de données principale
- **MinIO** : Fichiers et objets
- **Redis** : Cache (optionnel à sauvegarder)
- **RabbitMQ** : Files de messages (optionnel)

### Sauvegarde complète

#### Script de sauvegarde automatique

Créez un script `backup.sh` :

```bash
#!/bin/bash

# Configuration
BACKUP_DIR=~/opencti-backups
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH=$BACKUP_DIR/opencti-backup-$DATE

# Créer le dossier de sauvegarde
mkdir -p $BACKUP_PATH

echo "Démarrage de la sauvegarde OpenCTI..."

# Arrêter les workers pour éviter les modifications pendant la sauvegarde
cd ~/opencti/docker
docker compose stop worker-1 worker-2 worker-3

# Sauvegarde des volumes Docker
echo "Sauvegarde d'Elasticsearch..."
docker run --rm \
  -v opencti_esdata:/data \
  -v $BACKUP_PATH:/backup \
  alpine tar czf /backup/elasticsearch.tar.gz -C /data .

echo "Sauvegarde de MinIO..."
docker run --rm \
  -v opencti_s3data:/data \
  -v $BACKUP_PATH:/backup \
  alpine tar czf /backup/minio.tar.gz -C /data .

echo "Sauvegarde de Redis..."
docker run --rm \
  -v opencti_redisdata:/data \
  -v $BACKUP_PATH:/backup \
  alpine tar czf /backup/redis.tar.gz -C /data .

# Copier le fichier .env
echo "Sauvegarde de la configuration..."
cp ~/opencti/docker/.env $BACKUP_PATH/

# Redémarrer les workers
docker compose start worker-1 worker-2 worker-3

# Compresser l'ensemble
echo "Compression de la sauvegarde..."
cd $BACKUP_DIR
tar czf opencti-backup-$DATE.tar.gz opencti-backup-$DATE/
rm -rf opencti-backup-$DATE/

echo "Sauvegarde terminée : $BACKUP_DIR/opencti-backup-$DATE.tar.gz"
echo "Taille : $(du -h $BACKUP_DIR/opencti-backup-$DATE.tar.gz | cut -f1)"
```

Rendez le script exécutable :

```bash
chmod +x backup.sh
```

Exécutez la sauvegarde :

```bash
./backup.sh
```

#### Sauvegarde planifiée avec cron

Créez une tâche cron pour des sauvegardes automatiques :

```bash
# Éditer le crontab
crontab -e

# Ajouter une sauvegarde quotidienne à 2h du matin
0 2 * * * /Users/votre-utilisateur/opencti/backup.sh >> /Users/votre-utilisateur/opencti/backup.log 2>&1

# Sauvegarde hebdomadaire le dimanche à 3h
0 3 * * 0 /Users/votre-utilisateur/opencti/backup.sh
```

### Restauration

#### Script de restauration

Créez un script `restore.sh` :

```bash
#!/bin/bash

# Configuration
BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: ./restore.sh <chemin-vers-backup.tar.gz>"
    exit 1
fi

echo "ATTENTION : Cette opération va écraser les données actuelles !"
echo "Fichier de sauvegarde : $BACKUP_FILE"
read -p "Êtes-vous sûr de vouloir continuer ? (oui/non) : " confirm

if [ "$confirm" != "oui" ]; then
    echo "❌ Restauration annulée"
    exit 0
fi

# Créer un dossier temporaire
TEMP_DIR=$(mktemp -d)
echo "Extraction vers $TEMP_DIR..."
tar xzf $BACKUP_FILE -C $TEMP_DIR

RESTORE_DIR=$(find $TEMP_DIR -name "opencti-backup-*" -type d)

# Arrêter OpenCTI
echo "Arrêt d'OpenCTI..."
cd ~/opencti/docker
docker compose down

# Restaurer les volumes
echo "Restauration d'Elasticsearch..."
docker run --rm \
  -v opencti_esdata:/data \
  -v $RESTORE_DIR:/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/elasticsearch.tar.gz -C /data"

echo "Restauration de MinIO..."
docker run --rm \
  -v opencti_s3data:/data \
  -v $RESTORE_DIR:/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/minio.tar.gz -C /data"

echo "Restauration de Redis..."
docker run --rm \
  -v opencti_redisdata:/data \
  -v $RESTORE_DIR:/backup \
  alpine sh -c "rm -rf /data/* && tar xzf /backup/redis.tar.gz -C /data"

# Restaurer le fichier .env
echo "Restauration de la configuration..."
cp $RESTORE_DIR/.env ~/opencti/docker/

# Nettoyer
rm -rf $TEMP_DIR

# Redémarrer OpenCTI
echo "Redémarrage d'OpenCTI..."
docker compose up -d

echo "Restauration terminée !"
echo "Attendez quelques minutes que tous les services démarrent..."
```

Rendez le script exécutable :

```bash
chmod +x restore.sh
```

Restaurez une sauvegarde :

```bash
./restore.sh ~/opencti-backups/opencti-backup-20250101_020000.tar.gz
```

### Sauvegarde vers le cloud

#### Sauvegarde vers AWS S3

```bash
# Installer AWS CLI
brew install awscli

# Configurer AWS CLI
aws configure

# Script de sauvegarde vers S3
#!/bin/bash
./backup.sh
aws s3 cp ~/opencti-backups/opencti-backup-$(date +%Y%m%d)*.tar.gz \
  s3://votre-bucket/opencti-backups/
```

#### Sauvegarde vers Google Drive

```bash
# Installer rclone
brew install rclone

# Configurer rclone avec Google Drive
rclone config

# Script de sauvegarde
#!/bin/bash
./backup.sh
rclone copy ~/opencti-backups/ gdrive:OpenCTI-Backups/
```

---

## Mise à jour

### Vérifier la version actuelle

```bash
# Version dans l'interface web
# Settings → About → Version

# Version dans le conteneur
docker compose exec opencti cat /opt/opencti/VERSION
```

### Procédure de mise à jour

#### 1. Sauvegarder avant la mise à jour

```bash
# TOUJOURS faire une sauvegarde avant de mettre à jour
./backup.sh
```

#### 2. Mettre à jour le dépôt

```bash
cd ~/opencti/docker

# Récupérer les dernières modifications
git fetch --all --tags

# Voir les versions disponibles
git tag -l

# Voir la version actuelle
git describe --tags

# Passer à une version spécifique (recommandé)
git checkout tags/v5.12.0  # Exemple

# Ou passer à la dernière version (moins sûr)
git checkout master
git pull
```

#### 3. Mettre à jour les images Docker

```bash
# Télécharger les nouvelles images
docker compose pull

# Recréer les conteneurs avec les nouvelles images
docker compose up -d
```

#### 4. Vérifier la mise à jour

```bash
# Vérifier les logs
docker compose logs -f opencti

# Vérifier la version
docker compose exec opencti cat /opt/opencti/VERSION

# Accéder à l'interface web
open http://localhost:8080
```

### Mise à jour du fichier .env

Lors d'une mise à jour, comparez votre `.env` avec le nouveau `.env.sample` :

```bash
# Voir les différences
diff .env .env.sample

# Ou utiliser un outil visuel
code --diff .env .env.sample
```

Ajoutez les nouvelles variables nécessaires à votre `.env`.

### Rollback en cas de problème

Si la mise à jour pose problème :

```bash
# Revenir à la version précédente
cd ~/opencti/docker
git checkout tags/v5.11.0  # Version précédente

# Ou restaurer depuis une sauvegarde
./restore.sh ~/opencti-backups/opencti-backup-20250101_020000.tar.gz
```

### Mise à jour automatique (non recommandé pour la production)

Pour une installation de test, vous pouvez activer les mises à jour automatiques avec Watchtower :

```yaml
# Ajouter dans docker-compose.yml
watchtower:
  image: containrrr/watchtower
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  command: --interval 86400  # Vérifier toutes les 24h
```

**Attention** : Non recommandé en production sans tests préalables.

---

## Ressources utiles

### Documentation officielle

- **Site officiel** : [https://www.opencti.io](https://www.opencti.io)
- **Documentation** : [https://docs.opencti.io](https://docs.opencti.io)
- **GitHub** : [https://github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti)
- **Docker Hub** : [https://hub.docker.com/u/opencti](https://hub.docker.com/u/opencti)

### Communauté

- **Slack** : [https://community.filigran.io](https://community.filigran.io)
- **Forum** : [https://github.com/OpenCTI-Platform/opencti/discussions](https://github.com/OpenCTI-Platform/opencti/discussions)
- **Twitter** : [@OpenCTI_io](https://twitter.com/OpenCTI_io)

### Connecteurs et intégrations

- **Liste des connecteurs** : [OpenCTI Ecosystem](https://www.notion.so/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)
- **Développer un connecteur** : [https://docs.opencti.io/latest/development/connectors/](https://docs.opencti.io/latest/development/connectors/)

### Formation et tutoriels

- **Formation officielle** : [https://training.filigran.io](https://training.filigran.io)
- **Vidéos YouTube** : [Chaîne OpenCTI](https://www.youtube.com/@OpenCTI)
- **Blog Filigran** : [https://blog.filigran.io](https://blog.filigran.io)

### API et développement

- **API GraphQL Playground** : http://localhost:8080/graphql
- **Documentation API** : [https://docs.opencti.io/latest/deployment/integrations](https://docs.opencti.io/latest/deployment/integrations)
- **SDK Python** : [pycti](https://github.com/OpenCTI-Platform/client-python)

### Threat Intelligence

- **MISP** : [https://www.misp-project.org](https://www.misp-project.org)
- **STIX 2.1** : [https://oasis-open.github.io/cti-documentation/](https://oasis-open.github.io/cti-documentation/)
- **MITRE ATT&CK** : [https://attack.mitre.org](https://attack.mitre.org)
- **AlienVault OTX** : [https://otx.alienvault.com](https://otx.alienvault.com)

### Outils complémentaires

- **TheHive** : Plateforme de gestion d'incidents compatible avec OpenCTI
- **Cortex** : Moteur d'analyse et d'enrichissement
- **MISP** : Plateforme de partage de threat intelligence

---

## Annexes

### Annexe A : Commandes Docker utiles

```bash
# === CONTENEURS ===
# Lister tous les conteneurs
docker ps -a

# Lister uniquement les conteneurs en cours d'exécution
docker ps

# Démarrer un conteneur
docker start <nom-conteneur>

# Arrêter un conteneur
docker stop <nom-conteneur>

# Redémarrer un conteneur
docker restart <nom-conteneur>

# Supprimer un conteneur
docker rm <nom-conteneur>

# === IMAGES ===
# Lister les images
docker images

# Supprimer une image
docker rmi <nom-image>

# Télécharger une image
docker pull <nom-image>

# === VOLUMES ===
# Lister les volumes
docker volume ls

# Inspecter un volume
docker volume inspect <nom-volume>

# Supprimer un volume
docker volume rm <nom-volume>

# === LOGS ===
# Voir les logs d'un conteneur
docker logs <nom-conteneur>

# Suivre les logs en temps réel
docker logs -f <nom-conteneur>

# Dernières N lignes
docker logs --tail=100 <nom-conteneur>

# === EXÉCUTION ===
# Exécuter une commande dans un conteneur
docker exec <nom-conteneur> <commande>

# Ouvrir un shell dans un conteneur
docker exec -it <nom-conteneur> /bin/bash

# === RESSOURCES ===
# Utilisation des ressources
docker stats

# Espace disque
docker system df

# === NETTOYAGE ===
# Nettoyer les conteneurs arrêtés
docker container prune

# Nettoyer les images inutilisées
docker image prune -a

# Nettoyer les volumes inutilisés
docker volume prune

# Nettoyer tout
docker system prune -a --volumes
```

### Annexe B : Ports utilisés par OpenCTI

| Service | Port interne | Port exposé | Description |
|---------|--------------|-------------|-------------|
| OpenCTI | 8080 | 8080 | Interface web |
| Elasticsearch | 9200, 9300 | - | Base de données |
| Redis | 6379 | - | Cache |
| RabbitMQ | 5672 | - | Message broker |
| RabbitMQ Management | 15672 | 15672 | Interface d'admin RabbitMQ |
| MinIO | 9000 | - | Stockage S3 |
| MinIO Console | 9001 | 9001 | Interface MinIO |

### Annexe C : Structure de la base de données

OpenCTI utilise Elasticsearch avec les index suivants :

```
opencti-*                  # Données principales
opencti-history-*          # Historique des modifications
opencti-internal-*         # Données internes
opencti-files-*            # Métadonnées de fichiers
```

### Annexe D : Variables d'environnement complètes

Voici une liste exhaustive des variables importantes :

```bash
# === APPLICATION ===
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMe
OPENCTI_ADMIN_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENCTI_BASE_URL=http://localhost:8080

# === PLATEFORME ===
OPENCTI_PLATFORM_TITLE=OpenCTI
OPENCTI_PLATFORM_THEME=dark
OPENCTI_PLATFORM_LANGUAGE=en
OPENCTI_PLATFORM_LOGIN_BANNER=
OPENCTI_PLATFORM_BANNER_LEVEL=info
OPENCTI_PLATFORM_BANNER_TEXT=

# === ELASTICSEARCH ===
ELASTICSEARCH_URL=http://elasticsearch:9200
ELASTIC_MEMORY_SIZE=4G

# === REDIS ===
REDIS_HOSTNAME=redis
REDIS_PORT=6379
REDIS_MODE=standalone

# === RABBITMQ ===
RABBITMQ_HOSTNAME=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_MANAGEMENT_PORT=15672
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=ChangeMe

# === MINIO (S3) ===
MINIO_ENDPOINT=minio
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=ChangeMe
MINIO_BUCKET_NAME=opencti-bucket

# === WORKERS ===
WORKER_LOG_LEVEL=info

# === CONNECTEURS ===
CONNECTOR_EXPORT_FILE_STIX=true
CONNECTOR_EXPORT_FILE_CSV=true
CONNECTOR_EXPORT_FILE_TXT=true
CONNECTOR_IMPORT_FILE_STIX=true
CONNECTOR_IMPORT_DOCUMENT=true
```

### Annexe E : Checklist de sécurité

- [ ] Mots de passe forts définis
- [ ] Tokens sécurisés générés
- [ ] Fichier .env non partagé/committé
- [ ] Sauvegarde automatique configurée
- [ ] Mise à jour régulière planifiée
- [ ] Logs surveillés
- [ ] Accès réseau limité
- [ ] HTTPS configuré (si exposition)
- [ ] Utilisateurs avec rôles appropriés
- [ ] Tokens API révoqués si compromis

### Annexe F : FAQ

**Q : Puis-je utiliser OpenCTI en production sur Mac ?**
R : Mac est idéal pour le développement et les tests. Pour la production, préférez Linux sur un serveur dédié.

**Q : Combien de RAM faut-il minimum ?**
R : 8 GB minimum, 16 GB recommandés pour une utilisation confortable.

**Q : Peut-on arrêter OpenCTI sans perdre les données ?**
R : Oui, utilisez `docker compose stop` ou `docker compose down` (sans le flag `-v`).

**Q : Comment augmenter les performances ?**
R : Augmentez la RAM allouée à Docker, ajoutez des workers, et utilisez un SSD.

**Q : OpenCTI est-il gratuit ?**
R : Oui, OpenCTI est open-source (AGPL-3.0). Une version Enterprise payante existe avec support.

**Q : Peut-on importer des données depuis MISP ?**
R : Oui, via le connecteur MISP disponible dans l'écosystème OpenCTI.

**Q : Comment changer le port 8080 ?**
R : Modifiez le fichier `docker-compose.yml` dans la section `ports` du service `opencti`.

---

## Conclusion

Vous disposez maintenant d'une installation complète et fonctionnelle d'OpenCTI sur votre Mac. Cette documentation couvre l'ensemble du cycle de vie de votre plateforme, de l'installation à la maintenance quotidienne.

### Prochaines étapes recommandées

1. **Explorer l'interface** : Familiarisez-vous avec les différentes sections
2. **Créer des organisations et utilisateurs** : Structurez votre équipe
3. **Installer des connecteurs** : MITRE ATT&CK, CVE, etc.
4. **Importer des données** : Commencez à alimenter votre plateforme
5. **Configurer les sauvegardes** : Automatisez la protection de vos données

### Support

Pour toute question ou problème :
- Consultez la [documentation officielle](https://docs.opencti.io)
- Rejoignez le [Slack communautaire](https://community.filigran.io)
- Ouvrez une issue sur [GitHub](https://github.com/OpenCTI-Platform/opencti/issues)

---
