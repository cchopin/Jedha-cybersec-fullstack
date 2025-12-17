# Todo App - Guide de déploiement sécurisé

Application Todo basée sur Flask déployée avec Docker, Nginx, PostgreSQL et HTTPS.

## Architecture

Cette architecture de déploiement se compose de trois services principaux :

- **Base de données PostgreSQL** : Postgres 15 pour la persistance des données
- **Application Flask** : Application web Python 3.11 exécutée avec Gunicorn
- **Reverse Proxy Nginx** : Gère HTTPS, les en-têtes de sécurité et le proxy

## Structure du projet

```
.
├── app/
│   ├── __init__.py          # Factory de l'application Flask
│   ├── models.py            # Modèles de base de données
│   ├── routes.py            # Routes de l'application
│   └── templates/           # Templates HTML
├── nginx/
│   ├── nginx.conf           # Configuration Nginx
│   └── certs/               # Certificats SSL
│       ├── cert.pem
│       └── key.pem
├── Dockerfile               # Définition du conteneur Flask
├── docker-compose.yml       # Orchestration multi-conteneurs
├── requirements.txt         # Dépendances Python
├── run.py                   # Point d'entrée de l'application
└── README.md               # Ce fichier
```

## Prérequis

- Docker (version 20.10 ou supérieure)
- Docker Compose (version 2.0 ou supérieure)
- mkcert (pour générer les certificats SSL locaux)

## Variables d'environnement

L'application Flask nécessite ces variables d'environnement (configurées dans docker-compose.yml) :

- `FLASK_APP=run.py`
- `FLASK_ENV=development`
- `SECRET_KEY=dev_key_todo_app_2025`
- `DATABASE_URL=postgresql://postgres:postgres@db:5432/todo_db`

## Fonctionnalités de sécurité

### Configuration HTTPS
- TLS 1.2 et TLS 1.3 uniquement
- Suites de chiffrement robustes
- Redirection automatique HTTP vers HTTPS
- Support HTTP/2

### En-têtes de sécurité
- **Strict-Transport-Security** : Force HTTPS pendant 1 an
- **X-Content-Type-Options** : Empêche le MIME-sniffing
- **X-Frame-Options** : Empêche les attaques clickjacking
- **X-XSS-Protection** : Active le filtrage XSS
- **Referrer-Policy** : Contrôle les informations de référence
- **Content-Security-Policy** : Restreint le chargement des ressources
- **Permissions-Policy** : Restreint les fonctionnalités du navigateur

### Sécurité additionnelle
- Tokens serveur désactivés (cache la version Nginx)
- Taille du corps de requête limitée à 10MB
- Health checks de la base de données
- Politiques de redémarrage des conteneurs
- Isolation réseau via réseau bridge Docker

## Instructions de déploiement

### Étape 1 : Cloner ou préparer le projet

Assurez-vous d'avoir tous les fichiers du projet dans votre répertoire de travail.

### Étape 2 : Configurer le fichier hosts

Ajoutez `todo-app.local` à votre fichier `/etc/hosts` :

```bash
echo "127.0.0.1 todo-app.local" | sudo tee -a /etc/hosts
```

Pour vérifier :
```bash
ping todo-app.local
```

### Étape 3 : Générer les certificats SSL

Installez mkcert et générez les certificats SSL :

```bash
# Installer mkcert
brew install mkcert

# Installer l'autorité de certification locale
mkcert -install

# Créer le répertoire des certificats
mkdir -p nginx/certs

# Générer les certificats pour todo-app.local
mkcert -key-file ./nginx/certs/key.pem -cert-file ./nginx/certs/cert.pem "todo-app.local"
```

**Note** : mkcert crée des certificats de développement automatiquement acceptés par votre système. Pour la production, utilisez des certificats d'une autorité de certification (CA) comme Let's Encrypt.

### Étape 4 : Construire et démarrer les services

Construisez les images Docker et démarrez tous les services :

```bash
docker-compose up -d --build
```

Cette commande va :
1. Construire l'image Docker de l'application Flask
2. Télécharger les images PostgreSQL 15 et Nginx
3. Créer un réseau Docker pour la communication entre services
4. Démarrer la base de données avec health checks
5. Démarrer l'application Flask (attend que la base soit prête)
6. Démarrer le reverse proxy Nginx

### Étape 5 : Vérifier que les services sont actifs

Vérifiez le statut de tous les conteneurs :

```bash
docker-compose ps
```

Vous devriez voir trois conteneurs en cours d'exécution :
- `todo_postgres` - Base de données PostgreSQL
- `todo_flask_app` - Application Flask
- `todo_nginx` - Reverse proxy Nginx

### Étape 6 : Consulter les logs (optionnel)

Pour surveiller les logs de l'application :

```bash
# Tous les services
docker-compose logs -f

# Service spécifique
docker-compose logs -f flask_app
docker-compose logs -f nginx
docker-compose logs -f db
```

### Étape 7 : Accéder à l'application

Ouvrez votre navigateur et naviguez vers :

```
https://todo-app.local/
```

**Note** : Comme nous utilisons des certificats auto-signés, votre navigateur affichera un avertissement de sécurité. C'est normal. Cliquez sur "Avancé" et continuez vers le site.

L'application va :
1. Rediriger HTTP (port 80) vers HTTPS (port 443)
2. Afficher l'interface de l'application Todo
3. Permettre d'ajouter, compléter et supprimer des tâches

![Interface de l'application Todo](assets/todo-app-interface.png)

### Étape 8 : Tester la connexion à la base de données

L'application Flask automatiquement :
- Se connecte à la base de données PostgreSQL
- Crée les tables nécessaires au premier lancement
- Persiste les données dans un volume Docker (`postgres_data`)

Ajoutez un élément todo pour vérifier que la base de données fonctionne correctement.

### Étape 9 : Vérifier les en-têtes de sécurité

Testez les en-têtes de sécurité avec curl :

```bash
curl -I https://todo-app.local
```

Vous devriez voir des en-têtes comme :
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`

![Vérification des en-têtes de sécurité avec curl](assets/security-headers-curl.png)

## Comprendre l'option --build

### Différence entre les commandes

#### Sans --build :
```bash
docker-compose up -d
```
- Utilise les images Docker existantes (en cache)
- Si l'image n'existe pas, elle sera construite
- Plus rapide car ne reconstruit pas les images existantes
- **Problème** : Si vous modifiez le code, le Dockerfile ou requirements.txt, les changements ne seront PAS pris en compte

#### Avec --build :
```bash
docker-compose up -d --build
```
- Force la reconstruction de toutes les images définies avec `build:` dans docker-compose.yml
- Prend en compte toutes les modifications du code, Dockerfile, requirements.txt, etc.
- Plus lent car reconstruit même si l'image existe déjà
- **Recommandé** quand vous avez fait des changements

### Quand utiliser --build ?

| Situation | Commande recommandée |
|-----------|---------------------|
| Premier déploiement | `docker-compose up -d --build` |
| Modification du code Python (app/*.py) | `docker-compose up -d --build` |
| Modification du Dockerfile | `docker-compose up -d --build` |
| Modification de requirements.txt | `docker-compose up -d --build` |
| Redémarrage simple (sans changements) | `docker-compose restart` |
| Modification de nginx.conf uniquement | `docker-compose restart nginx` |

### Reconstruire un service spécifique

Si vous avez modifié seulement l'application Flask :

```bash
# Reconstruire seulement flask_app
docker-compose up -d --build flask_app

# Ou en 2 étapes
docker-compose build flask_app
docker-compose up -d
```

## Configuration avancée

### Ajouter le certificat SSL au Keychain macOS (avec mkcert)

Si vous utilisez `mkcert` pour générer les certificats (recommandé), l'installation des certificats se fait automatiquement :

```bash
# Installer mkcert (si pas déjà fait)
brew install mkcert

# Installer l'autorité de certification locale dans votre système
mkcert -install

# Générer les certificats pour todo-app.local
mkcert -key-file ./nginx/certs/key.pem -cert-file ./nginx/certs/cert.pem "todo-app.local"
```

Après cette opération :
- Votre navigateur acceptera automatiquement les certificats sans avertissement
- curl fonctionnera sans l'option `-k`
- Le certificat sera valide pour tous les navigateurs

Pour vérifier que cela fonctionne :
```bash
curl -I https://todo-app.local
```

#### Méthode alternative : ajout manuel au Keychain (sans mkcert)

Si vous n'utilisez pas mkcert et avez généré les certificats avec OpenSSL :

1. Double-cliquez sur le fichier `nginx/certs/cert.pem` dans le Finder
2. L'application "Trousseaux d'accès" s'ouvre automatiquement
3. Trouvez le certificat "todo-app.local" dans la liste
4. Double-cliquez sur le certificat
5. Dépliez la section "Se fier"
6. Changez "Lors de l'utilisation de ce certificat" à "Toujours faire confiance"
7. Fermez la fenêtre (vous devrez entrer votre mot de passe administrateur)

Ou via la ligne de commande :
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain nginx/certs/cert.pem
```

#### Retirer le certificat du Keychain

Pour désinstaller les certificats mkcert :

```bash
mkcert -uninstall
```

Ou pour retirer manuellement un certificat spécifique :

```bash
sudo security delete-certificate -c "todo-app.local" /Library/Keychains/System.keychain
```

Via l'interface graphique :
1. Ouvrez "Trousseaux d'accès"
2. Sélectionnez "Système" dans la barre latérale
3. Trouvez le certificat "todo-app.local"
4. Clic droit > Supprimer

**Note** : Cette configuration est adaptée au développement local uniquement. En production, utilisez toujours des certificats signés par une autorité de certification reconnue (comme Let's Encrypt).

## Commandes de gestion

### Arrêter l'application

```bash
docker-compose down
```

### Arrêter et supprimer toutes les données (y compris la base)

```bash
docker-compose down -v
```

**Attention** : Cela supprimera tous les éléments todo de la base de données.

### Redémarrer un service spécifique

```bash
docker-compose restart flask_app
```

### Reconstruire après des modifications du code

```bash
docker-compose up -d --build flask_app
```

### Accéder à la base de données

Se connecter directement à la base de données PostgreSQL :

```bash
docker-compose exec db psql -U postgres -d todo_db
```

Commandes SQL utiles :
```sql
-- Lister toutes les tables
\dt

-- Voir tous les todos
SELECT * FROM todo;

-- Quitter
\q
```

### Voir les logs de l'application en temps réel

```bash
docker-compose logs -f flask_app
```

## Dépannage

### Le conteneur ne démarre pas

Vérifiez les logs :
```bash
docker-compose logs flask_app
```

### Problèmes de connexion à la base de données

1. Assurez-vous que la base de données est en bonne santé :
```bash
docker-compose ps
```

2. Vérifiez les logs de la base :
```bash
docker-compose logs db
```

3. Vérifiez que la variable `DATABASE_URL` correspond à la configuration de la base.

### Erreurs SSL de Nginx

1. Vérifiez que les certificats existent :
```bash
ls -l nginx/certs/
```

2. Régénérez les certificats si nécessaire (voir Étape 2).

### Port déjà utilisé

Si les ports 80 ou 443 sont déjà utilisés, modifiez `docker-compose.yml` :

```yaml
nginx:
  ports:
    - "8080:80"
    - "8443:443"
```

Puis accédez à l'application via `https://todo-app.local:8443`

### Erreurs de permission

Assurez-vous que Docker a les permissions pour lire les fichiers de configuration :
```bash
chmod -R 755 nginx/
chmod 644 nginx/nginx.conf
chmod 644 nginx/certs/*
```

## Considérations pour la production

Pour un déploiement en production, considérez ces améliorations :

1. **Utiliser de vrais certificats SSL** : Remplacez les certificats auto-signés par des certificats CA (Let's Encrypt).

2. **Variables d'environnement** : Stockez les secrets dans des fichiers d'environnement ou des systèmes de gestion de secrets.

3. **Changer les mots de passe par défaut** : Mettez à jour le mot de passe PostgreSQL et la clé secrète Flask.

4. **Sauvegardes de la base** : Implémentez une stratégie de sauvegarde régulière pour les données PostgreSQL.

5. **Monitoring** : Ajoutez des solutions de monitoring et de logging.

6. **Mettre à jour FLASK_ENV** : Changez en `production` dans docker-compose.yml.

7. **Limites de ressources** : Ajoutez des limites CPU et mémoire dans docker-compose.yml :
```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
```

8. **Configuration CORS** : Configurez les en-têtes CORS si nécessaire pour l'accès API.

9. **Rate limiting** : Implémentez du rate limiting dans Nginx pour prévenir les abus.

10. **Mises à jour régulières** : Gardez les images Docker et les dépendances à jour.

## Dépendances

### Packages Python (requirements.txt)
- Flask==2.3.3
- Flask-SQLAlchemy==3.1.1
- psycopg2-binary==2.9.7
- python-dotenv==1.0.0
- gunicorn==21.2.0

### Images Docker
- python:3.11-slim (Base de l'application Flask)
- postgres:15-alpine (Base de données)
- nginx:1.25-alpine (Reverse proxy)

## Fonctionnalités de l'application

- Créer de nouveaux éléments todo
- Marquer les éléments comme complétés/non complétés
- Supprimer des éléments todo
- Stockage persistant avec PostgreSQL
- Interface web responsive


## Support

1. Vérifiez les logs : `docker-compose logs`
2. Vérifiez que tous les services sont actifs : `docker-compose ps`



