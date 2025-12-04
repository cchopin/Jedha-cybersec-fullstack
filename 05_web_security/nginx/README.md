# Crypto Tavern - Infrastructure Docker + Nginx + Flask + HTTPS

## Description

Application Flask sécurisée déployée avec Docker, Nginx comme reverse proxy, et HTTPS via mkcert. Ce projet démontre une configuration production-ready pour servir une application web Python avec SSL/TLS.

## Architecture

```
Browser (HTTPS) → Nginx (port 443) → Gunicorn → Flask Application
                     ↓
                Static Files (landing page)
```

### Composants

1. **Flask Application** : Application web Python avec Gunicorn comme WSGI server
2. **Nginx** : Reverse proxy et serveur de fichiers statiques
3. **Docker Compose** : Orchestration des conteneurs
4. **HTTPS** : Certificats SSL générés avec mkcert

## Structure du Projet

```
.
├── app/
│   ├── __init__.py              # Initialisation Flask avec Blueprint
│   ├── routes.py                # Routes de l'application (/app/login, /app/tavern, /app/logout)
│   ├── static/
│   │   ├── css/app.css          # Styles de l'application
│   │   └── js/app.js            # JavaScript
│   └── templates/
│       ├── base.html            # Template de base
│       ├── login.html           # Page de connexion
│       ├── tavern.html          # Page principale (marketplace crypto)
│       └── error.html           # Page d'erreur
├── nginx/
│   ├── nginx.conf               # Configuration Nginx
│   └── certs/
│       ├── cert.pem             # Certificat SSL
│       └── key.pem              # Clé privée SSL
├── static_site/
│   └── index.html               # Landing page statique
├── Dockerfile                   # Construction de l'image Flask
├── docker-compose.yml           # Orchestration Docker
├── requirements.txt             # Dépendances Python
└── run.py                       # Point d'entrée de l'application
```

## Prérequis

- Docker et Docker Compose installés
- mkcert installé (pour les certificats SSL en local)
- Entrée dans `/etc/hosts` : `127.0.0.1  crypto-tavern.local`

### Installation de mkcert

```bash
# macOS
brew install mkcert

# Installer le CA local
mkcert -install
```

## Configuration

### 1. Génération des Certificats SSL

Les certificats sont déjà générés dans `nginx/certs/`. Pour les régénérer :

```bash
mkcert -key-file ./nginx/certs/key.pem -cert-file ./nginx/certs/cert.pem "crypto-tavern.local"
```

### 2. Modification du fichier hosts

Ajouter cette ligne à `/etc/hosts` :

```
127.0.0.1  crypto-tavern.local
```

### 3. Configuration Docker

**docker-compose.yml** : Définit deux services

- **nginx** : Port 80 (HTTP) et 443 (HTTPS)
  - Monte nginx.conf, static_site, app/static et les certificats SSL
  - Dépend de flask_app

- **flask_app** : Application Flask avec Gunicorn
  - Écoute sur le port 5001
  - Variables d'environnement : `APPLICATION_ROOT=/app`

**Dockerfile** : Construction de l'image Flask

```dockerfile
FROM python:3.11-slim
WORKDIR /app

# Installation de gcc pour les dépendances Python avec extensions C
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code applicatif
COPY app/ ./app/
COPY run.py .

EXPOSE 5001

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "run:app"]
```

### 4. Configuration Nginx

**nginx/nginx.conf** : Configuration détaillée

```nginx
events {
    worker_connections 1024;
}

http {
    # Inclusion des types MIME
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Configuration SSL globale
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Serveur HTTP : Redirection vers HTTPS
    server {
        listen 80;
        server_name crypto-tavern.local;
        return 301 https://$host$request_uri;
    }

    # Serveur HTTPS
    server {
        listen 443 ssl;
        server_name crypto-tavern.local;

        # Landing page statique à la racine
        location / {
            root /usr/share/nginx/html/static_site;
            try_files $uri $uri/ =404;
        }

        # Reverse proxy vers Flask
        location /app/ {
            proxy_pass http://flask_app:5001;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Fichiers statiques de Flask servis directement par Nginx
        location /app/static/ {
            alias /usr/share/nginx/html/app/static/;
        }
    }
}
```

#### Points clés de la configuration Nginx

1. **Redirection HTTP vers HTTPS** : Tout le trafic HTTP est automatiquement redirigé vers HTTPS
2. **Reverse Proxy** : Les requêtes `/app/*` sont proxifiées vers le conteneur Flask (gunicorn sur port 5001)
3. **Fichiers Statiques** : Nginx sert directement les fichiers CSS/JS sans passer par Flask (performance)
4. **Headers de Proxy** : Préservation de l'IP client et du protocole original

### 5. Configuration Flask

**app/__init__.py** : Initialisation avec Blueprint

```python
app = Flask(__name__, static_url_path='/app/static')
app.config['APPLICATION_ROOT'] = '/app'
```

**app/routes.py** : Routes sous le préfixe `/app`

```python
bp = Blueprint('main', __name__, url_prefix='/app')

@bp.route('/login')
@bp.route('/tavern')
@bp.route('/logout')
```

Le Blueprint permet de préfixer toutes les routes avec `/app`, ce qui correspond à la configuration Nginx.

## Lancement

### Démarrage de l'application

```bash
# Construire et démarrer les conteneurs
docker compose up --build

# En mode détaché
docker compose up -d --build
```

### Arrêt de l'application

```bash
docker compose down
```

### Reconstruction forcée

```bash
docker compose down
docker compose build --no-cache
docker compose up
```

## Accès à l'Application

Une fois les conteneurs lancés :

- **Landing Page** : https://crypto-tavern.local
- **Application Flask** : https://crypto-tavern.local/app/login
- **Redirect HTTP** : http://crypto-tavern.local (redirige automatiquement vers HTTPS)

### Comptes de Test

- Utilisateur 1 : `admin` / `tavern2025`
- Utilisateur 2 : `merchant` / `crypto123`

## Fonctionnalités de l'Application

1. **Système d'authentification** : Login/logout avec gestion de session Flask
2. **Marketplace de cryptomonnaies** : Affichage de BTC, ETH, ADA, SOL, DOT avec prix et stocks
3. **Messages flash** : Notifications de succès/erreur/info
4. **Gestion d'erreurs** : Pages 404 et 500 personnalisées

## Détails Techniques

### Pourquoi Gunicorn ?

Le serveur de développement Flask n'est pas adapté à la production :
- Single-threaded
- Pas de gestion efficace des connexions concurrentes
- Manque de sécurité

Gunicorn est un WSGI server production-ready qui gère efficacement les requêtes Python.

### Pourquoi Nginx en plus de Gunicorn ?

Nginx apporte des fonctionnalités essentielles :
- Serveur de fichiers statiques performant
- Terminaison SSL/TLS
- Load balancing
- Protection contre certaines attaques
- Compression
- Caching

### Pourquoi un Blueprint Flask ?

Le Blueprint avec `url_prefix='/app'` permet de :
- Préfixer toutes les routes automatiquement
- Maintenir une structure cohérente avec Nginx
- Faciliter la coexistence avec d'autres applications (landing page à la racine)

### Volumes Docker

Les volumes dans docker-compose.yml permettent :
- **read-only (`:ro`)** : Sécurité, empêche le conteneur de modifier les fichiers
- **Hot reload** : Modifications de code visibles sans rebuild (en dev)

### Network Docker

Le réseau `web_network` de type `bridge` permet :
- Communication inter-conteneurs par nom (DNS interne Docker)
- Isolation du réseau
- `flask_app` résolu automatiquement dans la configuration Nginx

## Troubleshooting

### Port 5000 déjà utilisé (AirPlay sur macOS)

Modifier le port dans `run.py` ou désactiver AirPlay Receiver dans Préférences Système.

### Certificats SSL non reconnus

```bash
mkcert -install
```

### Nginx ne démarre pas

Vérifier la syntaxe de nginx.conf :

```bash
docker compose exec nginx nginx -t
```

### Flask ne répond pas

Vérifier les logs :

```bash
docker compose logs flask_app
```

### CSS/JS ne se chargent pas

Vérifier que `static_url_path='/app/static'` est bien configuré dans `app/__init__.py`.

## Sécurité

### Points de sécurité implémentés

1. **HTTPS obligatoire** : Redirection automatique HTTP vers HTTPS
2. **Volumes read-only** : Les conteneurs ne peuvent pas modifier le code source
3. **Secrets** : `SECRET_KEY` défini via variable d'environnement
4. **Headers de sécurité** : Préservation de l'IP client pour les logs

### Améliorations possibles pour la production

1. Utiliser Let's Encrypt au lieu de certificats auto-signés
2. Ajouter des headers de sécurité (HSTS, CSP, X-Frame-Options)
3. Externaliser les secrets (Docker secrets, vault)
4. Mettre en place un rate limiting
5. Configurer les logs structurés
6. Ajouter un healthcheck pour les conteneurs

## Ressources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Gunicorn Documentation](https://docs.gunicorn.org/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [mkcert](https://github.com/FiloSottile/mkcert)
