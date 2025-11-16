# 05 - Web Security

**Durée :** 6 jours
**Statut :** ⏳ En cours

## Objectifs

Apprendre à identifier et exploiter les vulnérabilités web, et à sécuriser les applications web.

## Sujets étudiés

- OWASP Top 10
- Injections (SQL, XSS, CSRF, etc.)
- Authentification et gestion de sessions
- Sécurité des APIs
- HTTPS et certificats SSL/TLS
- Web Application Firewall (WAF)
- Secure coding practices

## Projets

### python_blog

Application web de blog développée avec Flask pour mettre en pratique les concepts de sécurité web.

#### Technologies

- Python 3.x
- Flask (framework web)
- SQLite (base de données)
- HTML/CSS
- Jinja2 (templates)

#### Fonctionnalités

- Affichage d'articles de blog
- Gestion de posts
- Base de données SQLite pour le stockage
- Interface web responsive

#### Installation

```bash
cd python_blog

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
source venv/bin/activate  # Sur macOS/Linux
# .\venv\Scripts\activate  # Sur Windows

# Installer les dépendances
pip install flask

# Lancer l'application
python app.py
```

L'application sera accessible sur `http://localhost:5000`

#### Structure

```
python_blog/
├── app.py              # Application Flask principale
├── connector.py        # Connexion à la base de données
├── blog.db            # Base de données SQLite
├── static/
│   └── style.css      # Feuille de style
└── templates/
    ├── index.html     # Page d'accueil
    ├── post.html      # Affichage d'un article
    └── new.html       # Création d'article
```

## Compétences acquises (en cours)

- Développement d'applications web avec Flask
- Intégration de bases de données
- Templating avec Jinja2
- Gestion de routes et requêtes HTTP
- (À venir) Identification et correction de vulnérabilités web

## Notes

Module en cours. Le projet python_blog servira de base pour explorer les vulnérabilités web et apprendre à les corriger. D'autres projets Python viendront s'ajouter dans ce module.
