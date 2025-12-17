# Flask Blog

Application web de blog développée avec Flask et SQLite dans le cadre du module Web Security.

## Description

Blog minimaliste permettant de créer, afficher et supprimer des articles.

## Fonctionnalités

- Affichage de tous les articles
- Création de nouveaux articles
- Affichage d'un article individuel
- Suppression d'articles
- Stockage en base de données SQLite

## Architecture

```
python_blog/
├── app.py              # Application Flask et routes
├── connector.py        # Couche d'accès à la base de données
├── blog.db             # Base de données SQLite
├── templates/
│   ├── index.html     # Page d'accueil (liste des posts)
│   ├── new.html       # Formulaire de création
│   └── post.html      # Affichage d'un post
└── static/
    └── style.css      # Styles CSS
```

## Technologies

- **Backend:** Flask (Python)
- **Base de données:** SQLite3
- **Frontend:** HTML, CSS, Jinja2

## Installation

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou venv\Scripts\activate  # Windows

# Installer les dépendances
pip install flask

# Lancer l'application
python app.py
```

L'application sera accessible sur `http://localhost:5000`
