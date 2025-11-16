# Formation Cybersécurité Full Stack - Jedha

Ce repository contient les projets et exercices réalisés dans le cadre de ma formation en cybersécurité full stack avec Jedha.

## Modules de formation

| Module | Durée | Statut |
|--------|-------|--------|
| Prepare Your Training (Prep Work) | 1 jour | ✅ |
| Threat Intelligence | 2 jours | ✅ |
| Email Security | 1 jour | ✅ |
| Databases | 2 jours | ✅ |
| Web Security | 6 jours | ⏳ |
| Cloud Security | 3 jours | ⏳ |
| Network Security | 6 jours | ⏳ |
| Linux System Security | 8 jours | ⏳ |
| Windows Security | 8 jours | ⏳ |
| Incident Response | 4 jours | ⏳ |
| Digital Forensics | 3 jours | ⏳ |
| Governance Risk and Compliance | 1 jour | ⏳ |
| Penetration Testing | 3 jours | ⏳ |
| Career Coaching | 3 jours | ⏳ |
| Final Project | 10 jours | ⏳ |
| Cybersecurity Certification | - | ⏳ |


## Structure du projet

```
jedha/
├── bash_training/        # [Prep Work] Scripts Bash d'entraînement
├── opencti/             # [Threat Intelligence] Documentation OpenCTI
├── python_blog/          # [Web Security] Projet de blog Flask
└── README.md            # Ce fichier
```

## Projets par module

### Prepare Your Training (Prep Work) ✅
**Répertoire :** `bash_training/`

Collection de scripts Bash pour l'apprentissage :
- `search_with_bash.sh` - Script de recherche de fichiers et répertoires
- `lizard_toad_snake.sh` - Chi Fou Mi interactif en ligne de commande

### Threat Intelligence ✅
**Répertoire :** `opencti/`

Documentation et guides de configuration pour OpenCTI :
- `opencti_installation_macos.md` - Installation sur macOS
- `opencti_configuration_sources.md` - Configuration des sources de données

**Articles publiés :**
- [OpenCTI - DragonForce](https://tely.info/article.html?id=opencti-dragonforce)
- [OpenCTI](https://tely.info/article.html?id=opencti)

### Email Security ✅
Module complété sans projet Git associé.

### Databases ✅
Module complété sans projet Git associé.

### Web Security ⏳
**Répertoire :** `python_blog/`

Application web de blog développée avec Flask :
- Base de données SQLite
- Templates HTML/CSS
- Gestion des articles et des posts
- Connexion à la base de données

## Prérequis

- Python 3.x
- Flask
- Bash
- Git

## Installation

### Projet Flask (python_blog)
```bash
cd python_blog
python -m venv venv
source venv/bin/activate  # Sur macOS/Linux
pip install flask
python app.py
```

## Licence

Projet éducatif - Jedha
