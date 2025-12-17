# CI/CD Pipeline - Calculator App

Guide complet pour construire un pipeline CI/CD from scratch.

---

## Table des matières

1. [Objectifs](#objectifs)
2. [Structure finale du projet](#structure-finale-du-projet)
3. [Étape 1 : Créer le repo et l'application](#étape-1--créer-le-repo-et-lapplication)
4. [Étape 2 : Créer le CI Pipeline](#étape-2--créer-le-ci-pipeline)
5. [Étape 3 : Créer le Dockerfile](#étape-3--créer-le-dockerfile)
6. [Étape 4 : Configurer Docker Hub](#étape-4--configurer-docker-hub)
7. [Étape 5 : Créer le CD Pipeline](#étape-5--créer-le-cd-pipeline)
8. [Étape 6 : Configurer les secrets GitHub](#étape-6--configurer-les-secrets-github)
9. [Étape 7 : Tester le pipeline](#étape-7--tester-le-pipeline)
10. [Concepts clés](#concepts-clés)
11. [Dépannage](#dépannage)

---

## Objectifs

Construire un pipeline CI/CD qui :

- **CI** : Exécute les tests sur plusieurs versions Python (3.8, 3.9, 3.10)
- **CI** : Lance Flake8 pour vérifier la qualité du code
- **CI** : Exécute Trivy pour scanner les vulnérabilités
- **CD** : Build une image Docker (seulement si CI réussit)
- **CD** : Push l'image vers Docker Hub

---

## Structure finale du projet

```
ci-cd-lab/
├── .github/
│   └── workflows/
│       ├── ci.yml              # Pipeline CI
│       └── cd.yml              # Pipeline CD
├── calculator/
│   ├── __init__.py             # Fichier vide (requis pour le module Python)
│   └── calculator.py           # Application principale
├── tests/
│   ├── __init__.py             # Fichier vide (requis pour le module Python)
│   └── test_calculator.py      # Tests unitaires
├── Dockerfile                  # Instructions pour builder l'image Docker
└── README.md
```

---

## Étape 1 : Créer le repo et l'application

### 1.1 Créer le repo GitHub

```bash
mkdir ci-cd-lab
cd ci-cd-lab
git init
```

### 1.2 Créer l'application Python

**Fichier `calculator/__init__.py`** (fichier vide) :
```python
# Fichier vide - nécessaire pour que Python reconnaisse le dossier comme un module
```

**Fichier `calculator/calculator.py`** :
```python
def add(a, b):
    """Add two numbers and return the result."""
    return a + b

def subtract(a, b):
    """Subtract b from a and return the result."""
    return a - b

def multiply(a, b):
    """Multiply two numbers and return the result."""
    return a * b

def divide(a, b):
    """Divide a by b and return the result."""
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

if __name__ == "__main__":
    print(add(1, 2))
    print(subtract(1, 2))
    print(multiply(1, 2))
    print(divide(1, 2))
```

### 1.3 Créer les tests

**Fichier `tests/__init__.py`** (fichier vide) :
```python
# Fichier vide
```

**Fichier `tests/test_calculator.py`** :
```python
import unittest

from calculator.calculator import add, divide, multiply, subtract


class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(1, 2), 3)
        self.assertEqual(add(-1, 1), 0)
        self.assertEqual(add(-1, -1), -2)

    def test_subtract(self):
        self.assertEqual(subtract(1, 2), -1)
        self.assertEqual(subtract(-1, 1), -2)
        self.assertEqual(subtract(-1, -1), 0)

    def test_multiply(self):
        self.assertEqual(multiply(1, 2), 2)
        self.assertEqual(multiply(-1, 1), -1)
        self.assertEqual(multiply(-1, -1), 1)

    def test_divide(self):
        self.assertEqual(divide(1, 2), 0.5)
        self.assertEqual(divide(-1, 1), -1)
        self.assertEqual(divide(-1, -1), 1)
        self.assertEqual(divide(0, 5), 0)
        with self.assertRaises(ValueError):
            divide(1, 0)

if __name__ == '__main__':
    unittest.main()
```

### 1.4 Tester localement

```bash
# Installer pytest
pip install pytest

# Lancer les tests
pytest tests/
```

---

## Étape 2 : Créer le CI Pipeline

### 2.1 Créer la structure des workflows

```bash
mkdir -p .github/workflows
```

### 2.2 Créer le fichier CI

**Fichier `.github/workflows/ci.yml`** :

```yaml
name: CI pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  test:
    runs-on: ubuntu-latest

    # Matrix strategy : exécute le job sur plusieurs versions Python
    strategy:
      matrix:
        python-version: ['3.8', '3.9', '3.10']

    steps:
      # Étape 1 : Récupérer le code du repo
      - name: Checkout code
        uses: actions/checkout@v6

      # Étape 2 : Installer Python avec la version de la matrix
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v6
        with:
          python-version: ${{ matrix.python-version }}

      # Étape 3 : Installer les dépendances
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install flake8 pytest

      # Étape 4 : Linter avec flake8
      - name: Lint with flake8
        run: |
          # Arrête le build si erreurs de syntaxe Python ou noms non définis
          flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
          # exit-zero traite toutes les erreurs comme des warnings
          flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

      # Étape 5 : Lancer les tests
      - name: Test with pytest
        run: |
          pytest tests/

  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      # Scanner les vulnérabilités avec Trivy
      - name: Run Trivy vulnerability scanner in filesystem mode
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      # Envoyer les résultats vers l'onglet Security de GitHub
      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

### 2.3 Explication détaillée du CI

#### Déclencheurs (`on:`)

```yaml
on:
  push:
    branches: [ main ]      # Déclenche sur push vers main
  pull_request:
    branches: [ main ]      # Déclenche sur PR vers main
  workflow_dispatch:        # Permet de lancer manuellement depuis GitHub
```

#### Permissions

```yaml
permissions:
  contents: read          # Lire le code
  security-events: write  # Écrire les résultats Trivy dans Security tab
  actions: read           # Lire les informations des actions
```

#### Matrix Strategy

```yaml
strategy:
  matrix:
    python-version: ['3.8', '3.9', '3.10']
```

Cela crée **3 jobs parallèles**, un pour chaque version Python.

**Important** : Les quotes sur `'3.10'` sont obligatoires. Sans quotes, YAML interprète `3.10` comme `3.1` (supprime le zéro).

#### Variables de la matrix

```yaml
${{ matrix.python-version }}
```

Cette syntaxe accède à la valeur courante de la matrix (3.8, 3.9 ou 3.10 selon le job).

---

## Étape 3 : Créer le Dockerfile

**Fichier `Dockerfile`** (à la racine du projet) :

```dockerfile
FROM python:3.10-alpine

COPY . /app

WORKDIR /app

CMD ["python", "calculator/calculator.py"]
```

### Explication du Dockerfile

| Instruction | Description |
|-------------|-------------|
| `FROM python:3.10-alpine` | Image de base Python 3.10 (version légère Alpine) |
| `COPY . /app` | Copie tout le code dans le dossier /app du container |
| `WORKDIR /app` | Définit /app comme répertoire de travail |
| `CMD [...]` | Commande exécutée au lancement du container |

### Tester le Dockerfile localement

```bash
# Builder l'image
docker build -t calculator:local .

# Lancer le container
docker run calculator:local
```

---

## Étape 4 : Configurer Docker Hub

### 4.1 Créer un compte Docker Hub

1. Aller sur https://hub.docker.com
2. S'inscrire (ou se connecter avec Google SSO)

### 4.2 Créer un Access Token

**Pourquoi un token ?** Plus sécurisé qu'un mot de passe, et nécessaire en cas d'utilisation du SSO.

1. Docker Hub → **Account Settings** → **Security**
2. Cliquer **New Access Token**
3. Nom : `github-actions`
4. Permissions : **Read & Write**
5. **Copier le token** (visible une seule fois)

### 4.3 Noter le username

Le username Docker Hub est visible en haut à droite sur hub.docker.com.

---

## Étape 5 : Créer le CD Pipeline

**Fichier `.github/workflows/cd.yml`** :

```yaml
name: CD pipeline

on:
  workflow_run:
    workflows: ["CI pipeline"]  # Doit correspondre au "name:" du ci.yml
    types:
      - completed

jobs:
  build:
    runs-on: ubuntu-latest
    # Ne s'exécute QUE si le CI a réussi
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v6

      # Se connecter à Docker Hub
      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      # Builder et pusher l'image
      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: <DOCKER_USERNAME>/calculator:latest  # Remplacer <DOCKER_USERNAME>
```

### Explication détaillée du CD

#### Déclencheur `workflow_run`

```yaml
on:
  workflow_run:
    workflows: ["CI pipeline"]
    types:
      - completed
```

- `workflows: ["CI pipeline"]` : Référence le nom du workflow CI (ligne 1 de ci.yml)
- `types: completed` : Se déclenche quand le CI se termine (succès OU échec)

#### Condition de succès

```yaml
if: ${{ github.event.workflow_run.conclusion == 'success' }}
```

Le job ne s'exécute **que** si le CI a réussi. Si le CI échoue, le CD ne se lance pas.

#### Secrets

```yaml
username: ${{ secrets.DOCKER_USERNAME }}
password: ${{ secrets.DOCKER_PASSWORD }}
```

Les secrets sont des variables chiffrées stockées dans GitHub, jamais visibles dans les logs.

---

## Étape 6 : Configurer les secrets GitHub

### 6.1 Accéder aux secrets

1. Aller sur le repo GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Cliquer **New repository secret**

### 6.2 Créer les 2 secrets

| Nom du secret | Valeur |
|---------------|--------|
| `DOCKER_USERNAME` | Username Docker Hub |
| `DOCKER_PASSWORD` | Access Token créé à l'étape 4.2 |

### 6.3 Types de secrets (pour info)

| Type | Usage |
|------|-------|
| **Repository secrets** | Disponibles pour tous les workflows du repo |
| **Environment secrets** | Liés à un environnement spécifique (prod, staging...) |
| **Variables** | Pour valeurs non sensibles uniquement |

---

## Étape 7 : Tester le pipeline

### 7.1 Commit et push

```bash
git add .
git commit -m "Add CI/CD pipeline"
git push origin main
```

### 7.2 Vérifier sur GitHub

1. Aller sur le repo → onglet **Actions**
2. Le **CI pipeline** devrait être en cours d'exécution
3. Le job `test` s'exécute **3 fois** (une par version Python)
4. Le job `trivy-scan` s'exécute en parallèle
5. Une fois le CI terminé avec succès → **CD pipeline** démarre automatiquement

### 7.3 Vérifier sur Docker Hub

1. Aller sur `https://hub.docker.com/r/<DOCKER_USERNAME>/calculator`
2. L'image devrait apparaître avec le tag `latest`

### 7.4 Tester l'image

```bash
# Télécharger l'image
docker pull <DOCKER_USERNAME>/calculator:latest

# Lancer le container
docker run --name calculator <DOCKER_USERNAME>/calculator:latest
```

---

## Concepts clés

### Actions GitHub utilisées

| Action | Description |
|--------|-------------|
| `actions/checkout@v6` | Clone le repo dans le runner |
| `actions/setup-python@v6` | Installe une version Python |
| `aquasecurity/trivy-action` | Scan de vulnérabilités |
| `github/codeql-action/upload-sarif@v3` | Upload résultats vers Security tab |
| `docker/login-action@v3` | Connexion à Docker Hub |
| `docker/build-push-action@v6` | Build et push image Docker |

### SHA vs Tags pour les actions

```yaml
# Tag (lisible, mais peut être modifié)
uses: docker/login-action@v3

# SHA (immuable, recommandé en production)
uses: docker/login-action@6d4b68b490aef8836e8fb5e50ee7b3bdfa5894f0
```

Le SHA garantit que le code de l'action ne changera jamais.

### Syntaxe des expressions GitHub

| Expression | Description |
|------------|-------------|
| `${{ matrix.python-version }}` | Valeur de la matrix |
| `${{ secrets.NOM }}` | Accès à un secret |
| `${{ github.event.workflow_run.conclusion }}` | Résultat du workflow précédent |

---

## Dépannage

### Le CD ne se déclenche pas

- Vérifier que le nom dans `workflows: ["CI pipeline"]` correspond **exactement** au `name:` du ci.yml
- Vérifier que le CI a réussi (check vert dans Actions)

### Erreur d'authentification Docker Hub

- Vérifier que les secrets `DOCKER_USERNAME` et `DOCKER_PASSWORD` sont bien créés
- Vérifier que le token Docker Hub a les permissions Read & Write

### Les tests échouent sur une version Python

- Vérifier la compatibilité du code avec toutes les versions
- Les quotes sur `'3.10'` sont-elles présentes ?

### Trivy ne trouve pas de vulnérabilités

C'est normal. Le code est simple et n'a pas de dépendances vulnérables.

---

## Commandes utiles

```bash
# Lancer les tests localement
pytest tests/

# Lancer flake8 localement
pip install flake8
flake8 .

# Builder l'image Docker localement
docker build -t calculator:local .

# Lancer le container
docker run calculator:local

# Voir les images Docker locales
docker images

# Supprimer une image
docker rmi calculator:local
```
