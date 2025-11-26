# Guide de transformation HTTP vers HTTPS

## Introduction

Ce document explique en détail les modifications apportées pour transformer le serveur HTTP en serveur HTTPS sécurisé avec support TLS 1.3.

## Vue d'ensemble

La transformation d'un serveur HTTP en HTTPS nécessite trois composants principaux :

1. **Certificats SSL/TLS** : Pour authentifier le serveur et établir un canal chiffré
2. **Configuration des chemins** : Localisation des certificats dans le code
3. **Enveloppement SSL du socket** : Transformation du socket TCP en socket TLS

## Modifications détaillées

### 1. Génération des certificats SSL/TLS

#### Commande utilisée :
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=FR/ST=IDF/L=Paris/O=Jedha/OU=Cybersec/CN=localhost"
```

#### Explication des paramètres :

| Paramètre | Description |
|-----------|-------------|
| `openssl req` | Outil de gestion des certificats et requêtes |
| `-x509` | Crée un certificat auto-signé (au lieu d'une CSR) |
| `-newkey rsa:4096` | Génère une nouvelle clé privée RSA de 4096 bits |
| `-keyout key.pem` | Nom du fichier de la clé privée |
| `-out cert.pem` | Nom du fichier du certificat public |
| `-days 365` | Durée de validité du certificat (1 an) |
| `-nodes` | "No DES" - ne chiffre pas la clé privée avec un mot de passe |
| `-subj` | Informations du certificat (évite les prompts interactifs) |

#### Informations du certificat (-subj) :

- **C=FR** : Country (Pays - France)
- **ST=IDF** : State (État - Île-de-France)
- **L=Paris** : Locality (Ville - Paris)
- **O=Jedha** : Organization (Organisation - Jedha)
- **OU=Cybersec** : Organizational Unit (Département - Cybersec)
- **CN=localhost** : Common Name (Nom du serveur - **IMPORTANT**)

#### Fichiers générés :

- **cert.pem** (2 Ko) : Certificat public, partageable
- **key.pem** (3.3 Ko) : Clé privée, à garder SECRÈTE (permissions 600)

### 2. Configuration (config.py)

#### Modifications apportées :

```python
#!/usr/bin/python3
import os  # ← AJOUTÉ

HOST = "0.0.0.0"
PORT = 8443  # ← MODIFIÉ (était 8080)
PUBLIC_DIR = "public"

# ← AJOUTÉ : Configuration SSL/TLS
CERT_FILE = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_FILE = os.path.join(os.path.dirname(__file__), "key.pem")
```

#### Explications :

1. **Import du module os** :
   - Nécessaire pour construire des chemins absolus
   - Garantit la portabilité (Windows/Linux/macOS)

2. **Changement de port 8080 → 8443** :
   - Port 443 : port standard HTTPS (nécessite root/admin)
   - Port 8443 : port alternatif HTTPS pour le développement
   - Évite les problèmes de permissions

3. **Variables CERT_FILE et KEY_FILE** :
   - `os.path.dirname(__file__)` : récupère le dossier du script config.py
   - `os.path.join()` : construit le chemin complet de manière portable
   - Résultat : chemins absolus vers cert.pem et key.pem

### 3. Serveur (server.py)

#### Modification 1 : Import du module SSL

```python
#!/usr/bin/env python3
import socket
import ssl  # ← AJOUTÉ
import signal
import sys
# ...
```

Le module `ssl` fait partie de la bibliothèque standard Python et fournit toutes les fonctionnalités TLS/SSL.

#### Modification 2 : Configuration SSL dans start_server()

**AVANT (HTTP) :**
```python
try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config.HOST, config.PORT))
    server_socket.listen(5)
```

**APRÈS (HTTPS) :**
```python
try:
    # Création du socket TCP classique
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Configuration SSL/TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)

    # Envelopper le socket avec SSL
    server_socket = context.wrap_socket(server_socket, server_side=True)

    server_socket.bind((config.HOST, config.PORT))
    server_socket.listen(5)
```

#### Modification 3 : Gestion des erreurs SSL

```python
def _accept_connections(local_server_socket, ssl_context):
    while True:
        try:
            client_socket, client_address = local_server_socket.accept()

            try:
                # Envelopper le socket client avec SSL
                ssl_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)

                client_thread = threading.Thread(
                    target=http_handler.handle_client,
                    args=(ssl_client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()

            except ssl.SSLError as e:
                print(f"Erreur SSL lors du handshake: {e}")
                try:
                    client_socket.close()
                except:
                    pass
```

**Pourquoi cette gestion d'erreurs est-elle importante ?**

Sans le `try/except ssl.SSLError` :
- ❌ Le serveur crashe quand un navigateur rejette le certificat auto-signé
- ❌ Les premières connexions (avant que l'utilisateur accepte le certificat) font planter le serveur
- ❌ Aucune information sur ce qui s'est mal passé

Avec la gestion d'erreurs :
- ✅ Le serveur continue de fonctionner même si le handshake SSL échoue
- ✅ Les erreurs sont loggées pour le débogage
- ✅ Le socket client est proprement fermé
- ✅ Une fois que l'utilisateur accepte le certificat, le serveur répond normalement

**Erreur typique** :
```
Erreur SSL lors du handshake: [SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate
```
Cette erreur apparaît quand le navigateur rejette le certificat auto-signé. C'est **normal** et attendu.

#### Explication étape par étape :

##### Étape 1 : Créer le contexte SSL
```python
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
```

- **SSLContext** : Objet qui contient toute la configuration SSL/TLS
- **PROTOCOL_TLS_SERVER** : Utilise automatiquement la meilleure version de TLS disponible
  - Privilégie TLS 1.3 (le plus récent)
  - Compatible avec TLS 1.2 si nécessaire
  - Désactive automatiquement les versions obsolètes (SSLv2, SSLv3, TLS 1.0)

##### Étape 2 : Charger les certificats
```python
context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)
```

- **load_cert_chain()** : Charge le certificat public et la clé privée
- Premier paramètre : chemin vers le certificat (cert.pem)
- Deuxième paramètre : chemin vers la clé privée (key.pem)
- Ces fichiers sont nécessaires pour :
  - Authentifier le serveur auprès des clients
  - Établir le canal de chiffrement

##### Étape 3 : Envelopper le socket
```python
server_socket = context.wrap_socket(server_socket, server_side=True)
```

- **wrap_socket()** : Transforme un socket TCP classique en socket SSL/TLS
- **server_side=True** : Indique que nous sommes le serveur (pas le client)
- Le socket peut maintenant :
  - Négocier le handshake TLS
  - Chiffrer/déchiffrer les données automatiquement
  - Vérifier l'intégrité des messages

#### Ordre des opérations (CRUCIAL) :

```
1. Créer socket TCP         socket.socket()
2. Configurer options        setsockopt()
3. Créer contexte SSL        ssl.SSLContext()
4. Charger certificats       context.load_cert_chain()
5. Envelopper avec SSL       context.wrap_socket()  ← Socket devient HTTPS ici
6. Bind au port              server_socket.bind()
7. Écouter les connexions    server_socket.listen()
```

**Important** : Le socket DOIT être enveloppé avec SSL AVANT le bind() et listen().

## Fonctionnement du protocole TLS

### 1. Handshake TLS

Quand un client se connecte, voici ce qui se passe :

```
Client                                Server
  |                                      |
  |------- Client Hello ---------------->|  (Versions TLS, chiffrements supportés)
  |                                      |
  |<------ Server Hello -----------------|  (Version TLS choisie, chiffrement)
  |<------ Certificate -----------------|  (Envoi du cert.pem)
  |<------ Server Key Exchange ---------|  (Paramètres de chiffrement)
  |<------ Server Hello Done -----------|
  |                                      |
  |------- Client Key Exchange -------->|  (Clé de session chiffrée)
  |------- Change Cipher Spec --------->|
  |------- Finished ------------------->|
  |                                      |
  |<------ Change Cipher Spec -----------|
  |<------ Finished --------------------|
  |                                      |
  |======= Canal chiffré établi ========|
  |                                      |
  |------- Requête HTTP chiffrée ------>|
  |<------ Réponse HTTP chiffrée -------|
```

### 2. Algorithmes de chiffrement utilisés

Avec TLS 1.3, la négociation aboutit généralement à :

- **Algorithme de chiffrement** : AES-256-GCM
  - AES : Advanced Encryption Standard
  - 256 : Taille de clé de 256 bits (très sécurisé)
  - GCM : Galois/Counter Mode (chiffrement authentifié)

- **Fonction de hachage** : SHA-384
  - Secure Hash Algorithm 384 bits
  - Garantit l'intégrité des données

- **Échange de clés** : ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
  - Assure le "Perfect Forward Secrecy"
  - Si la clé privée est compromise, les anciennes sessions restent sécurisées

## Test du serveur HTTPS

### 1. Lancement du serveur

```bash
python3 server.py
```

Sortie attendue :
```
PyServ - Serveur HTTPS Python
Démarrage sur 0.0.0.0:8443
Dossier public: public
----------------------------------------
Serveur en écoute sur https://0.0.0.0:8443
Certificat: /chemin/vers/cert.pem
```

### 2. Test avec curl

```bash
# Test basique
curl -k https://localhost:8443/

# Test avec détails de connexion
curl -k -v https://localhost:8443/

# Voir uniquement les headers
curl -k -I https://localhost:8443/
```

**Note** : Le flag `-k` (ou `--insecure`) ignore la vérification du certificat. Nécessaire pour les certificats auto-signés.

### 3. Test avec navigateur

Ouvrez `https://localhost:8443` dans votre navigateur.

**Vous verrez un avertissement de sécurité** :
- Chrome : "Votre connexion n'est pas privée" (NET::ERR_CERT_AUTHORITY_INVALID)
- Firefox : "Attention : risque probable de sécurité"
- Safari : "Ce site web peut ne pas être sûr"

**C'est normal !** Le certificat est auto-signé et n'est pas émis par une autorité de certification reconnue.

Pour continuer :
- Chrome : Cliquez sur "Paramètres avancés" → "Continuer vers localhost"
- Firefox : "Paramètres avancés" → "Accepter le risque et poursuivre"
- Safari : "Afficher les détails" → "visiter ce site web"

### 4. Vérification du certificat avec OpenSSL

```bash
# Afficher les détails du certificat
openssl x509 -in cert.pem -text -noout

# Tester la connexion SSL
openssl s_client -connect localhost:8443 -showcerts
```

## Sécurité

### Ce qui est maintenant protégé :

✅ **Confidentialité** :
- Toutes les données sont chiffrées (requêtes et réponses)
- Protection contre l'écoute passive (sniffing)
- Algorithme AES-256-GCM (niveau militaire)

✅ **Intégrité** :
- Les données ne peuvent pas être modifiées en transit
- Détection automatique des altérations
- Fonction de hachage SHA-384

✅ **Authentification** :
- Le serveur prouve son identité via le certificat
- Protection contre l'usurpation d'identité basique

### Limitations (certificat auto-signé) :

⚠️ **Pas de validation par une autorité de certification** :
- Les navigateurs affichent un avertissement
- Risque d'attaque man-in-the-middle sophistiquée
- Pas adapté à la production

⚠️ **Certificat non reconnu par défaut** :
- Les clients doivent accepter manuellement le risque
- Mauvaise expérience utilisateur

## Pour la production

### Option 1 : Let's Encrypt (Gratuit)

Let's Encrypt fournit des certificats gratuits reconnus par tous les navigateurs.

```bash
# Installer certbot
sudo apt-get install certbot  # Ubuntu/Debian
brew install certbot          # macOS

# Obtenir un certificat
sudo certbot certonly --standalone -d votredomaine.com

# Certificats générés dans :
# /etc/letsencrypt/live/votredomaine.com/fullchain.pem
# /etc/letsencrypt/live/votredomaine.com/privkey.pem
```

Puis modifiez `config.py` :
```python
CERT_FILE = "/etc/letsencrypt/live/votredomaine.com/fullchain.pem"
KEY_FILE = "/etc/letsencrypt/live/votredomaine.com/privkey.pem"
```

### Option 2 : Certificat commercial

Achetez un certificat auprès de :
- DigiCert
- GlobalSign
- Sectigo
- Etc.

### Configuration recommandée pour la production

```python
# Créer un contexte SSL plus strict
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)

# Options de sécurité supplémentaires
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Désactiver TLS < 1.2
```

## Comparaison HTTP vs HTTPS

| Aspect | HTTP (avant) | HTTPS (après) |
|--------|-------------|---------------|
| Port | 8080 | 8443 |
| Chiffrement | ❌ Aucun | ✅ TLS 1.3 / AES-256 |
| Confidentialité | ❌ Tout en clair | ✅ Données chiffrées |
| Intégrité | ❌ Aucune garantie | ✅ Vérification automatique |
| Authentification | ❌ Aucune | ✅ Certificat serveur |
| Performance | Légèrement plus rapide | Overhead cryptographique ~5% |
| Conformité | Non conforme | Conforme aux standards web |

## Problèmes courants et solutions

### Le serveur crash dès qu'un navigateur se connecte

**Symptôme** :
```bash
PyServ - Serveur HTTPS Python
Démarrage sur 0.0.0.0:8443
[21:28:09] Connexion de 127.0.0.1:61695
# Le serveur s'arrête brutalement sans message d'erreur
```

**Cause** : Absence de gestion des erreurs SSL. Quand un navigateur rejette le certificat auto-signé (avant que l'utilisateur accepte le risque), le handshake SSL échoue et fait planter le serveur.

**Solution** : Ajouter une gestion d'erreurs robuste dans la fonction `_accept_connections()` :
```python
try:
    ssl_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)
    # Traiter la requête...
except ssl.SSLError as e:
    print(f"Erreur SSL lors du handshake: {e}")
    client_socket.close()
```

**Résultat avec la correction** :
```bash
[21:28:52] Connexion de 127.0.0.1:61766
Erreur SSL lors du handshake: [SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate
[21:28:52] Connexion de 127.0.0.1:61767
Erreur SSL lors du handshake: [SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate
[21:29:00] Connexion de 127.0.0.1:61777
Request received: GET / HTTP/1.1  # ✅ Fonctionne après avoir accepté le certificat !
```

### Firefox affiche "La connexion a échoué"

**Symptôme** : Le navigateur ne peut pas établir de connexion (pas d'avertissement de certificat).

**Causes possibles** :
1. Le serveur n'est pas démarré
2. Le serveur a crashé (voir problème ci-dessus)
3. Mauvais port (vérifier 8443)

**Solution** : Vérifier que le serveur tourne avec la gestion d'erreurs SSL.

## Dépannage

### Erreur : "Certificate verify failed"

Si vous voyez cette erreur avec curl sans `-k` :
```
curl: (60) SSL certificate problem: self signed certificate
```

**Solution** : Utilisez `-k` pour les certificats auto-signés, ou installez le certificat dans le magasin de confiance du système.

### Erreur : "Address already in use"

```
OSError: [Errno 48] Address already in use
```

**Solution** : Un autre processus utilise le port 8443.
```bash
# Trouver le processus
lsof -i :8443

# Tuer le processus
kill -9 <PID>
```

### Erreur : "Permission denied" (port 443)

```
PermissionError: [Errno 13] Permission denied
```

**Solution** : Le port 443 nécessite les privilèges root.
```bash
# Option 1 : Utiliser sudo
sudo python3 server.py

# Option 2 : Utiliser un port >1024 (ex: 8443)
# Modifier PORT = 8443 dans config.py
```

### Le navigateur refuse toujours le certificat

**Solution** : Pour un usage permanent en développement, ajoutez le certificat aux certificats de confiance :

**macOS** :
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
```

**Linux** :
```bash
sudo cp cert.pem /usr/local/share/ca-certificates/pyserv.crt
sudo update-ca-certificates
```

**Windows** :
1. Double-cliquez sur cert.pem
2. "Installer le certificat"
3. "Ordinateur local"
4. "Placer tous les certificats dans le magasin suivant"
5. Sélectionnez "Autorités de certification racines de confiance"

## Ressources supplémentaires

- [Documentation SSL Python](https://docs.python.org/3/library/ssl.html)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

