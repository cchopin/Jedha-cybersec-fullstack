#  TODO List - Serveur HTTP Python

##  Phase 1 : Création de la structure du projet

- [x] Créer le dossier principal `projet-http-server/`
- [x] Créer les fichiers Python vides :
  - [ ] `server.py`
  - [ ] `http_handler.py`
  - [x] `file_manager.py`
  - [x] `response_builder.py`
  - [x] `config.py`
  - [x] `utils.py`
- [x] Créer le dossier `public/`
- [ ] Créer le dossier `logs/` (optionnel)
- [ ] Créer le fichier `public/index.html` avec le contenu de base

---

## ️ Phase 2 : Configuration (config.py)

- [x] Définir les constantes du serveur :
  - [x] `HOST = '0.0.0.0'`
  - [x] `PORT = 8000`
  - [x] `PUBLIC_DIR = 'public'`
  - [x] `MAX_CONNECTIONS = 5`
- [x] Créer le dictionnaire des codes de statut HTTP :
  - [x] 200 : "OK"
  - [x] 404 : "Not Found"
  - [x] 403 : "Forbidden"
  - [x] 405 : "Method Not Allowed"
  - [x] 500 : "Internal Server Error"
- [x] Créer le dictionnaire des MIME types :
  - [x] `.html` → `text/html`
  - [x] `.css` → `text/css`
  - [x] `.js` → `application/javascript`
  - [x] `.jpg` / `.jpeg` → `image/jpeg`
  - [x] `.png` → `image/png`
  - [x] `.gif` → `image/gif`
  - [x] `.txt` → `text/plain`
  - [x] Type par défaut → `application/octet-stream`

---

## ️ Phase 3 : Utilitaires (utils.py)

- [x] Fonction `get_mime_type(file_path)` :
  - [x] Extraire l'extension du fichier
  - [x] Retourner le MIME type correspondant
  - [x] Gérer le cas par défaut
- [x] Fonction `get_status_message(status_code)` :
  - [x] Retourner le message associé au code de statut
  - [x] Gérer le cas où le code n'existe pas
- [ ] Fonction `format_log(message, level="INFO")` :
  - [ ] Formater avec timestamp
  - [ ] Ajouter le niveau (INFO, ERROR, WARNING)
  - [ ] Retourner le message formaté

---

##  Phase 4 : Gestion des fichiers (file_manager.py)

- [x] Fonction `sanitize_path(requested_path)` :
  - [x] Supprimer les `../` pour éviter les attaques
  - [x] Normaliser le chemin
  - [x] Retourner le chemin sécurisé
- [x] Fonction `resolve_file_path(path)` :
  - [x] Si path == "/" ou vide, retourner "index.html"
  - [x] Sinon, construire le chemin complet avec PUBLIC_DIR
  - [x] Appeler `sanitize_path()` sur le résultat
- [x] Fonction `file_exists(file_path)` :
  - [x] Vérifier si le fichier existe
  - [x] Retourner True/False
- [x] Fonction `read_file(file_path)` :
  - [x] Essayer d'ouvrir et lire le fichier
  - [x] Retourner le contenu en bytes
  - [x] Gérer l'exception `FileNotFoundError`
  - [x] Gérer les autres exceptions possibles

---

##  Phase 5 : Construction des réponses (response_builder.py)

- [x] Fonction `get_error_page(status_code)` :
  - [x] Créer une page HTML d'erreur personnalisée
  - [x] Inclure le code et le message d'erreur
  - [x] Retourner le contenu HTML
- [x] Fonction `build_status_line(status_code)` :
  - [x] Construire la ligne "HTTP/1.1 {code} {message}"
  - [x] Utiliser `get_status_message()` de utils
  - [x] Retourner la ligne complète
- [x] Fonction `build_headers(content_length, mime_type)` :
  - [x] Créer le header `Content-Type`
  - [x] Créer le header `Content-Length`
  - [x] Ajouter le header `Connection: close`
  - [x] Retourner tous les headers formatés
- [x] Fonction `build_response(status_code, content, mime_type)` :
  - [x] Construire la ligne de statut
  - [x] Construire les headers
  - [x] Assembler : status_line + headers + "\r\n\r\n" + content
  - [x] Retourner la réponse complète en bytes

---

##  Phase 6 : Gestion HTTP (http_handler.py)

- [x] Fonction `parse_request(raw_request)` :
  - [x] Décoder la requête brute
  - [x] Séparer les lignes
  - [x] Extraire la première ligne (request line)
  - [x] Parser : méthode, path, version HTTP
  - [x] Retourner un dictionnaire avec ces infos
- [x] Fonction `route_request(method, path)` :
  - [x] Vérifier que la méthode est GET (sinon retourner 405)
  - [x] Résoudre le chemin du fichier avec `resolve_file_path()`
  - [x] Vérifier l'existence avec `file_exists()`
  - [x] Si existe : lire le fichier et retourner (200, content, mime_type)
  - [x] Si n'existe pas : retourner (404, error_page, "text/html")
- [x] Fonction `handle_client(client_socket)` :
  - [x] Recevoir les données (recv 1024 bytes)
  - [x] Parser la requête avec `parse_request()`
  - [ ] Logger la requête reçue
  - [x] Appeler `route_request()` pour obtenir status, content, mime_type
  - [x] Construire la réponse avec `build_response()`
  - [x] Envoyer la réponse avec `sendall()`
  - [x] Fermer la connexion client
  - [x] Gérer les exceptions globales (retourner 500 en cas d'erreur)

---

##  Phase 7 : Serveur principal (server.py)

- [x] Importer tous les modules nécessaires
- [x] Fonction `shutdown_handler(signum, frame)` :
  - [x] Afficher un message de fermeture
  - [x] Fermer le socket serveur
  - [x] Appeler `sys.exit(0)`
- [x] Fonction `accept_connections(server_socket)` :
  - [x] Créer une boucle infinie `while True`
  - [x] Accepter les connexions avec `server_socket.accept()`
  - [x] Logger l'adresse du client
  - [x] Appeler `handle_client()` du module http_handler
  - [x] Gérer les exceptions
- [x] Fonction `start_server()` :
  - [ ] Logger le démarrage du serveur
  - [x] Créer le socket TCP/IP
  - [x] Configurer `SO_REUSEADDR`
  - [x] Binder le socket sur HOST:PORT
  - [x] Mettre le socket en écoute (listen)
  - [ ] Logger l'URL d'accès
  - [x] Appeler `accept_connections()`
  - [x] Fermer le socket en fin de programme
- [x] Bloc `if __name__ == "__main__"` :
  - [x] Configurer le handler de signal pour Ctrl+C
  - [x] Appeler `start_server()`
  - [x] Gérer l'exception `KeyboardInterrupt`

---

##  Phase 8 : Tests et validation

- [x] Tester le serveur de base :
  - [x] Lancer `python server.py`
  - [x] Vérifier que le serveur démarre sans erreur
  - [ ] Vérifier les logs de démarrage
- [x] Tester l'accès à index.html :
  - [x] Ouvrir `http://localhost:8080/`
  - [x] Vérifier que la page s'affiche correctement
  - [ ] Vérifier les logs du serveur
- [ ] Tester les fichiers statiques :
  - [ ] Créer un fichier CSS dans `public/`
  - [x] Créer une image dans `public/`
  - [x] Accéder à ces fichiers via le navigateur
  - [x] Vérifier que les MIME types sont corrects
- [x] Tester les erreurs 404 :
  - [x] Accéder à `http://localhost:8080/fichier-inexistant.html`
  - [x] Vérifier la page d'erreur personnalisée
  - [ ] Vérifier le code de statut dans les logs
- [x]Tester la sécurité :
  - [x] Essayer d'accéder à `http://localhost:8080/../config.py`
  - [x] Vérifier que l'accès est refusé - redirection 404 valide
- [x] Tester l'arrêt propre :
  - [x] Faire Ctrl+C
  - [x] Vérifier que le serveur se ferme proprement

---

##  Phase 9 : Améliorations (Bonus)

- [ ] Ajouter le support de plus de MIME types
- [ ] Créer des pages d'erreur HTML personnalisées pour chaque code
- [ ] Ajouter un système de logging dans des fichiers
- [ ] Ajouter le support des méthodes POST et PUT
- [ ] Implémenter un cache simple pour les fichiers statiques
- [ ] Ajouter des headers de sécurité (CORS, etc.)
- [ ] Créer un mode debug/verbose
- [ ] Ajouter des statistiques (nombre de requêtes, etc.)

---

##  Phase 10 : Documentation

- [ ] Créer un fichier `README.md` :
  - [ ] Description du projet
  - [ ] Instructions d'installation
  - [ ] Instructions d'utilisation
  - [ ] Exemples de requêtes
  - [ ] Architecture du projet
- [ ] Ajouter des docstrings à toutes les fonctions
- [ ] Ajouter des commentaires dans le code complexe

---

##  Phase finale : Validation du projet

- [ ] Relire tout le code
- [ ] Vérifier que tous les TODOs de l'exercice sont complétés
- [ ] Tester tous les scénarios possibles
- [ ] Nettoyer le code (supprimer les prints de debug)
- [ ] Commit final et push (si utilisation de Git)

---

