#  TODO List - Serveur HTTP Python

##  Phase 1 : Création de la structure du projet

- [ ] Créer le dossier principal `projet-http-server/`
- [ ] Créer les fichiers Python vides :
  - [ ] `server.py`
  - [ ] `http_handler.py`
  - [ ] `file_manager.py`
  - [ ] `response_builder.py`
  - [ ] `config.py`
  - [ ] `utils.py`
- [ ] Créer le dossier `public/`
- [ ] Créer le dossier `logs/` (optionnel)
- [ ] Créer le fichier `public/index.html` avec le contenu de base

---

## ️ Phase 2 : Configuration (config.py)

- [ ] Définir les constantes du serveur :
  - [ ] `HOST = '0.0.0.0'`
  - [ ] `PORT = 8000`
  - [ ] `PUBLIC_DIR = 'public'`
  - [ ] `MAX_CONNECTIONS = 5`
- [ ] Créer le dictionnaire des codes de statut HTTP :
  - [ ] 200 : "OK"
  - [ ] 404 : "Not Found"
  - [ ] 403 : "Forbidden"
  - [ ] 405 : "Method Not Allowed"
  - [ ] 500 : "Internal Server Error"
- [ ] Créer le dictionnaire des MIME types :
  - [ ] `.html` → `text/html`
  - [ ] `.css` → `text/css`
  - [ ] `.js` → `application/javascript`
  - [ ] `.jpg` / `.jpeg` → `image/jpeg`
  - [ ] `.png` → `image/png`
  - [ ] `.gif` → `image/gif`
  - [ ] `.txt` → `text/plain`
  - [ ] Type par défaut → `application/octet-stream`

---

## ️ Phase 3 : Utilitaires (utils.py)

- [ ] Fonction `get_mime_type(file_path)` :
  - [ ] Extraire l'extension du fichier
  - [ ] Retourner le MIME type correspondant
  - [ ] Gérer le cas par défaut
- [ ] Fonction `get_status_message(status_code)` :
  - [ ] Retourner le message associé au code de statut
  - [ ] Gérer le cas où le code n'existe pas
- [ ] Fonction `format_log(message, level="INFO")` :
  - [ ] Formater avec timestamp
  - [ ] Ajouter le niveau (INFO, ERROR, WARNING)
  - [ ] Retourner le message formaté

---

##  Phase 4 : Gestion des fichiers (file_manager.py)

- [ ] Fonction `sanitize_path(requested_path)` :
  - [ ] Supprimer les `../` pour éviter les attaques
  - [ ] Normaliser le chemin
  - [ ] Retourner le chemin sécurisé
- [ ] Fonction `resolve_file_path(path)` :
  - [ ] Si path == "/" ou vide, retourner "index.html"
  - [ ] Sinon, construire le chemin complet avec PUBLIC_DIR
  - [ ] Appeler `sanitize_path()` sur le résultat
- [ ] Fonction `file_exists(file_path)` :
  - [ ] Vérifier si le fichier existe
  - [ ] Retourner True/False
- [ ] Fonction `read_file(file_path)` :
  - [ ] Essayer d'ouvrir et lire le fichier
  - [ ] Retourner le contenu en bytes
  - [ ] Gérer l'exception `FileNotFoundError`
  - [ ] Gérer les autres exceptions possibles

---

##  Phase 5 : Construction des réponses (response_builder.py)

- [ ] Fonction `get_error_page(status_code)` :
  - [ ] Créer une page HTML d'erreur personnalisée
  - [ ] Inclure le code et le message d'erreur
  - [ ] Retourner le contenu HTML
- [ ] Fonction `build_status_line(status_code)` :
  - [ ] Construire la ligne "HTTP/1.1 {code} {message}"
  - [ ] Utiliser `get_status_message()` de utils
  - [ ] Retourner la ligne complète
- [ ] Fonction `build_headers(content_length, mime_type)` :
  - [ ] Cr#éer le header `Content-Type`
  - [ ] Créer le header `Content-Length`
  - [ ] Ajouter le header `Connection: close`
  - [ ] Retourner tous les headers formatés
- [ ] Fonction `build_response(status_code, content, mime_type)` :
  - [ ] Construire la ligne de statut
  - [ ] Construire les headers
  - [ ] Assembler : status_line + headers + "\r\n\r\n" + content
  - [ ] Retourner la réponse complète en bytes

---

##  Phase 6 : Gestion HTTP (http_handler.py)

- [ ] Fonction `parse_request(raw_request)` :
  - [ ] Décoder la requête brute
  - [ ] Séparer les lignes
  - [ ] Extraire la première ligne (request line)
  - [ ] Parser : méthode, path, version HTTP
  - [ ] Retourner un dictionnaire avec ces infos
- [ ] Fonction `route_request(method, path)` :
  - [ ] Vérifier que la méthode est GET (sinon retourner 405)
  - [ ] Résoudre le chemin du fichier avec `resolve_file_path()`
  - [ ] Vérifier l'existence avec `file_exists()`
  - [ ] Si existe : lire le fichier et retourner (200, content, mime_type)
  - [ ] Si n'existe pas : retourner (404, error_page, "text/html")
- [ ] Fonction `handle_client(client_socket)` :
  - [ ] Recevoir les données (recv 1024 bytes)
  - [ ] Parser la requête avec `parse_request()`
  - [ ] Logger la requête reçue
  - [ ] Appeler `route_request()` pour obtenir status, content, mime_type
  - [ ] Construire la réponse avec `build_response()`
  - [ ] Envoyer la réponse avec `sendall()`
  - [ ] Fermer la connexion client
  - [ ] Gérer les exceptions globales (retourner 500 en cas d'erreur)

---

##  Phase 7 : Serveur principal (server.py)

- [ ] Importer tous les modules nécessaires
- [ ] Fonction `shutdown_handler(signum, frame)` :
  - [ ] Afficher un message de fermeture
  - [ ] Fermer le socket serveur
  - [ ] Appeler `sys.exit(0)`
- [ ] Fonction `accept_connections(server_socket)` :
  - [ ] Créer une boucle infinie `while True`
  - [ ] Accepter les connexions avec `server_socket.accept()`
  - [ ] Logger l'adresse du client
  - [ ] Appeler `handle_client()` du module http_handler
  - [ ] Gérer les exceptions
- [ ] Fonction `start_server()` :
  - [ ] Logger le démarrage du serveur
  - [ ] Créer le socket TCP/IP
  - [ ] Configurer `SO_REUSEADDR`
  - [ ] Binder le socket sur HOST:PORT
  - [ ] Mettre le socket en écoute (listen)
  - [ ] Logger l'URL d'accès
  - [ ] Appeler `accept_connections()`
  - [ ] Fermer le socket en fin de programme
- [ ] Bloc `if __name__ == "__main__"` :
  - [ ] Configurer le handler de signal pour Ctrl+C
  - [ ] Appeler `start_server()`
  - [ ] Gérer l'exception `KeyboardInterrupt`

---

##  Phase 8 : Tests et validation

- [ ] Tester le serveur de base :
  - [ ] Lancer `python server.py`
  - [ ] Vérifier que le serveur démarre sans erreur
  - [ ] Vérifier les logs de démarrage
- [ ] Tester l'accès à index.html :
  - [ ] Ouvrir `http://localhost:8000/`
  - [ ] Vérifier que la page s'affiche correctement
  - [ ] Vérifier les logs du serveur
- [ ] Tester les fichiers statiques :
  - [ ] Créer un fichier CSS dans `public/`
  - [ ] Créer une image dans `public/`
  - [ ] Accéder à ces fichiers via le navigateur
  - [ ] Vérifier que les MIME types sont corrects
- [ ] Tester les erreurs 404 :
  - [ ] Accéder à `http://localhost:8000/fichier-inexistant.html`
  - [ ] Vérifier la page d'erreur personnalisée
  - [ ] Vérifier le code de statut dans les logs
- [ ] Tester la sécurité :
  - [ ] Essayer d'accéder à `http://localhost:8000/../config.py`
  - [ ] Vérifier que l'accès est refusé
- [ ] Tester l'arrêt propre :
  - [ ] Faire Ctrl+C
  - [ ] Vérifier que le serveur se ferme proprement

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

