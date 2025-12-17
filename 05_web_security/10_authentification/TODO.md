TODO List - Projet Authentification Flask avec Cookies

═══════════════════════════════════════════════════════════════════
 
Phase 1 : Vérification de la structure du projet

═══════════════════════════════════════════════════════════════════

☐ Vérifier l'arborescence complète :
  - ☐ Dossier models/ avec __init__.py
  - ☐ Dossier routes/ avec __init__.py
  - ☐ Dossier utils/ avec __init__.py
  - ☐ Dossier static/ avec css/ et js/
  - ☐ Dossier instance/ (sera créé automatiquement)
  - ☐ Fichier config.py à la racine
  - ☐ Fichier app.py à la racine
  - ☐ Fichier init_db.py à la racine
  - ☐ Fichier requirements.txt

☐ Créer les fichiers Python vides :
  - ☐ models/user.py
  - ☐ routes/auth.py
  - ☐ routes/main.py
  - ☐ utils/db.py

═══════════════════════════════════════════════════════════════════
 
Phase 2 : Configuration (config.py)

═══════════════════════════════════════════════════════════════════

☐ Définir les constantes de configuration :
  - ☐ SECRET_KEY (générer une clé aléatoire sécurisée)
  - ☐ DATABASE_PATH = 'instance/database.db'
  - ☐ SESSION_COOKIE_SECURE = False (True en production)
  - ☐ SESSION_COOKIE_HTTPONLY = True
  - ☐ SESSION_COOKIE_SAMESITE = 'Lax'
  - ☐ PERMANENT_SESSION_LIFETIME (ex: 30 jours)

☐ Ajouter les paramètres de sécurité :
  - ☐ PASSWORD_MIN_LENGTH = 8
  - ☐ USERNAME_MIN_LENGTH = 3
  - ☐ MAX_LOGIN_ATTEMPTS = 5

═══════════════════════════════════════════════════════════════════
 
Phase 3 : Initialisation de la base de données

═══════════════════════════════════════════════════════════════════

☐ Finaliser le script init_db.py :
  - ☐ Corriger les erreurs SQL (déjà fait !)
  - ☐ Ajouter un print de confirmation
  - ☐ Gérer les exceptions potentielles

☐ Exécuter le script :
  - ☐ Lancer python init_db.py
  - ☐ Vérifier que database.db est créé dans instance/
  - ☐ Vérifier les tables avec sqlite3 (optionnel)

═══════════════════════════════════════════════════════════════════
 
Phase 4 : Utilitaires base de données (utils/db.py)

═══════════════════════════════════════════════════════════════════

☐ Fonction get_db_connection() :
  - ☐ Se connecter à la base de données
  - ☐ Configurer row_factory pour dict-like access
  - ☐ Retourner la connexion

☐ Fonction close_db_connection(conn) :
  - ☐ Fermer proprement la connexion
  - ☐ Gérer les exceptions

☐ Fonction execute_query(query, params=(), fetch_one=False) :
  - ☐ Ouvrir une connexion
  - ☐ Exécuter la requête avec les paramètres
  - ☐ Retourner un résultat (fetch_one ou fetch_all)
  - ☐ Fermer la connexion
  - ☐ Gérer les exceptions

═══════════════════════════════════════════════════════════════════
 
Phase 5 : Modèle User (models/user.py)

═══════════════════════════════════════════════════════════════════

☐ Importer werkzeug.security (generate_password_hash, check_password_hash)

☐ Fonction create_user(username, password) :
  - ☐ Valider le username (longueur, caractères autorisés)
  - ☐ Valider le password (longueur minimale)
  - ☐ Hasher le mot de passe avec generate_password_hash()
  - ☐ Insérer dans la table users
  - ☐ Gérer l'exception UNIQUE (username déjà pris)
  - ☐ Retourner True/False ou l'id_user

☐ Fonction get_user_by_username(username) :
  - ☐ Requête SELECT avec WHERE username = ?
  - ☐ Retourner le dictionnaire user ou None

☐ Fonction get_user_by_id(user_id) :
  - ☐ Requête SELECT avec WHERE id_user = ?
  - ☐ Retourner le dictionnaire user ou None

☐ Fonction verify_password(username, password) :
  - ☐ Récupérer l'utilisateur avec get_user_by_username()
  - ☐ Vérifier le mot de passe avec check_password_hash()
  - ☐ Retourner True/False

☐ Fonction get_all_users() :
  - ☐ Requête SELECT * FROM users
  - ☐ Retourner la liste des utilisateurs (sans password_hash !)

═══════════════════════════════════════════════════════════════════
 
Phase 6 : Gestion des sessions (models/user.py ou utils/session.py)

═══════════════════════════════════════════════════════════════════

☐ Fonction create_session_token(user_id, duration_days=30) :
  - ☐ Générer un token aléatoire sécurisé (secrets.token_urlsafe())
  - ☐ Calculer expires_at (datetime.now() + timedelta)
  - ☐ Insérer dans la table sessions
  - ☐ Retourner le token

☐ Fonction validate_session_token(token) :
  - ☐ Requête SELECT avec WHERE token = ?
  - ☐ Vérifier que expires_at > maintenant
  - ☐ Retourner user_id ou None

☐ Fonction delete_session_token(token) :
  - ☐ Requête DELETE avec WHERE token = ?
  - ☐ Commit

☐ Fonction cleanup_expired_sessions() :
  - ☐ Requête DELETE avec WHERE expires_at < maintenant
  - ☐ (Bonus : à exécuter périodiquement)

═══════════════════════════════════════════════════════════════════
 
Phase 7 : Routes principales (routes/main.py)

═══════════════════════════════════════════════════════════════════

☐ Créer le Blueprint 'main'

☐ Route GET / (page d'accueil) :
  - ☐ Vérifier si l'utilisateur est connecté (session['user_id'])
  - ☐ Si oui, rediriger vers /dashboard
  - ☐ Sinon, afficher how_it_works.html

☐ Route GET /dashboard :
  - ☐ Vérifier si l'utilisateur est connecté
  - ☐ Si non, rediriger vers /login
  - ☐ Récupérer les infos user avec get_user_by_id()
  - ☐ Afficher base.html avec les infos user

☐ Route GET /users :
  - ☐ Vérifier si l'utilisateur est connecté
  - ☐ Si non, rediriger vers /login
  - ☐ Récupérer tous les users avec get_all_users()
  - ☐ Afficher users.html avec la liste

☐ Fonction helper is_logged_in() :
  - ☐ Vérifier 'user_id' in session
  - ☐ Retourner True/False
  - ☐ (Bonus : créer un décorateur @login_required)

═══════════════════════════════════════════════════════════════════
 
Phase 8 : Routes d'authentification (routes/auth.py)

═══════════════════════════════════════════════════════════════════

☐ Créer le Blueprint 'auth'

☐ Route GET /register :
  - ☐ Afficher register.html

☐ Route POST /register :
  - ☐ Récupérer username et password du formulaire
  - ☐ Valider les données (longueur, format)
  - ☐ Vérifier que les mots de passe correspondent (si confirmation)
  - ☐ Appeler create_user()
  - ☐ Si succès : rediriger vers /login avec message de succès
  - ☐ Si échec : réafficher le formulaire avec erreur
  - ☐ Gérer les cas : username déjà pris, mot de passe trop court

☐ Route GET /login :
  - ☐ Si déjà connecté, rediriger vers /dashboard
  - ☐ Sinon, afficher login.html

☐ Route POST /login :
  - ☐ Récupérer username et password
  - ☐ Appeler verify_password()
  - ☐ Si succès :
    - ☐ Stocker user_id dans session['user_id']
    - ☐ Si "Remember me" coché :
      - ☐ Créer un token de session avec create_session_token()
      - ☐ Stocker le token dans un cookie persistant
    - ☐ Rediriger vers /dashboard
  - ☐ Si échec :
    - ☐ Réafficher login.html avec message d'erreur
    - ☐ (Bonus : limiter les tentatives)

☐ Route GET /logout :
  - ☐ Supprimer session['user_id']
  - ☐ Si cookie de session existe :
    - ☐ Récupérer le token
    - ☐ Appeler delete_session_token()
    - ☐ Supprimer le cookie
  - ☐ Rediriger vers /

═══════════════════════════════════════════════════════════════════
 
Phase 9 : Application principale (app.py)

═══════════════════════════════════════════════════════════════════

☐ Importer Flask et les modules nécessaires

☐ Créer l'instance Flask :
  - ☐ app = Flask(__name__)

☐ Charger la configuration :
  - ☐ app.config.from_object('config')
  - ☐ ou app.config['SECRET_KEY'] = config.SECRET_KEY

☐ Enregistrer les Blueprints :
  - ☐ from routes.main import main_bp
  - ☐ from routes.auth import auth_bp
  - ☐ app.register_blueprint(main_bp)
  - ☐ app.register_blueprint(auth_bp)

☐ Ajouter un before_request pour les sessions persistantes :
  - ☐ Vérifier si un cookie de session existe
  - ☐ Valider le token avec validate_session_token()
  - ☐ Si valide, restaurer session['user_id']

☐ Bloc if __name__ == '__main__' :
  - ☐ app.run(debug=True, host='0.0.0.0', port=5000)

═══════════════════════════════════════════════════════════════════
 
Phase 10 : Fichiers statiques (static/)

═══════════════════════════════════════════════════════════════════

☐ Créer static/css/style.css :
  - ☐ Styles de base pour les formulaires
  - ☐ Styles pour les messages d'erreur/succès
  - ☐ Design responsive (optionnel)

☐ Créer static/js/script.js (optionnel) :
  - ☐ Validation côté client des formulaires
  - ☐ Animations/transitions
  - ☐ Gestion des messages flash

═══════════════════════════════════════════════════════════════════
 
Phase 11 : Tests de sécurité et validation

═══════════════════════════════════════════════════════════════════

☐ Test du système d'inscription :
  - ☐ Créer un compte avec des données valides
  - ☐ Vérifier que le mot de passe est bien hashé en DB
  - ☐ Essayer de créer un compte avec un username existant
  - ☐ Essayer avec un mot de passe trop court
  - ☐ Essayer avec des caractères spéciaux

☐ Test du système de connexion :
  - ☐ Se connecter avec des identifiants valides
  - ☐ Vérifier la redirection vers /dashboard
  - ☐ Essayer avec un mauvais mot de passe
  - ☐ Essayer avec un username inexistant
  - ☐ Tester le "Remember me"

☐ Test des sessions :
  - ☐ Vérifier que session['user_id'] est bien défini
  - ☐ Fermer le navigateur et rouvrir (avec Remember me)
  - ☐ Vérifier la persistance du cookie
  - ☐ Tester l'expiration du cookie (modifier expires_at)

☐ Test de la déconnexion :
  - ☐ Se déconnecter
  - ☐ Vérifier que la session est bien supprimée
  - ☐ Vérifier que le cookie est supprimé
  - ☐ Essayer d'accéder à /dashboard après déconnexion

☐ Tests de sécurité :
  - ☐ SQL Injection sur le formulaire de login
    - ☐ Essayer : username = ' OR '1'='1
    - ☐ Vérifier que l'attaque échoue (paramètres liés)
  - ☐ XSS sur les formulaires :
    - ☐ Essayer : username = <script>alert('XSS')</script>
    - ☐ Vérifier que le code n'est pas exécuté
  - ☐ CSRF :
    - ☐ Vérifier que Flask-WTF ou des tokens CSRF sont utilisés
    - ☐ (Bonus : implémenter Flask-WTF)
  - ☐ Session Fixation :
    - ☐ Vérifier que session.regenerate() est appelé après login
  - ☐ Cookie Hijacking :
    - ☐ Vérifier les flags HttpOnly, Secure, SameSite
    - ☐ Inspecter les cookies dans le navigateur (F12)

☐ Test de protection des routes :
  - ☐ Essayer d'accéder à /dashboard sans être connecté
  - ☐ Essayer d'accéder à /users sans être connecté
  - ☐ Vérifier les redirections appropriées

═══════════════════════════════════════════════════════════════════
 
Phase 12 : Renforcement de la sécurité (Important pour le cours !)

═══════════════════════════════════════════════════════════════════

☐ Ajouter la protection CSRF :
  - ☐ Installer flask-wtf : pip install flask-wtf
  - ☐ Configurer CSRFProtect dans app.py
  - ☐ Ajouter {{ csrf_token() }} dans les formulaires

☐ Sécuriser les cookies :
  - ☐ Vérifier SESSION_COOKIE_HTTPONLY = True
  - ☐ Vérifier SESSION_COOKIE_SAMESITE = 'Lax'
  - ☐ En production : SESSION_COOKIE_SECURE = True

☐ Ajouter la limitation des tentatives de connexion :
  - ☐ Créer une table login_attempts (optionnel)
  - ☐ Ou utiliser un dictionnaire en mémoire
  - ☐ Bloquer après N tentatives échouées
  - ☐ Ajouter un timeout avant réessai

☐ Validation et sanitization des entrées :
  - ☐ Vérifier les longueurs min/max
  - ☐ Filtrer les caractères dangereux
  - ☐ Utiliser des regex pour valider le format

☐ Gestion des erreurs sécurisée :
  - ☐ Ne jamais révéler d'infos sensibles dans les messages
  - ☐ Ex : "Identifiants incorrects" au lieu de "Username inexistant"
  - ☐ Logger les erreurs côté serveur, pas côté client

☐ Headers de sécurité :
  - ☐ X-Content-Type-Options: nosniff
  - ☐ X-Frame-Options: DENY
  - ☐ Content-Security-Policy (bonus)

═══════════════════════════════════════════════════════════════════
 
Phase 13 : Logging et monitoring

═══════════════════════════════════════════════════════════════════

☐ Configurer le système de logging :
  - ☐ Importer logging
  - ☐ Configurer le niveau (DEBUG, INFO, WARNING, ERROR)
  - ☐ Créer un fichier de logs (optionnel)

☐ Logger les événements importants :
  - ☐ Tentatives de connexion (succès/échec)
  - ☐ Créations de comptes
  - ☐ Déconnexions
  - ☐ Tentatives d'accès non autorisé
  - ☐ Erreurs SQL

☐ Format des logs :
  - ☐ Timestamp
  - ☐ Niveau (INFO, WARNING, ERROR)
  - ☐ Action effectuée
  - ☐ Username concerné (si applicable)
  - ☐ Adresse IP (optionnel)

═══════════════════════════════════════════════════════════════════
 
Phase 14 : Gestion des dépendances

═══════════════════════════════════════════════════════════════════

☐ Créer requirements.txt :
  - ☐ Flask==3.0.0 (ou version actuelle)
  - ☐ Werkzeug==3.0.0
  - ☐ flask-wtf (si utilisé pour CSRF)

☐ Documenter l'installation :
  - ☐ python -m venv venv
  - ☐ source venv/bin/activate (ou venv\Scripts\activate sur Windows)
  - ☐ pip install -r requirements.txt

═══════════════════════════════════════════════════════════════════
 
Phase 15 : Documentation

═══════════════════════════════════════════════════════════════════

☐ Créer README.md :
  - ☐ Description du projet (objectifs pédagogiques)
  - ☐ Architecture du projet
  - ☐ Instructions d'installation
  - ☐ Instructions d'utilisation
  - ☐ Fonctionnalités implémentées
  - ☐ Mesures de sécurité mises en place
  - ☐ Vulnérabilités testées

☐ Ajouter des docstrings :
  - ☐ Documenter chaque fonction
  - ☐ Expliquer les paramètres
  - ☐ Expliquer les valeurs de retour
  - ☐ Ajouter des exemples si nécessaire

☐ Commenter le code :
  - ☐ Expliquer les parties complexes
  - ☐ Marquer les points de sécurité importants
  - ☐ Documenter les choix techniques

═══════════════════════════════════════════════════════════════════
 
Phase 16 : Améliorations bonus

═══════════════════════════════════════════════════════════════════

☐ Ajouter un système de "Mot de passe oublié" :
  - ☐ Génération de token de réinitialisation
  - ☐ Email de récupération (ou affichage console)
  - ☐ Page de réinitialisation

☐ Ajouter des rôles utilisateurs :
  - ☐ Table roles (admin, user, etc.)
  - ☐ Restriction d'accès selon les rôles
  - ☐ Décorateur @admin_required

☐ Dashboard administrateur :
  - ☐ Liste de tous les utilisateurs
  - ☐ Statistiques de connexion
  - ☐ Logs d'activité

☐ Amélioration de l'UX :
  - ☐ Messages flash pour feedback utilisateur
  - ☐ Animations CSS
  - ☐ Validation en temps réel côté client

☐ Double authentification (2FA) :
  - ☐ Génération de codes TOTP
  - ☐ QR code pour configuration
  - ☐ Vérification du code à la connexion

═══════════════════════════════════════════════════════════════════
 
Phase finale : Validation du projet

═══════════════════════════════════════════════════════════════════

☐ Checklist de sécurité finale :
  - ☐ Mots de passe hashés (jamais en clair)
  - ☐ Requêtes SQL paramétrées (protection SQL injection)
  - ☐ Validation et sanitization des entrées
  - ☐ Protection CSRF implémentée
  - ☐ Cookies sécurisés (HttpOnly, SameSite)
  - ☐ Sessions gérées correctement
  - ☐ Gestion des erreurs sans fuite d'infos
  - ☐ Limitation des tentatives de connexion

☐ Checklist fonctionnelle :
  - ☐ Inscription fonctionne
  - ☐ Connexion fonctionne
  - ☐ Déconnexion fonctionne
  - ☐ Remember me fonctionne
  - ☐ Protection des routes fonctionne
  - ☐ Tous les templates s'affichent correctement

☐ Relecture du code :
  - ☐ Supprimer les print() de debug
  - ☐ Vérifier l'indentation
  - ☐ Vérifier les noms de variables
  - ☐ Supprimer le code commenté inutile

☐ Tests finaux :
  - ☐ Tester avec plusieurs navigateurs
  - ☐ Tester avec les DevTools (cookies, sessions)
  - ☐ Tester les cas limites
  - ☐ Vérifier les logs

☐ Documentation finale :
  - ☐ README complet
  - ☐ Code commenté
  - ☐ Rapport de sécurité (pour le cours)

☐ Commit et archivage :
  - ☐ Git init (si pas déjà fait)
  - ☐ .gitignore (venv/, instance/, __pycache__/)
  - ☐ Commits atomiques et descriptifs
  - ☐ Push sur GitHub/GitLab

═══════════════════════════════════════════════════════════════════
 
Phase bonus : Rapport pour le cours
═══════════════════════════════════════════════════════════════════

☐ Créer un document de synthèse :
  - ☐ Vulnérabilités identifiées et testées
  - ☐ Mesures de protection implémentées
  - ☐ Captures d'écran des tests
  - ☐ Explication des choix techniques
  - ☐ Limitations connues
  - ☐ Pistes d'amélioration

☐ Démonstration des attaques :
  - ☐ Screenshots de tentatives de SQL injection
  - ☐ Screenshots de tentatives XSS
  - ☐ Analyse des cookies dans le navigateur
  - ☐ Preuves que les protections fonctionnent

═══════════════════════════════════════════════════════════════════