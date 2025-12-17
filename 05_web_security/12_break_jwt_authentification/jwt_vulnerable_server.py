#!/usr/bin/env python3
"""
Serveur Flask VULNÉRABLE acceptant l'algorithme JWT "none"

ATTENTION: Ce code est volontairement vulnérable à des fins pédagogiques.
Ne JAMAIS utiliser en production.
"""

from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
SECRET_KEY = "sup3rs3cr3t"

# Base de données simulée
users_db = {
    1: {"user_id": 1, "username": "admin", "role": "admin"},
    5: {"user_id": 5, "username": "user", "role": "user"}
}


@app.route('/login', methods=['POST'])
def login():
    """Endpoint de connexion - génère un JWT"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Authentification simplifiée (pour la démo)
    if username == "user" and password == "password":
        # Créer un JWT pour l'utilisateur normal
        payload = {
            'user_id': 5,
            'username': 'user',
            'role': 'user',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/admin', methods=['GET'])
def admin_panel():
    """
    Endpoint admin VULNÉRABLE

    VULNÉRABILITÉ: Accepte l'algorithme 'none' en utilisant verify_signature=False
    ou en ne spécifiant pas les algorithmes autorisés.
    """
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]

    try:
        # VULNÉRABLE: Ne vérifie pas la signature et accepte tous les algorithmes
        # Méthode 1: verify_signature=False (ancienne version PyJWT)
        # payload = jwt.decode(token, options={"verify_signature": False})

        # Méthode 2: algorithms inclut "none" ou pas de vérification stricte
        # En PyJWT moderne, il faut explicitement désactiver la vérification
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256', 'none'],  # VULNÉRABILITÉ: accepte "none"
            options={"verify_signature": False}  # VULNÉRABILITÉ: pas de vérif
        )

        # Vérifier le rôle
        if payload.get('role') == 'admin':
            return jsonify({
                'message': 'Welcome to admin panel!',
                'user': payload
            }), 200
        else:
            return jsonify({'error': 'Insufficient privileges'}), 403

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401


@app.route('/profile', methods=['GET'])
def profile():
    """Endpoint de profil - également vulnérable"""
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]

    try:
        # Même vulnérabilité
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256', 'none'],
            options={"verify_signature": False}
        )

        user_id = payload.get('user_id')
        user = users_db.get(user_id, {})

        return jsonify({
            'message': 'Profile retrieved',
            'user': payload,
            'database': user
        }), 200

    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401


@app.route('/')
def home():
    """Page d'accueil avec instructions"""
    return jsonify({
        'message': 'JWT Vulnerable Server',
        'endpoints': {
            'POST /login': 'Login with username=user, password=password',
            'GET /admin': 'Admin panel (requires admin role)',
            'GET /profile': 'User profile'
        },
        'warning': 'This server is INTENTIONALLY VULNERABLE for educational purposes'
    })


if __name__ == '__main__':
    print("="*70)
    print("SERVEUR VULNÉRABLE JWT - DÉMO PÉDAGOGIQUE")
    print("="*70)
    print()
    print("Ce serveur accepte l'algorithme 'none' et ne vérifie pas les signatures.")
    print()
    print("Endpoints disponibles:")
    print("  POST /login       - Authentification (user:password)")
    print("  GET  /admin       - Panel admin (nécessite role=admin)")
    print("  GET  /profile     - Profil utilisateur")
    print()
    print("Pour tester l'attaque:")
    print("  1. Obtenez un token: curl -X POST http://localhost:5002/login \\")
    print("                            -H 'Content-Type: application/json' \\")
    print("                            -d '{\"username\":\"user\",\"password\":\"password\"}'")
    print()
    print("  2. Utilisez jwt_none_attack.py pour forger un token admin")
    print()
    print("  3. Testez: curl http://localhost:5002/admin \\")
    print("                  -H 'Authorization: Bearer <forged_token>'")
    print()
    print("="*70)
    print()

    app.run(debug=True, host='0.0.0.0', port=5002)
