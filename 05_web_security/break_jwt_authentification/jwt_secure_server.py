#!/usr/bin/env python3
"""
Serveur Flask SÉCURISÉ - Protection contre l'attaque JWT "none"

Ce code montre les bonnes pratiques pour sécuriser les endpoints JWT.
"""

from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
SECRET_KEY = "sup3rs3cr3t"

# Liste blanche des algorithmes autorisés
ALLOWED_ALGORITHMS = ['HS256']  # NE JAMAIS inclure 'none'

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
    Endpoint admin SÉCURISÉ

    PROTECTIONS:
    - Whitelist explicite des algorithmes (ALLOWED_ALGORITHMS)
    - Vérification obligatoire de la signature
    - Vérification de l'expiration
    - Validation du rôle
    """
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]

    try:
        # SÉCURISÉ: Whitelist explicite + vérification de signature activée
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=ALLOWED_ALGORITHMS,  # Uniquement HS256
            options={
                "verify_signature": True,    # Vérification obligatoire
                "verify_exp": True,          # Vérifier l'expiration
                "require": ["exp", "user_id", "role"]  # Champs requis
            }
        )

        # Validation supplémentaire du rôle
        if payload.get('role') != 'admin':
            return jsonify({
                'error': 'Insufficient privileges',
                'required_role': 'admin',
                'your_role': payload.get('role')
            }), 403

        return jsonify({
            'message': 'Welcome to admin panel!',
            'user': payload
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidSignatureError:
        return jsonify({'error': 'Invalid signature'}), 401
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token format'}), 401
    except jwt.InvalidAlgorithmError:
        return jsonify({'error': 'Invalid algorithm'}), 401
    except Exception as e:
        return jsonify({'error': f'Token validation failed: {str(e)}'}), 401


@app.route('/profile', methods=['GET'])
def profile():
    """Endpoint de profil - également sécurisé"""
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]

    try:
        # Même niveau de sécurité
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=ALLOWED_ALGORITHMS,
            options={
                "verify_signature": True,
                "verify_exp": True
            }
        )

        user_id = payload.get('user_id')
        user = users_db.get(user_id, {})

        return jsonify({
            'message': 'Profile retrieved',
            'token_data': payload,
            'database': user
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidSignatureError:
        return jsonify({'error': 'Invalid signature'}), 401
    except Exception as e:
        return jsonify({'error': f'Token validation failed: {str(e)}'}), 401


@app.route('/')
def home():
    """Page d'accueil avec instructions"""
    return jsonify({
        'message': 'JWT Secure Server',
        'security': {
            'allowed_algorithms': ALLOWED_ALGORITHMS,
            'signature_verification': 'enabled',
            'expiration_check': 'enabled'
        },
        'endpoints': {
            'POST /login': 'Login with username=user, password=password',
            'GET /admin': 'Admin panel (requires admin role)',
            'GET /profile': 'User profile'
        }
    })


if __name__ == '__main__':
    print("="*70)
    print("SERVEUR SÉCURISÉ JWT - BONNES PRATIQUES")
    print("="*70)
    print()
    print("Ce serveur est protégé contre l'attaque 'none':")
    print("  - Whitelist d'algorithmes:", ALLOWED_ALGORITHMS)
    print("  - Vérification de signature activée")
    print("  - Vérification de l'expiration")
    print("  - Validation stricte des claims")
    print()
    print("Endpoints disponibles:")
    print("  POST /login       - Authentification (user:password)")
    print("  GET  /admin       - Panel admin (nécessite role=admin)")
    print("  GET  /profile     - Profil utilisateur")
    print()
    print("Pour tester:")
    print("  1. Obtenez un token: curl -X POST http://localhost:5003/login \\")
    print("                            -H 'Content-Type: application/json' \\")
    print("                            -d '{\"username\":\"user\",\"password\":\"password\"}'")
    print()
    print("  2. Essayez d'utiliser un token forgé (il sera rejeté)")
    print()
    print("="*70)
    print()

    app.run(debug=True, host='0.0.0.0', port=5003)
