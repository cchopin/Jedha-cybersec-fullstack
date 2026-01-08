#!/usr/bin/env python3
"""
Script de configuration Cisco via console TCP (GNS3)
Lab 35 - OSPF Basics

Ce script se connecte à un routeur Cisco via la console TCP de GNS3
et exécute les commandes passées via la variable d'environnement ROUTER_COMMANDS.

Usage:
    export ROUTER_HOST="192.168.144.120"
    export ROUTER_PORT="5001"
    export ROUTER_COMMANDS="show ip ospf neighbor"
    python3 cisco_cli.py
"""

import os
import socket
import time
import sys


class CiscoConsole:
    """Client console Cisco via socket TCP"""

    def __init__(self, host: str, port: int, timeout: int = 10, verbose: bool = True):
        """
        Initialise la connexion console.

        Args:
            host: Adresse IP du serveur GNS3
            port: Port console du routeur
            timeout: Timeout de connexion en secondes
            verbose: Afficher les commandes et réponses
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.sock = None
        self.buffer = ""

    def connect(self) -> bool:
        """Établit la connexion TCP"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            if self.verbose:
                print(f"[+] Connecté à {self.host}:{self.port}")
            # Attendre l'invite initiale
            time.sleep(1)
            self._read_until_prompt()
            return True
        except socket.error as e:
            print(f"[-] Erreur de connexion: {e}")
            return False

    def disconnect(self):
        """Ferme la connexion"""
        if self.sock:
            self.sock.close()
            if self.verbose:
                print("[+] Déconnecté")

    def _read_until_prompt(self, timeout: float = 2.0) -> str:
        """
        Lit jusqu'à trouver un prompt Cisco.

        Args:
            timeout: Temps max d'attente

        Returns:
            Données lues
        """
        self.sock.settimeout(timeout)
        data = ""
        try:
            while True:
                chunk = self.sock.recv(4096).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                data += chunk
                # Vérifier si on a un prompt
                if any(p in data for p in ['>', '#', 'Password:', 'Username:']):
                    # Continuer à lire un peu plus
                    self.sock.settimeout(0.5)
        except socket.timeout:
            pass
        return data

    def send(self, command: str, wait: float = 0.5) -> str:
        """
        Envoie une commande et attend la réponse.

        Args:
            command: Commande à envoyer
            wait: Temps d'attente après envoi

        Returns:
            Réponse du routeur
        """
        if self.verbose:
            print(f">>> {command}")

        # Envoyer la commande
        self.sock.send((command + "\r\n").encode())
        time.sleep(wait)

        # Lire la réponse
        response = self._read_until_prompt()

        if self.verbose and response.strip():
            # Filtrer l'écho de la commande
            lines = response.split('\n')
            for line in lines:
                line = line.strip()
                if line and line != command:
                    print(f"<<< {line}")

        return response

    def enable_mode(self) -> bool:
        """Passe en mode enable"""
        response = self.send("enable")
        if "Password:" in response:
            self.send("")  # Pas de mot de passe par défaut
        return True

    def config_mode(self) -> bool:
        """Passe en mode configuration"""
        self.send("configure terminal")
        return True

    def exit_config(self):
        """Sort du mode configuration"""
        self.send("end")

    def run_commands(self, commands: list) -> list:
        """
        Exécute une liste de commandes.

        Args:
            commands: Liste de commandes

        Returns:
            Liste des réponses
        """
        responses = []
        for cmd in commands:
            cmd = cmd.strip()
            if cmd and not cmd.startswith('!'):
                response = self.send(cmd)
                responses.append(response)
        return responses


def main():
    """Point d'entrée principal"""
    # Récupérer les variables d'environnement
    host = os.environ.get('ROUTER_HOST', '192.168.144.120')
    port = int(os.environ.get('ROUTER_PORT', '5000'))
    commands_str = os.environ.get('ROUTER_COMMANDS', '')

    if not commands_str:
        print("[-] Aucune commande fournie (ROUTER_COMMANDS vide)")
        sys.exit(1)

    # Parser les commandes
    commands = [cmd.strip() for cmd in commands_str.split('\n') if cmd.strip()]

    print(f"[*] Configuration du routeur sur {host}:{port}")
    print(f"[*] Nombre de commandes: {len(commands)}")

    # Créer la connexion
    console = CiscoConsole(host, port, verbose=True)

    if not console.connect():
        print("[-] Échec de la connexion")
        sys.exit(1)

    try:
        # Envoyer un retour chariot pour réveiller la console
        console.send("")

        # Exécuter les commandes
        console.run_commands(commands)

        print("[+] Configuration terminée")

    except Exception as e:
        print(f"[-] Erreur: {e}")
        sys.exit(1)

    finally:
        console.disconnect()


if __name__ == "__main__":
    main()
