#!/usr/bin/env python3
"""
Script pour envoyer des commandes a un equipement Cisco via console GNS3.

Ce script permet de se connecter au port console d'un equipement GNS3
(switch, routeur, VPC) et d'executer des commandes.

Usage:
    # Executer plusieurs commandes
    python3 cisco_cli.py --host IP_GNS3 --port PORT --commands "cmd1;cmd2;cmd3"

    # Executer une commande show
    python3 cisco_cli.py --host IP_GNS3 --port PORT --show "show vlan brief"

    # Depuis un fichier
    python3 cisco_cli.py --host IP_GNS3 --port PORT --commands-file commands.txt

Exemples:
    python3 cisco_cli.py --host 192.168.190.174 --port 5000 --show "show vlan brief"
    python3 cisco_cli.py --host 192.168.190.174 --port 5000 --commands "enable;conf t;hostname SW1;end"

Auteur: Formation Jedha - Network Security
"""

import socket
import time
import argparse
import re
import sys


class CiscoConsole:
    """
    Gere la connexion console vers un equipement Cisco/VPC dans GNS3.

    Cette classe utilise des sockets TCP bruts (pas SSH, pas telnet)
    pour communiquer avec le port console expose par GNS3.
    """

    def __init__(self, host, port, timeout=30):
        """
        Initialise la connexion.

        Args:
            host: Adresse IP du serveur GNS3
            port: Port console de l'equipement (ex: 5000)
            timeout: Timeout en secondes pour les operations
        """
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.socket = None

    def connect(self):
        """
        Ouvre la connexion TCP vers le port console.

        Cette methode:
        1. Cree un socket TCP
        2. Se connecte au serveur GNS3 sur le port console
        3. Attend et vide le banner initial de l'equipement
        4. "Reveille" le prompt en envoyant un retour chariot
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)

        try:
            self.socket.connect((self.host, self.port))
        except socket.error as e:
            print(f"ERREUR: Impossible de se connecter a {self.host}:{self.port}")
            print(f"Details: {e}")
            print("\nVerifiez que:")
            print("  - Le serveur GNS3 est demarre")
            print("  - L'equipement est demarre dans GNS3")
            print("  - Le port console est correct")
            sys.exit(1)

        # Attendre que l'equipement envoie son banner
        time.sleep(1)
        self._read_buffer()

        # Envoyer un retour chariot pour reveiller le prompt
        self.send("")
        time.sleep(0.5)

    def disconnect(self):
        """Ferme proprement la connexion."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    def _read_buffer(self):
        """
        Lit tout ce qui est disponible dans le buffer de reception.

        Returns:
            Le texte recu, nettoye des caracteres de controle
        """
        response = b""
        self.socket.setblocking(False)

        try:
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk
        except (BlockingIOError, socket.error):
            # Plus rien a lire - c'est normal
            pass

        self.socket.setblocking(True)

        # Decoder et nettoyer
        text = response.decode('utf-8', errors='ignore')
        return self._clean_output(text)

    def _clean_output(self, text):
        """
        Nettoie la sortie des caracteres de controle Cisco.

        Les equipements Cisco envoient des codes ANSI (couleurs),
        des backspaces, et d'autres caracteres qu'il faut supprimer
        pour avoir une sortie lisible.

        Args:
            text: Texte brut recu de l'equipement

        Returns:
            Texte nettoye
        """
        # Supprimer les sequences d'echappement ANSI
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)

        # Supprimer les backspaces et le caractere precedent
        while '\x08' in text:
            text = re.sub(r'.\x08', '', text)

        # Supprimer le prompt "--More--" de pagination
        text = re.sub(r'--More--\s*', '', text)

        # Supprimer les caracteres nuls
        text = text.replace('\x00', '')

        return text

    def send(self, command, wait_time=1):
        """
        Envoie une commande et retourne la reponse.

        Args:
            command: La commande a envoyer (sans retour chariot)
            wait_time: Temps d'attente apres l'envoi (en secondes)

        Returns:
            La reponse de l'equipement
        """
        # Envoyer la commande avec retour chariot
        self.socket.send((command + "\r\n").encode())

        # Attendre que l'equipement traite la commande
        time.sleep(wait_time)

        # Lire et retourner la reponse
        return self._read_buffer()

    def enable_mode(self):
        """
        Entre en mode enable (privilegie) sur un switch Cisco.

        Note: Sur GNS3, il n'y a generalement pas de mot de passe enable.
        """
        return self.send("enable")

    def config_mode(self):
        """Entre en mode configuration globale."""
        self.enable_mode()
        return self.send("configure terminal")

    def exit_config(self):
        """Sort du mode configuration."""
        return self.send("end")

    def save_config(self):
        """Sauvegarde la configuration en memoire."""
        return self.send("write memory", wait_time=3)

    def execute_commands(self, commands):
        """
        Execute une liste de commandes.

        Args:
            commands: Liste de commandes OU string avec ; comme separateur

        Returns:
            Liste des resultats [{command, output}, ...]
        """
        # Convertir string en liste si necessaire
        if isinstance(commands, str):
            commands = [c.strip() for c in commands.split(';') if c.strip()]

        results = []
        for cmd in commands:
            # Temps d'attente plus long pour certaines commandes
            wait = 2 if any(x in cmd.lower() for x in ['show', 'write', 'copy']) else 1

            output = self.send(cmd, wait_time=wait)
            print(f">>> {cmd}")
            if output.strip():
                # N'afficher que les lignes non-vides significatives
                for line in output.split('\n'):
                    line = line.strip()
                    if line and not line.endswith('#') and not line.endswith('>'):
                        print(f"    {line}")

            results.append({
                'command': cmd,
                'output': output
            })

        return results

    def execute_show(self, command):
        """
        Execute une commande show et affiche le resultat proprement.

        Args:
            command: La commande show a executer
        """
        self.enable_mode()
        output = self.send(command, wait_time=2)

        # Afficher proprement
        lines = output.split('\n')
        for line in lines:
            line = line.rstrip()
            # Ignorer les lignes de prompt
            if line and not re.match(r'^[\w-]+[#>]\s*$', line):
                print(line)


def main():
    """Point d'entree principal du script."""
    parser = argparse.ArgumentParser(
        description='Envoyer des commandes Cisco via la console GNS3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s --host 192.168.190.174 --port 5000 --show "show vlan brief"
  %(prog)s --host 192.168.190.174 --port 5000 --commands "enable;conf t;hostname SW1;end"
  %(prog)s --host 192.168.190.174 --port 5001 --commands "ip 192.168.10.10 255.255.255.0;save"
        """
    )

    parser.add_argument('--host', required=True,
                        help='Adresse IP du serveur GNS3')
    parser.add_argument('--port', required=True,
                        help='Port console de l\'equipement')
    parser.add_argument('--commands',
                        help='Commandes a executer (separees par ;)')
    parser.add_argument('--commands-file',
                        help='Fichier contenant les commandes (une par ligne)')
    parser.add_argument('--show',
                        help='Commande show a executer')
    parser.add_argument('--timeout', default=30, type=int,
                        help='Timeout en secondes (defaut: 30)')

    args = parser.parse_args()

    # Verifier qu'on a au moins une action
    if not any([args.commands, args.commands_file, args.show]):
        parser.error("Specifiez --commands, --commands-file, ou --show")

    # Creer la connexion
    console = CiscoConsole(args.host, args.port, args.timeout)

    try:
        print(f"Connexion a {args.host}:{args.port}...")
        console.connect()
        print("Connecte!\n")

        if args.show:
            # Mode show : une seule commande
            console.execute_show(args.show)

        elif args.commands:
            # Mode commands : plusieurs commandes separees par ;
            console.execute_commands(args.commands)

        elif args.commands_file:
            # Mode fichier : lire les commandes depuis un fichier
            with open(args.commands_file, 'r') as f:
                commands = [line.strip() for line in f if line.strip()]
            console.execute_commands(commands)

    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur")
    except Exception as e:
        print(f"ERREUR: {e}")
        sys.exit(1)
    finally:
        console.disconnect()
        print("\nDeconnexion.")


if __name__ == '__main__':
    main()
