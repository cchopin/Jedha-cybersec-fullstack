#!/usr/bin/env python3
"""
Script générique pour exécuter des commandes Cisco IOU via socket
Compatible Python 3.13+ (pas de telnetlib)

Usage:
    python3 cisco_cli.py --host IP --port PORT --commands "cmd1;cmd2;cmd3"
    python3 cisco_cli.py --host IP --port PORT --commands-file commands.txt
    python3 cisco_cli.py --host IP --port PORT --show "show vlan brief"
"""

import argparse
import re
import socket
import time
import sys


class CiscoConsole:
    """Client console Cisco via socket TCP"""

    def __init__(self, host, port, timeout=10, verbose=True):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

        if self.verbose:
            print(f"[*] Connexion à {host}:{port}...")

        try:
            self.sock.connect((host, port))
            time.sleep(1)
            self._read_buffer()  # Clear initial buffer
        except Exception as e:
            print(f"[ERROR] Connexion impossible: {e}")
            sys.exit(1)

    def _read_buffer(self, timeout=0.5):
        """Lit toutes les données disponibles"""
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        # Nettoyer les caractères de contrôle Cisco
        output = data.decode('ascii', errors='ignore')
        output = output.replace('\r\n', '\n').replace('\r', '\n')
        # Supprimer les séquences --More-- et backspaces
        output = re.sub(r' --More-- \x08+\s+\x08+', '\n', output)
        output = re.sub(r'\x08+', '', output)
        return output

    def send(self, command, wait=0.5):
        """Envoie une commande et retourne la réponse"""
        if self.verbose:
            print(f"[>] {command}")
        self.sock.send(command.encode('ascii') + b"\r\n")
        time.sleep(wait)
        output = self._read_buffer()
        return output

    def enable_mode(self):
        """Passe en mode enable"""
        self.send("")
        self.send("enable")
        return self

    def config_mode(self):
        """Passe en mode configuration"""
        self.send("configure terminal")
        return self

    def exit_config(self):
        """Sort du mode configuration"""
        self.send("end")
        return self

    def save_config(self):
        """Sauvegarde la configuration"""
        output = self.send("write memory", wait=2)
        if self.verbose:
            print("[*] Configuration sauvegardée")
        return output

    def run_commands(self, commands):
        """Exécute une liste de commandes"""
        outputs = []
        for cmd in commands:
            cmd = cmd.strip()
            if cmd and not cmd.startswith('#'):
                output = self.send(cmd)
                outputs.append(output)
        return outputs

    def show(self, command, wait=1):
        """Exécute une commande show et affiche le résultat"""
        self.send("")
        self.exit_config()
        output = self.send(command, wait=wait)
        print(f"\n{'='*60}")
        print(f"  {command}")
        print('='*60)
        print(output)
        return output

    def close(self):
        """Ferme la connexion"""
        self.sock.close()
        if self.verbose:
            print("[*] Connexion fermée")


def main():
    parser = argparse.ArgumentParser(
        description='Cisco IOU CLI - Execute commands via console',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Exécuter des commandes
  python3 cisco_cli.py --host 192.168.139.14 --port 5000 --commands "enable;show vlan brief"

  # Depuis un fichier
  python3 cisco_cli.py --host 192.168.139.14 --port 5000 --commands-file config.txt

  # Commande show simple
  python3 cisco_cli.py --host 192.168.139.14 --port 5000 --show "show interfaces trunk"
        """
    )
    parser.add_argument('--host', required=True, help='GNS3 server IP')
    parser.add_argument('--port', required=True, type=int, help='Console port')
    parser.add_argument('--commands', help='Commandes séparées par ";"')
    parser.add_argument('--commands-file', help='Fichier contenant les commandes')
    parser.add_argument('--show', help='Commande show à exécuter')
    parser.add_argument('--quiet', action='store_true', help='Mode silencieux')

    args = parser.parse_args()

    console = CiscoConsole(args.host, args.port, verbose=not args.quiet)

    try:
        if args.show:
            console.enable_mode()
            console.show(args.show)

        elif args.commands:
            commands = args.commands.split(';')
            console.run_commands(commands)

        elif args.commands_file:
            with open(args.commands_file, 'r') as f:
                commands = f.readlines()
            console.run_commands(commands)

        else:
            parser.print_help()

    finally:
        console.close()


if __name__ == "__main__":
    main()
