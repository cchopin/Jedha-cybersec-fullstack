#!/usr/bin/env python3
"""
Script generique pour executer des commandes Cisco IOU via socket
Compatible Python 3.13+ (pas de telnetlib)

Usage:
    python3 cisco_cli.py --host IP --port PORT --commands "cmd1;cmd2;cmd3"
    python3 cisco_cli.py --host IP --port PORT --commands-file commands.txt
    python3 cisco_cli.py --host IP --port PORT --show "show ip arp"
"""

import argparse
import re
import socket
import time
import sys


class CiscoConsole:
    """Client console Cisco via socket TCP"""

    def __init__(self, host, port, timeout=30, verbose=True):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

        if self.verbose:
            print(f"[*] Connexion a {host}:{port}...")

        try:
            self.sock.connect((host, port))
            time.sleep(2)  # Attendre que la console soit prete
            self._read_buffer()  # Clear initial buffer
            # Reveiller la console avec plusieurs retours chariot
            self._wake_console()
        except Exception as e:
            print(f"[ERROR] Connexion impossible: {e}")
            sys.exit(1)

    def _read_buffer(self, timeout=1):
        """Lit toutes les donnees disponibles"""
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
        # Nettoyer les caracteres de controle Cisco
        output = data.decode('ascii', errors='ignore')
        output = output.replace('\r\n', '\n').replace('\r', '\n')
        # Supprimer les sequences --More-- et backspaces
        output = re.sub(r' --More-- \x08+\s+\x08+', '\n', output)
        output = re.sub(r'\x08+', '', output)
        return output

    def _wake_console(self):
        """Reveille la console et attend un prompt"""
        # Envoie plusieurs retours chariot pour reveiller la console
        for _ in range(3):
            self.sock.send(b"\r\n")
            time.sleep(0.5)
        self._read_buffer()
        # Envoie un espace puis supprime pour forcer un prompt
        self.sock.send(b"\r\n")
        time.sleep(1)
        output = self._read_buffer()
        if self.verbose:
            print("[*] Console initialisee")
        return output

    def send(self, command, wait=1.0):
        """Envoie une commande et retourne la reponse"""
        if self.verbose:
            print(f"[>] {command}")
        self.sock.send(command.encode('ascii') + b"\r\n")
        time.sleep(wait)
        output = self._read_buffer()
        return output

    def enable_mode(self):
        """Passe en mode enable"""
        self.send("", wait=0.5)
        self.send("enable", wait=1)
        return self

    def config_mode(self):
        """Passe en mode configuration"""
        self.send("configure terminal", wait=1)
        return self

    def exit_config(self):
        """Sort du mode configuration"""
        self.send("end", wait=1)
        return self

    def save_config(self):
        """Sauvegarde la configuration"""
        output = self.send("write memory", wait=3)
        if self.verbose:
            print("[*] Configuration sauvegardee")
        return output

    def run_commands(self, commands):
        """Execute une liste de commandes"""
        outputs = []
        for cmd in commands:
            cmd = cmd.strip()
            if cmd and not cmd.startswith('#'):
                # Delai plus long pour certaines commandes
                if cmd.lower().startswith('write') or cmd.lower().startswith('copy'):
                    wait = 3
                elif cmd.lower().startswith('vlan') or cmd.lower().startswith('interface'):
                    wait = 1.5
                else:
                    wait = 1.0
                output = self.send(cmd, wait=wait)
                outputs.append(output)
        return outputs

    def show(self, command, wait=2):
        """Execute une commande show et affiche le resultat"""
        self.send("", wait=0.5)
        self.exit_config()
        output = self.send(command, wait=wait)
        print(f"\n{'='*60}")
        print(f"  {command}")
        print('='*60)
        print(output)
        return output

    def close(self):
        """Ferme la connexion"""
        time.sleep(0.5)
        self.sock.close()
        if self.verbose:
            print("[*] Connexion fermee")


def main():
    parser = argparse.ArgumentParser(
        description='Cisco IOU CLI - Execute commands via console',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Voir les VLANs
  python3 cisco_cli.py --host 192.168.156.183 --port 5000 --show "show vlan brief"

  # Voir les trunks
  python3 cisco_cli.py --host 192.168.156.183 --port 5000 --show "show interfaces trunk"

  # Executer des commandes
  python3 cisco_cli.py --host 192.168.156.183 --port 5000 --commands "enable;show vlan brief"

  # Depuis un fichier
  python3 cisco_cli.py --host 192.168.156.183 --port 5000 --commands-file config.txt
        """
    )
    parser.add_argument('--host', required=True, help='GNS3 server IP')
    parser.add_argument('--port', required=True, type=int, help='Console port')
    parser.add_argument('--commands', help='Commandes separees par ";"')
    parser.add_argument('--commands-file', help='Fichier contenant les commandes')
    parser.add_argument('--show', help='Commande show a executer')
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
