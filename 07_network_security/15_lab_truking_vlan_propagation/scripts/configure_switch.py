#!/usr/bin/env python3
"""
Script pour configurer un switch Cisco IOU via socket (compatible Python 3.13+)
Utilisé par Ansible pour automatiser la configuration VLAN/Trunk
"""

import argparse
import socket
import time
import json
import sys


class TelnetClient:
    """Simple telnet client using raw sockets"""

    def __init__(self, host, port, timeout=10):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))

    def read_until_timeout(self, timeout=0.5):
        """Read all available data"""
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
        return data.decode('ascii', errors='ignore')

    def write(self, text):
        """Send text"""
        self.sock.send(text.encode('ascii') + b"\r\n")

    def send_command(self, command, wait=0.5):
        """Send command and wait for response"""
        self.write(command)
        time.sleep(wait)
        return self.read_until_timeout()

    def close(self):
        self.sock.close()


def configure_switch(host, port, hostname, vlans, trunk_interface, trunk_vlans, native_vlan):
    """Configure le switch avec les VLANs et le trunk"""

    print(f"[*] Connexion à {host}:{port}...")

    try:
        tn = TelnetClient(host, port, timeout=10)
    except Exception as e:
        print(f"[ERROR] Impossible de se connecter: {e}")
        sys.exit(1)

    time.sleep(2)
    tn.read_until_timeout()  # Clear buffer

    # Sortir du mode actuel et passer en enable
    print("[*] Passage en mode enable...")
    tn.send_command("")
    tn.send_command("")
    tn.send_command("enable")
    tn.send_command("configure terminal")

    # Hostname
    print(f"[*] Configuration hostname: {hostname}")
    tn.send_command(f"hostname {hostname}")

    # Créer les VLANs
    print("[*] Création des VLANs...")
    for vlan in vlans:
        print(f"    - VLAN {vlan['id']}: {vlan['name']}")
        tn.send_command(f"vlan {vlan['id']}")
        tn.send_command(f"name {vlan['name']}")
        tn.send_command("exit")

    # Créer le native VLAN s'il n'existe pas
    print(f"[*] Création Native VLAN {native_vlan}")
    tn.send_command(f"vlan {native_vlan}")
    tn.send_command("name NATIVE")
    tn.send_command("exit")

    # Configurer l'interface trunk
    print(f"[*] Configuration trunk sur {trunk_interface}...")
    tn.send_command(f"interface {trunk_interface}")
    tn.send_command("switchport trunk encapsulation dot1q")
    tn.send_command("switchport mode trunk")
    tn.send_command(f"switchport trunk allowed vlan {trunk_vlans}")
    tn.send_command(f"switchport trunk native vlan {native_vlan}")
    tn.send_command("no shutdown")
    tn.send_command("exit")

    # Sauvegarder la config
    print("[*] Sauvegarde de la configuration...")
    tn.send_command("end")
    tn.send_command("write memory", wait=2)

    # Vérification
    print("[*] Vérification de la configuration...")
    print("\n--- SHOW VLAN BRIEF ---")
    output = tn.send_command("show vlan brief", wait=1)
    print(output)

    print("\n--- SHOW INTERFACES TRUNK ---")
    output = tn.send_command("show interfaces trunk", wait=1)
    print(output)

    tn.close()
    print(f"[OK] Configuration de {hostname} terminée!")


def main():
    parser = argparse.ArgumentParser(description='Configure Cisco IOU Switch')
    parser.add_argument('--host', required=True, help='GNS3 server IP')
    parser.add_argument('--port', required=True, type=int, help='Console port')
    parser.add_argument('--hostname', required=True, help='Switch hostname')
    parser.add_argument('--vlans', required=True, help='VLANs JSON array')
    parser.add_argument('--trunk-interface', required=True, help='Trunk interface')
    parser.add_argument('--trunk-vlans', required=True, help='Allowed VLANs')
    parser.add_argument('--native-vlan', required=True, type=int, help='Native VLAN')

    args = parser.parse_args()

    vlans = json.loads(args.vlans)

    configure_switch(
        host=args.host,
        port=args.port,
        hostname=args.hostname,
        vlans=vlans,
        trunk_interface=args.trunk_interface,
        trunk_vlans=args.trunk_vlans,
        native_vlan=args.native_vlan
    )


if __name__ == "__main__":
    main()
