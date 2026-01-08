# Le Script Python `cisco_cli.py` expliqué

## Pourquoi ce script ?

Quand on crée un switch Cisco dans GNS3, on peut le voir dans l'interface graphique, mais **comment le configurer** ?

Dans la vraie vie, on brancherait un câble console (série) sur le switch et on taperait les commandes. Dans GNS3, cette connexion console est exposée via un **port TCP**.

Le problème : Ansible n'a pas de module natif pour parler en "console Cisco". D'où ce script Python qui fait le pont.

```
┌──────────┐       HTTP API        ┌──────────┐      TCP/Console     ┌──────────┐
│  Ansible │  ─────────────────>   │   GNS3   │  ──────────────────>  │  Switch  │
│          │   (créer topology)    │  Server  │   (port 5000, 5001)   │  Cisco   │
└──────────┘                       └──────────┘                       └──────────┘
     │                                                                      ▲
     │                                                                      │
     │                          ┌──────────────┐                            │
     └────────────────────────> │ cisco_cli.py │ ───────────────────────────┘
           script module         └──────────────┘     Connexion TCP directe
                                 (notre script)       Envoie les commandes
```

---

## Utilisation basique

Le script s'utilise en ligne de commande :

```bash
# Afficher l'aide
python3 cisco_cli.py --help

# Exécuter une commande show
python3 cisco_cli.py --host 192.168.190.174 --port 5000 --show "show vlan brief"

# Exécuter plusieurs commandes de configuration
python3 cisco_cli.py --host 192.168.190.174 --port 5000 --commands "enable;conf t;hostname MonSwitch;end"
```

### Les trois modes d'utilisation

| Mode | Option | Utilisation |
|------|--------|-------------|
| Show | `--show "commande"` | Une seule commande d'affichage |
| Commands | `--commands "cmd1;cmd2;cmd3"` | Plusieurs commandes séparées par `;` |
| File | `--commands-file fichier.txt` | Commandes depuis un fichier |

---

## Structure du script

Le script est organisé en une classe principale : `CiscoConsole`.

### Vue d'ensemble

```python
class CiscoConsole:
    def __init__(self, host, port, timeout=30):
        # Initialisation de la connexion

    def connect(self):
        # Ouvrir la connexion TCP

    def send(self, command):
        # Envoyer une commande et lire la réponse

    def enable_mode(self):
        # Entrer en mode privilégié (enable)

    def config_mode(self):
        # Entrer en mode configuration

    def execute_commands(self, commands):
        # Exécuter une liste de commandes
```

---

## Explications pas à pas

### 1. Connexion TCP (pas SSH !)

```python
import socket

class CiscoConsole:
    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
```

**Important** : On utilise `socket`, pas `paramiko` (SSH) ni `telnetlib` (telnet deprecated en Python 3.13). C'est une connexion TCP brute.

### 2. Se connecter

```python
def connect(self):
    """Ouvre la connexion vers le port console GNS3"""
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.settimeout(self.timeout)
    self.socket.connect((self.host, self.port))

    # Lire le banner initial (texte de bienvenue du switch)
    time.sleep(1)
    self._read_buffer()  # Vide le buffer initial
```

**Ce qui se passe** :
1. Création d'un socket TCP
2. Connexion à l'IP du serveur GNS3 sur le port console
3. Le switch envoie son banner (texte d'accueil)
4. On lit et ignore ce banner

### 3. Envoyer une commande

```python
def send(self, command, wait_time=1):
    """Envoie une commande et retourne la réponse"""
    # Envoyer la commande + retour chariot
    self.socket.send((command + "\r\n").encode())

    # Attendre que le switch traite la commande
    time.sleep(wait_time)

    # Lire la réponse
    response = self._read_buffer()
    return response
```

**Points clés** :
- `\r\n` = retour chariot + nouvelle ligne (comme appuyer sur Entrée)
- `.encode()` = convertir le texte en bytes (obligatoire pour les sockets)
- On attend avant de lire (le switch a besoin de temps pour répondre)

### 4. Lire la réponse (avec nettoyage)

```python
def _read_buffer(self):
    """Lit tout ce qui est disponible dans le buffer"""
    response = b""
    self.socket.setblocking(False)  # Mode non-bloquant

    try:
        while True:
            chunk = self.socket.recv(4096)  # Lire par blocs de 4Ko
            if not chunk:
                break
            response += chunk
    except BlockingIOError:
        pass  # Plus rien à lire

    self.socket.setblocking(True)  # Retour en mode normal

    # Nettoyer la réponse
    text = response.decode('utf-8', errors='ignore')
    text = self._clean_output(text)
    return text
```

### 5. Nettoyer la sortie Cisco

Le switch Cisco envoie des caractères spéciaux (codes ANSI, backspaces...) qu'il faut nettoyer :

```python
def _clean_output(self, text):
    """Nettoie les caractères de contrôle Cisco"""
    import re

    # Supprimer les séquences d'échappement ANSI (couleurs, etc.)
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)

    # Supprimer les backspaces et le caractère précédent
    while '\x08' in text:
        text = re.sub(r'.\x08', '', text)

    # Supprimer le prompt "--More--" de pagination
    text = re.sub(r'--More--\s*', '', text)

    return text
```

**Pourquoi ?** Sans ce nettoyage, la sortie contiendrait des caractères illisibles :
```
# Avant nettoyage :
^[[0mSwitch#^[[0m^H ^H^H ^Hshow vlan brief^M

# Après nettoyage :
Switch#show vlan brief
```

---

## Modes du switch Cisco

Un switch Cisco a plusieurs "modes" de commande :

```
Switch>              ← Mode utilisateur (limité)
   │
   │ enable
   ▼
Switch#              ← Mode privilégié (toutes les commandes show)
   │
   │ configure terminal
   ▼
Switch(config)#      ← Mode configuration globale
   │
   │ interface e0/0
   ▼
Switch(config-if)#   ← Mode configuration d'interface
```

Le script gère ces modes :

```python
def enable_mode(self):
    """Entre en mode enable (privilégié)"""
    response = self.send("enable")
    # Pas de mot de passe par défaut sur GNS3
    return response

def config_mode(self):
    """Entre en mode configuration"""
    self.enable_mode()
    response = self.send("configure terminal")
    return response

def exit_config(self):
    """Sort du mode configuration"""
    response = self.send("end")
    return response

def save_config(self):
    """Sauvegarde la configuration"""
    response = self.send("write memory", wait_time=3)
    return response
```

---

## Exécuter une liste de commandes

```python
def execute_commands(self, commands):
    """
    Exécute une liste de commandes.

    Args:
        commands: Liste de commandes ou string avec ; comme séparateur
    """
    # Convertir string en liste si nécessaire
    if isinstance(commands, str):
        commands = commands.split(';')

    results = []
    for cmd in commands:
        cmd = cmd.strip()  # Enlever les espaces
        if cmd:
            output = self.send(cmd)
            results.append({
                'command': cmd,
                'output': output
            })

    return results
```

---

## Utilisation depuis Ansible

Dans un playbook, on appelle le script avec le module `script` :

### Exemple 1 : Commandes simples

```yaml
- name: "Configurer le hostname"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ switch1_console_port }}
    --commands "enable;configure terminal;hostname MonSwitch;end;write memory"
```

### Exemple 2 : Avec des variables

```yaml
- name: "Créer les VLANs"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ switch1_console_port }}
    --commands "{{ vlan_commands | join(';') }}"
  vars:
    vlan_commands:
      - "enable"
      - "configure terminal"
      - "vlan 10"
      - "name Administration"
      - "exit"
      - "vlan 20"
      - "name Comptabilite"
      - "exit"
      - "end"
      - "write memory"
```

### Exemple 3 : Commande show pour vérification

```yaml
- name: "Vérifier les VLANs"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ switch1_console_port }}
    --show "show vlan brief"
  register: vlan_output

- name: "Afficher le résultat"
  debug:
    var: vlan_output.stdout
```

---

## Le script complet (simplifié)

Voici une version simplifiée et commentée du script :

```python
#!/usr/bin/env python3
"""
Script pour envoyer des commandes à un équipement Cisco via console GNS3.

Usage:
    python3 cisco_cli.py --host IP --port PORT --commands "cmd1;cmd2;cmd3"
    python3 cisco_cli.py --host IP --port PORT --show "show vlan brief"
"""

import socket
import time
import argparse
import re


class CiscoConsole:
    """Gère la connexion console vers un équipement Cisco dans GNS3."""

    def __init__(self, host, port, timeout=30):
        """
        Initialise la connexion.

        Args:
            host: IP du serveur GNS3
            port: Port console de l'équipement
            timeout: Timeout en secondes
        """
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.socket = None

    def connect(self):
        """Ouvre la connexion TCP vers le port console."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.socket.connect((self.host, self.port))

        # Attendre et vider le banner initial
        time.sleep(1)
        self._read_buffer()

        # Envoyer un retour chariot pour "réveiller" le prompt
        self.send("")

    def disconnect(self):
        """Ferme la connexion."""
        if self.socket:
            self.socket.close()
            self.socket = None

    def _read_buffer(self):
        """Lit tout ce qui est disponible dans le buffer."""
        response = b""
        self.socket.setblocking(False)

        try:
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk
        except (BlockingIOError, socket.error):
            pass

        self.socket.setblocking(True)

        # Décoder et nettoyer
        text = response.decode('utf-8', errors='ignore')
        return self._clean_output(text)

    def _clean_output(self, text):
        """Nettoie les caractères de contrôle."""
        # Séquences ANSI
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        # Backspaces
        while '\x08' in text:
            text = re.sub(r'.\x08', '', text)
        # --More--
        text = re.sub(r'--More--\s*', '', text)
        return text

    def send(self, command, wait_time=1):
        """
        Envoie une commande et retourne la réponse.

        Args:
            command: La commande à envoyer
            wait_time: Temps d'attente pour la réponse

        Returns:
            La réponse du switch
        """
        self.socket.send((command + "\r\n").encode())
        time.sleep(wait_time)
        return self._read_buffer()

    def execute_commands(self, commands):
        """
        Exécute une liste de commandes.

        Args:
            commands: Liste ou string (séparateur ;)
        """
        if isinstance(commands, str):
            commands = [c.strip() for c in commands.split(';') if c.strip()]

        results = []
        for cmd in commands:
            output = self.send(cmd)
            print(f">>> {cmd}")
            print(output)
            results.append({'command': cmd, 'output': output})

        return results


def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(description='Cisco CLI via GNS3 console')
    parser.add_argument('--host', required=True, help='IP du serveur GNS3')
    parser.add_argument('--port', required=True, help='Port console')
    parser.add_argument('--commands', help='Commandes séparées par ;')
    parser.add_argument('--show', help='Une commande show')
    parser.add_argument('--timeout', default=30, type=int, help='Timeout')

    args = parser.parse_args()

    # Créer la connexion
    console = CiscoConsole(args.host, args.port, args.timeout)

    try:
        console.connect()

        if args.show:
            # Mode show : une seule commande
            console.send("enable")
            output = console.send(args.show, wait_time=2)
            print(output)

        elif args.commands:
            # Mode commands : plusieurs commandes
            console.execute_commands(args.commands)

        else:
            print("Erreur: spécifier --commands ou --show")

    finally:
        console.disconnect()


if __name__ == '__main__':
    main()
```

---

## Configurer un VPC (cas spécial)

Les VPCs GNS3 ne sont pas des Cisco, ils ont leur propre syntaxe :

```bash
# Syntaxe VPC pour configurer l'IP
ip 192.168.10.10 255.255.255.0 192.168.10.1
#  └─ IP ─────┘   └─ masque ─┘   └─ gateway ─┘

# Sauvegarder
save
```

Le script fonctionne aussi pour les VPCs :

```yaml
- name: "Configurer le VPC"
  script: >
    ../scripts/cisco_cli.py
    --host {{ gns3_host }}
    --port {{ pc1_console_port }}
    --commands "ip 192.168.10.10 255.255.255.0 192.168.10.1;save"
  ignore_errors: true  # Les VPCs peuvent etre capricieux
```

---

## Troubleshooting

### "Connection refused"

Le port console n'est pas accessible :
- L'équipement n'est pas démarré
- Mauvais port (vérifier `switch_info.yml`)
- Firewall bloque la connexion

### "Timeout"

Le switch ne répond pas :
- Il démarre encore (attendre 30-90s)
- Augmenter `--timeout 60`

### Sortie vide ou incomplète

Augmenter le `wait_time` dans le script :
```python
output = self.send(cmd, wait_time=3)  # 3 secondes au lieu de 1
```

### "% Invalid input detected"

Commande incorrecte ou pas dans le bon mode :
- Vérifier qu'on est bien en mode `enable` puis `conf t`
- Vérifier la syntaxe de la commande

---

## Résumé

| Élément | Description |
|---------|-------------|
| Connexion | TCP brut (socket) vers le port console GNS3 |
| Format | Commandes texte + `\r\n` |
| Nettoyage | Suppression des caractères ANSI/contrôle |
| Usage Ansible | Module `script` |
| Syntaxe | `--commands "cmd1;cmd2;cmd3"` ou `--show "commande"` |

Le script `cisco_cli.py` est le pont entre Ansible et les équipements GNS3.

Maintenant, passons au mini playbook fonctionnel !
