# Installation d'Ansible pour GNS3

Ce guide explique comment installer Ansible sur Mac et Windows pour automatiser vos labs GNS3.

## Qu'est-ce qu'Ansible ?

Ansible est un outil d'automatisation qui permet d'exécuter des tâches sur des machines distantes (ou locales). Dans notre cas, on l'utilise pour :

- Créer des topologies GNS3 automatiquement (via l'API REST)
- Configurer des switches et routeurs Cisco
- Configurer des VPCs (Virtual PCs)

**Particularité pour GNS3** : On n'utilise PAS Ansible en mode "SSH vers des machines". On l'utilise en **mode local** pour faire des appels API HTTP vers le serveur GNS3.

---

## Installation sur Mac

### Méthode 1 : Via Homebrew (Recommandé)

```bash
# 1. Installer Homebrew si pas déjà fait
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Installer Ansible
brew install ansible

# 3. Vérifier l'installation
ansible --version
```

### Méthode 2 : Via pip (Python)

```bash
# 1. S'assurer que Python 3 est installé
python3 --version

# 2. Installer Ansible via pip
pip3 install ansible

# 3. Vérifier l'installation
ansible --version
```

**Résultat attendu** :
```
ansible [core 2.15.x]
  config file = None
  configured module search path = ...
  python version = 3.x.x
```

---

## Installation sur Windows

### Méthode 1 : Via WSL (Windows Subsystem for Linux) - RECOMMANDÉ

WSL permet d'exécuter Linux directement sur Windows. C'est la méthode la plus fiable.

#### Étape 1 : Installer WSL

Ouvrir PowerShell **en tant qu'Administrateur** :

```powershell
# Installer WSL avec Ubuntu
wsl --install

# Redémarrer l'ordinateur si demandé
```

Après redémarrage, Ubuntu se lance automatiquement. Créer un utilisateur et mot de passe.

#### Étape 2 : Installer Ansible dans WSL

Dans le terminal Ubuntu (WSL) :

```bash
# Mettre à jour les paquets
sudo apt update && sudo apt upgrade -y

# Installer Ansible
sudo apt install ansible -y

# Vérifier l'installation
ansible --version
```

#### Étape 3 : Accéder à vos fichiers Windows depuis WSL

Vos fichiers Windows sont accessibles via `/mnt/c/` :

```bash
# Exemple : aller dans Documents
cd /mnt/c/Users/VotreNom/Documents

# Cloner un repo ou naviguer vers votre projet
cd /mnt/c/Users/VotreNom/projets/network_security
```

**Astuce** : Vous pouvez aussi ouvrir un terminal WSL directement depuis l'explorateur Windows en tapant `wsl` dans la barre d'adresse.

---

### Méthode 2 : Via Python natif Windows

Cette méthode fonctionne mais peut avoir des problèmes de compatibilité.

```powershell
# 1. Installer Python depuis python.org
# Télécharger : https://www.python.org/downloads/
# IMPORTANT : Cocher "Add Python to PATH" lors de l'installation

# 2. Dans PowerShell, installer Ansible
pip install ansible

# 3. Vérifier
ansible --version
```

**Note** : Certains modules Ansible peuvent ne pas fonctionner correctement sur Windows natif. WSL est vraiment recommandé.

---

## Configuration de base

### Créer le fichier ansible.cfg

Dans chaque projet, créer un fichier `ansible.cfg` pour configurer Ansible :

```ini
[defaults]
# Ne pas vérifier les clés SSH (on utilise pas SSH ici)
host_key_checking = False

# Désactiver les warnings Python
interpreter_python = auto_silent

# Timeout pour les connexions (en secondes)
timeout = 60

# Fichier d'inventaire par défaut
inventory = inventory.yml
```

Ce fichier doit être à la **racine** de votre projet (là où vous lancez `ansible-playbook`).

---

## Vérifier que tout fonctionne

### Test 1 : Ansible peut s'exécuter

```bash
ansible --version
```

### Test 2 : Ansible peut se connecter en local

Créer un fichier test :

```bash
# Créer un inventaire minimal
echo "localhost ansible_connection=local" > test_inventory.ini

# Tester avec un ping local
ansible localhost -i test_inventory.ini -m ping
```

**Résultat attendu** :
```
localhost | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

### Test 3 : Vérifier que le serveur GNS3 est accessible

```bash
# Remplacer IP_GNS3 par l'IP de votre serveur GNS3
curl http://IP_GNS3:80/v2/version
```

**Résultat attendu** :
```json
{"local": false, "version": "2.x.x"}
```

Si ça ne marche pas :
- Vérifier que GNS3 Server est démarré
- Vérifier l'IP (la VM GNS3 a sa propre IP)
- Vérifier le firewall

---

## Structure de dossier recommandée

Pour chaque lab, utiliser cette structure :

```
mon_lab/
├── ansible.cfg          # Configuration Ansible
├── inventory.yml        # Liste des "hôtes" (localhost)
├── group_vars/
│   └── all.yml          # Variables globales (IP GNS3, topologie)
├── playbooks/
│   ├── 00_full_lab.yml  # Playbook principal (lance tout)
│   ├── 01_create_topology.yml
│   ├── 02_configure_switches.yml
│   └── ...
├── scripts/
│   └── cisco_cli.py     # Script pour configurer les équipements
└── switch_info.yml      # Généré automatiquement (ports console)
```

---

## Dépendances Python

Le script `cisco_cli.py` nécessite Python 3.x. Vérifier :

```bash
python3 --version
```

Aucune bibliothèque externe n'est nécessaire - le script utilise uniquement les modules standards Python.

---

## Résumé des commandes utiles

| Action | Commande |
|--------|----------|
| Version Ansible | `ansible --version` |
| Lancer un playbook | `ansible-playbook playbooks/mon_playbook.yml` |
| Mode verbose | `ansible-playbook playbooks/mon_playbook.yml -v` |
| Mode très verbose | `ansible-playbook playbooks/mon_playbook.yml -vvv` |
| Vérifier syntaxe | `ansible-playbook playbooks/mon_playbook.yml --syntax-check` |
| Dry-run (simulation) | `ansible-playbook playbooks/mon_playbook.yml --check` |

---

## Problèmes courants

### "ansible: command not found"

- **Mac** : Fermer et rouvrir le terminal, ou `source ~/.zshrc`
- **Windows WSL** : Fermer et rouvrir Ubuntu
- **Windows natif** : Ajouter Python/Scripts au PATH

### "Permission denied"

Sur Mac/Linux :
```bash
chmod +x scripts/cisco_cli.py
```

### "Connection refused" vers GNS3

1. Vérifier que le serveur GNS3 tourne
2. Vérifier l'IP de la VM GNS3 (peut changer à chaque démarrage)
3. Mettre à jour `group_vars/all.yml` avec la bonne IP

---

Maintenant que Ansible est installé, passons au tutoriel sur l'inventory !
