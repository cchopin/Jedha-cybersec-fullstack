# Tutoriel : L'Inventory Ansible pour GNS3

## C'est quoi un Inventory ?

L'inventory (inventaire) est un fichier qui dit à Ansible **sur quelles machines** il doit travailler.

Normalement, avec Ansible, on liste des serveurs distants (par exemple `192.168.1.10`, `192.168.1.11`...) et Ansible se connecte en SSH pour exécuter des commandes.

**Mais avec GNS3, c'est différent !**

On ne se connecte PAS en SSH aux switches/routeurs. À la place :
1. On exécute Ansible **localement** (sur notre PC)
2. Ansible fait des **appels HTTP** vers l'API GNS3
3. L'API GNS3 crée les équipements et les connecte

C'est pour ça que notre inventory est très simple : un seul hôte = `localhost`.

---

## L'Inventory minimal pour GNS3

Créer le fichier `inventory.yml` :

```yaml
all:
  hosts:
    localhost:
      ansible_connection: local
```

**Décortiquons ligne par ligne** :

| Ligne | Explication |
|-------|-------------|
| `all:` | Groupe racine qui contient tous les hôtes |
| `hosts:` | Section listant les machines |
| `localhost:` | Nom de la machine (notre propre PC) |
| `ansible_connection: local` | **IMPORTANT** : Dit à Ansible de ne PAS utiliser SSH, mais d'exécuter localement |

---

## Pourquoi `ansible_connection: local` ?

Sans cette ligne, Ansible essaierait de se connecter en SSH à `localhost`, ce qui :
- Nécessiterait un serveur SSH actif
- Demanderait un mot de passe
- Serait inutilement complexe

Avec `ansible_connection: local`, Ansible exécute simplement les commandes Python directement sur votre machine.

---

## Structure complète d'un projet

Voici comment les fichiers s'organisent :

```
mon_lab/
├── ansible.cfg           ← Configuration Ansible
├── inventory.yml         ← Liste des hôtes (localhost)
├── group_vars/
│   └── all.yml           ← Variables globales
└── playbooks/
    └── ...
```

### Le fichier `ansible.cfg`

Ce fichier configure le comportement d'Ansible :

```ini
[defaults]
host_key_checking = False
interpreter_python = auto_silent
timeout = 60
inventory = inventory.yml
```

La ligne `inventory = inventory.yml` dit à Ansible d'utiliser automatiquement notre fichier inventory.

---

## Les Variables avec `group_vars/all.yml`

Le dossier `group_vars/` contient des fichiers de variables. Le fichier `all.yml` s'applique au groupe `all` (tous les hôtes).

### Structure de base

```yaml
# Connexion au serveur GNS3
gns3_server: "http://192.168.190.174:80"
gns3_host: "192.168.190.174"

# Nom du projet GNS3
project_name: "Mon_Lab_Test"
```

**Explication** :

| Variable | Utilisation |
|----------|-------------|
| `gns3_server` | URL complète pour les appels API (avec http:// et port) |
| `gns3_host` | IP seule (pour la connexion console telnet) |
| `project_name` | Nom du projet qui sera créé dans GNS3 |

### Comment trouver l'IP de GNS3 ?

Si vous utilisez la VM GNS3 :

1. Démarrer la VM GNS3
2. L'IP s'affiche sur l'écran de la VM :
   ```
   GNS3 Server: http://192.168.x.x:80
   ```
3. Utiliser cette IP dans `group_vars/all.yml`

**Attention** : Cette IP peut changer à chaque démarrage de la VM !

---

## Définir la topologie dans les variables

C'est dans `group_vars/all.yml` qu'on définit toute notre topologie :

### Exemple 1 : Un switch simple

```yaml
# Connexion GNS3
gns3_server: "http://192.168.190.174:80"
gns3_host: "192.168.190.174"
project_name: "Lab_Simple"

# Un seul switch
switches:
  - name: "Switch1"
    x: 0       # Position X dans GNS3
    y: 0       # Position Y dans GNS3
```

### Exemple 2 : Plusieurs switches connectés

```yaml
gns3_server: "http://192.168.190.174:80"
gns3_host: "192.168.190.174"
project_name: "Lab_Multi_Switch"

# Trois switches en ligne
switches:
  - name: "IOU1"
    x: -200
    y: 0
  - name: "IOU2"
    x: 0
    y: 0
  - name: "IOU3"
    x: 200
    y: 0

# Liens trunk entre les switches
trunk_links:
  - switch1: "IOU1"
    port1: 0          # e0/0
    switch2: "IOU2"
    port2: 0          # e0/0
  - switch1: "IOU2"
    port1: 1          # e0/1
    switch2: "IOU3"
    port2: 0          # e0/0
```

### Exemple 3 : Avec des VPCs (ordinateurs virtuels)

```yaml
gns3_server: "http://192.168.190.174:80"
gns3_host: "192.168.190.174"
project_name: "Lab_VLAN"

# VLANs à créer
vlans:
  - id: 10
    name: "Administration"
  - id: 20
    name: "Comptabilite"

# Switches
switches:
  - name: "Switch1"
    x: 0
    y: 0

# VPCs (ordinateurs virtuels)
vpcs:
  - name: "PC_Admin"
    switch: "Switch1"
    port: 2            # e0/2 sur le switch
    vlan: 10
    ip: "192.168.10.10"
    gateway: "192.168.10.1"
    x: -100
    y: 100
  - name: "PC_Compta"
    switch: "Switch1"
    port: 3            # e0/3 sur le switch
    vlan: 20
    ip: "192.168.20.10"
    gateway: "192.168.20.1"
    x: 100
    y: 100
```

---

## Comprendre les ports Cisco IOU

Sur un switch Cisco IOU, les ports sont organisés ainsi :

| Interface | Adapter | Port |
|-----------|---------|------|
| e0/0 | 0 | 0 |
| e0/1 | 0 | 1 |
| e0/2 | 0 | 2 |
| e0/3 | 0 | 3 |
| e1/0 | 1 | 0 |
| e1/1 | 1 | 1 |
| ... | ... | ... |

**Formule** :
- `adapter_number = port // 4` (division entière)
- `port_number = port % 4` (reste de la division)

Exemple pour `e1/2` (port 6) :
- `adapter = 6 // 4 = 1`
- `port = 6 % 4 = 2`

---

## Le fichier `switch_info.yml` (généré automatiquement)

Quand on crée la topologie, un fichier `switch_info.yml` est généré. Il contient les **ports console** de chaque équipement :

```yaml
project_id: "abc123-def456-..."
iou1_console_port: 5000
iou2_console_port: 5001
pc_admin_console_port: 5002
```

**Pourquoi c'est important ?**

Pour configurer un switch ou un VPC, on doit se connecter à son port console (comme avec un câble série). GNS3 expose ces consoles via des ports TCP.

Le playbook de création sauvegarde ces ports pour que les playbooks suivants puissent s'y connecter.

---

## Comment utiliser les variables dans les playbooks

### Accès direct

```yaml
- name: Afficher l'IP du serveur GNS3
  debug:
    msg: "Serveur GNS3 : {{ gns3_server }}"
```

### Boucle sur une liste

```yaml
- name: Créer chaque switch
  uri:
    url: "{{ gns3_server }}/v2/projects/{{ project_id }}/templates/{{ template_id }}"
    method: POST
    body:
      name: "{{ item.name }}"
      x: "{{ item.x }}"
      y: "{{ item.y }}"
  loop: "{{ switches }}"
```

### Accès aux éléments d'une liste

```yaml
# Premier switch
{{ switches[0].name }}

# Tous les VPCs du VLAN 10
{{ vpcs | selectattr('vlan', 'equalto', 10) | list }}
```

---

## Récapitulatif : Les 3 fichiers essentiels

### 1. `inventory.yml` (toujours pareil)

```yaml
all:
  hosts:
    localhost:
      ansible_connection: local
```

### 2. `ansible.cfg` (toujours pareil)

```ini
[defaults]
host_key_checking = False
interpreter_python = auto_silent
inventory = inventory.yml
```

### 3. `group_vars/all.yml` (personnalisé par lab)

```yaml
# À adapter selon votre setup
gns3_server: "http://VOTRE_IP_GNS3:80"
gns3_host: "VOTRE_IP_GNS3"
project_name: "Nom_De_Votre_Lab"

# Votre topologie ici...
switches:
  - name: "Switch1"
    x: 0
    y: 0
```

---

## Exercice pratique

1. Créer un dossier `test_inventory/`
2. Y créer les 3 fichiers avec un seul switch
3. Tester avec :
   ```bash
   ansible-inventory --graph
   ```
   Résultat attendu :
   ```
   @all:
     |--@ungrouped:
     |  |--localhost
   ```

4. Afficher les variables :
   ```bash
   ansible localhost -m debug -a "var=gns3_server"
   ```

---

Maintenant que vous comprenez l'inventory, passons aux playbooks !
