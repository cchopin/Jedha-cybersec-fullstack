# Tutoriel : Les Playbooks Ansible pour GNS3

## C'est quoi un Playbook ?

Un playbook est une **liste d'instructions** que Ansible va exécuter dans l'ordre. C'est comme une recette de cuisine :

1. Prendre les ingrédients (récupérer les templates GNS3)
2. Préparer le plat (créer les équipements)
3. Assembler (connecter les équipements)
4. Cuire (démarrer les équipements)
5. Servir (configurer les équipements)

---

## Structure d'un Playbook

Un playbook est un fichier YAML. Voici la structure de base :

```yaml
---
- name: "Description de ce que fait le playbook"
  hosts: localhost              # Sur quelle machine exécuter
  gather_facts: false           # Ne pas collecter d'infos système

  vars:                         # Variables locales (optionnel)
    ma_variable: "valeur"

  vars_files:                   # Charger des variables depuis un fichier
    - ../switch_info.yml

  tasks:                        # Liste des tâches à exécuter
    - name: "Première tâche"
      debug:
        msg: "Hello World!"

    - name: "Deuxième tâche"
      debug:
        msg: "Suite..."
```

---

## Les modules Ansible qu'on utilise

Pour GNS3, on utilise principalement 3 modules :

| Module | Utilité |
|--------|---------|
| `uri` | Faire des appels HTTP (API GNS3) |
| `script` | Exécuter un script Python local |
| `debug` | Afficher des messages |
| `set_fact` | Créer/modifier des variables |
| `pause` | Attendre un certain temps |
| `copy` | Créer/copier des fichiers |

---

## Étape 1 : Créer un projet GNS3

### Ce qu'on veut faire

1. Vérifier si le projet existe déjà
2. Si non, le créer
3. L'ouvrir

### Le playbook expliqué

```yaml
---
- name: "Créer un projet GNS3"
  hosts: localhost
  gather_facts: false

  tasks:
    # ═══════════════════════════════════════════
    # ÉTAPE 1 : Récupérer la liste des projets
    # ═══════════════════════════════════════════
    - name: "Récupérer les projets existants"
      uri:
        url: "{{ gns3_server }}/v2/projects"    # URL de l'API
        method: GET                              # Méthode HTTP
        return_content: yes                      # On veut voir la réponse
      register: projets                          # Stocker la réponse

    # Afficher ce qu'on a récupéré (pour debug)
    - name: "Afficher les projets"
      debug:
        msg: "Projets trouvés : {{ projets.json | map(attribute='name') | list }}"
```

**Décortiquons** :

- `uri` : Module pour faire des requêtes HTTP
- `url` : L'endpoint de l'API GNS3 (`/v2/projects` liste tous les projets)
- `method: GET` : On veut lire, pas écrire
- `register: projets` : La réponse est stockée dans la variable `projets`
- `projets.json` : Le contenu JSON de la réponse

### Suite : Créer le projet s'il n'existe pas

```yaml
    # ═══════════════════════════════════════════
    # ÉTAPE 2 : Vérifier si notre projet existe
    # ═══════════════════════════════════════════
    - name: "Chercher notre projet"
      set_fact:
        projet_existant: "{{ projets.json | selectattr('name', 'equalto', project_name) | list | first | default(none) }}"

    # ═══════════════════════════════════════════
    # ÉTAPE 3 : Créer le projet s'il n'existe pas
    # ═══════════════════════════════════════════
    - name: "Créer le projet"
      uri:
        url: "{{ gns3_server }}/v2/projects"
        method: POST                             # POST = créer
        body_format: json                        # On envoie du JSON
        body:
          name: "{{ project_name }}"             # Nom du projet
        status_code: [200, 201]                  # Codes HTTP acceptés
      register: nouveau_projet
      when: projet_existant is none              # SEULEMENT si pas trouvé
```

**Nouveautés** :

- `set_fact` : Crée une variable à partir d'une expression
- `selectattr('name', 'equalto', project_name)` : Filtre les projets par nom
- `method: POST` : On veut créer quelque chose
- `body` : Les données à envoyer
- `when:` : Condition - la tâche ne s'exécute que si la condition est vraie

---

## Étape 2 : Créer un switch

### Récupérer le template

Chaque type d'équipement GNS3 (switch, routeur, VPC...) a un **template**. On doit d'abord récupérer l'ID du template.

```yaml
    # ═══════════════════════════════════════════
    # Récupérer les templates disponibles
    # ═══════════════════════════════════════════
    - name: "Récupérer les templates GNS3"
      uri:
        url: "{{ gns3_server }}/v2/templates"
        method: GET
      register: templates

    - name: "Trouver le template IOU L2 (switch)"
      set_fact:
        template_switch_id: "{{ templates.json | selectattr('name', 'search', 'IOU L2') | map(attribute='template_id') | first }}"

    - name: "Afficher l'ID du template"
      debug:
        msg: "Template switch trouvé : {{ template_switch_id }}"
```

**Note** : Le nom du template dépend de votre installation GNS3. Ça peut être :
- "Cisco IOU L2"
- "IOU L2"
- "L2 Switch"

Regardez dans GNS3 GUI le nom exact.

### Créer le switch

```yaml
    # ═══════════════════════════════════════════
    # Créer un switch dans le projet
    # ═══════════════════════════════════════════
    - name: "Créer le switch"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/templates/{{ template_switch_id }}"
        method: POST
        body_format: json
        body:
          name: "Switch1"          # Nom du switch
          x: 0                     # Position X
          y: 0                     # Position Y
        status_code: [200, 201]
      register: switch_cree
```

**L'URL expliquée** :
```
/v2/projects/{project_id}/templates/{template_id}
     │               │                   │
     │               │                   └── Quel type d'équipement créer
     │               └── Dans quel projet
     └── Version de l'API
```

---

## Étape 3 : Créer un VPC (ordinateur virtuel)

Même principe que le switch, mais avec le template VPC :

```yaml
    # ═══════════════════════════════════════════
    # Trouver le template VPC
    # ═══════════════════════════════════════════
    - name: "Trouver le template VPCS"
      set_fact:
        template_vpc_id: "{{ templates.json | selectattr('name', 'equalto', 'VPCS') | map(attribute='template_id') | first }}"

    # ═══════════════════════════════════════════
    # Créer un VPC
    # ═══════════════════════════════════════════
    - name: "Créer le VPC"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/templates/{{ template_vpc_id }}"
        method: POST
        body_format: json
        body:
          name: "PC1"
          x: -100
          y: 100
        status_code: [200, 201]
      register: vpc_cree
```

---

## Étape 4 : Connecter les équipements

C'est la partie la plus technique. On doit créer un **lien** entre deux équipements.

### Récupérer les IDs des nodes

D'abord, on doit connaître les `node_id` de chaque équipement :

```yaml
    # ═══════════════════════════════════════════
    # Récupérer tous les nodes du projet
    # ═══════════════════════════════════════════
    - name: "Récupérer les nodes"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/nodes"
        method: GET
      register: all_nodes

    # Créer un dictionnaire pour accès facile
    - name: "Créer dictionnaire des nodes"
      set_fact:
        nodes_dict: "{{ nodes_dict | default({}) | combine({item.name: item}) }}"
      loop: "{{ all_nodes.json }}"
```

**Le dictionnaire permet** :
```yaml
# Au lieu de chercher dans une liste :
{{ all_nodes.json | selectattr('name', 'equalto', 'Switch1') | first }}

# On peut simplement faire :
{{ nodes_dict['Switch1'] }}
```

### Créer le lien

```yaml
    # ═══════════════════════════════════════════
    # Connecter PC1 au port e0/2 de Switch1
    # ═══════════════════════════════════════════
    - name: "Créer le lien PC1 <-> Switch1"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/links"
        method: POST
        body_format: json
        body:
          nodes:
            # Premier bout du câble : le VPC
            - adapter_number: 0                        # Le VPC n'a qu'une carte réseau
              node_id: "{{ nodes_dict['PC1'].node_id }}"
              port_number: 0                           # Port 0 du VPC
            # Deuxième bout : le switch
            - adapter_number: 0                        # Adapter 0 = ports e0/x
              node_id: "{{ nodes_dict['Switch1'].node_id }}"
              port_number: 2                           # Port 2 = e0/2
        status_code: [200, 201, 409]     # 409 = lien existe déjà (OK)
```

**Comprendre adapter et port** :

Pour un switch Cisco IOU :
- `adapter_number: 0` + `port_number: 0` = interface `e0/0`
- `adapter_number: 0` + `port_number: 2` = interface `e0/2`
- `adapter_number: 1` + `port_number: 0` = interface `e1/0`

Pour un VPC :
- Toujours `adapter_number: 0`, `port_number: 0` (un seul port)

---

## Étape 5 : Démarrer les équipements

```yaml
    # ═══════════════════════════════════════════
    # Démarrer tous les équipements
    # ═══════════════════════════════════════════
    - name: "Démarrer tous les nodes"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/nodes/start"
        method: POST
        status_code: [200, 204]

    # IMPORTANT : Attendre que les équipements démarrent
    - name: "Attendre le démarrage (30 secondes)"
      pause:
        seconds: 30
        prompt: "Les équipements démarrent... Patience !"
```

**Pourquoi la pause ?**

Les switches Cisco IOU mettent 30-90 secondes à démarrer complètement. Sans cette pause, les commandes de configuration échoueraient.

---

## Étape 6 : Sauvegarder les ports console

Pour configurer les équipements plus tard, on a besoin des ports console :

```yaml
    # ═══════════════════════════════════════════
    # Sauvegarder les infos pour la suite
    # ═══════════════════════════════════════════
    - name: "Sauvegarder les ports console"
      copy:
        content: |
          project_id: "{{ project_id }}"
          switch1_console_port: {{ nodes_dict['Switch1'].console }}
          pc1_console_port: {{ nodes_dict['PC1'].console }}
        dest: "{{ playbook_dir }}/../switch_info.yml"
```

Le fichier `switch_info.yml` ressemblera à :
```yaml
project_id: "abc123-456..."
switch1_console_port: 5000
pc1_console_port: 5001
```

---

## Utiliser des boucles

Pour créer plusieurs switches d'un coup, on utilise `loop` :

### Dans `group_vars/all.yml`

```yaml
switches:
  - name: "Switch1"
    x: -200
    y: 0
  - name: "Switch2"
    x: 0
    y: 0
  - name: "Switch3"
    x: 200
    y: 0
```

### Dans le playbook

```yaml
    - name: "Créer tous les switches"
      uri:
        url: "{{ gns3_server }}/v2/projects/{{ project_id }}/templates/{{ template_switch_id }}"
        method: POST
        body_format: json
        body:
          name: "{{ item.name }}"      # item = élément courant de la boucle
          x: "{{ item.x }}"
          y: "{{ item.y }}"
        status_code: [200, 201, 409]   # 409 si existe déjà
      loop: "{{ switches }}"           # Boucle sur la liste switches
```

Ansible va exécuter cette tâche 3 fois, une pour chaque switch.

---

## Conditions avec `when`

Parfois, on veut exécuter une tâche seulement si une condition est vraie :

```yaml
    # Créer seulement si le switch n'existe pas déjà
    - name: "Créer switch"
      uri:
        url: "..."
        method: POST
        body:
          name: "{{ item.name }}"
      loop: "{{ switches }}"
      when: item.name not in existing_node_names
```

---

## Organiser en plusieurs playbooks

Pour les labs complexes, on sépare en plusieurs fichiers :

```
playbooks/
├── 00_full_lab.yml          # Lance tout
├── 01_create_topology.yml   # Crée la topologie
├── 02_configure_switches.yml # Configure les switches
└── 03_configure_vpcs.yml     # Configure les VPCs
```

### Le playbook principal (00_full_lab.yml)

```yaml
---
- name: "=== PHASE 1 : Création de la topologie ==="
  hosts: localhost
  gather_facts: false
  tasks:
    - debug:
        msg: "Début de la création du lab..."

# Importer les autres playbooks
- import_playbook: 01_create_topology.yml
- import_playbook: 02_configure_switches.yml
- import_playbook: 03_configure_vpcs.yml

- name: "=== TERMINÉ ==="
  hosts: localhost
  gather_facts: false
  tasks:
    - debug:
        msg: "Lab créé avec succès !"
```

### Lancer tout le lab

```bash
ansible-playbook playbooks/00_full_lab.yml
```

### Lancer seulement une partie

```bash
# Seulement la topologie
ansible-playbook playbooks/01_create_topology.yml

# Seulement la config des switches
ansible-playbook playbooks/02_configure_switches.yml
```

---

## Debug et troubleshooting

### Mode verbose

```bash
# Un peu de détails
ansible-playbook playbooks/mon_playbook.yml -v

# Beaucoup de détails
ansible-playbook playbooks/mon_playbook.yml -vv

# Tous les détails (pour debug)
ansible-playbook playbooks/mon_playbook.yml -vvv
```

### Afficher une variable

```yaml
    - name: "Debug - voir le contenu d'une variable"
      debug:
        var: ma_variable

    - name: "Debug - afficher un message"
      debug:
        msg: "La valeur est {{ ma_variable }}"
```

### Vérifier la syntaxe sans exécuter

```bash
ansible-playbook playbooks/mon_playbook.yml --syntax-check
```

---

## Récapitulatif : Workflow complet

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Récupérer les templates (GET /v2/templates)              │
│    └─> template_switch_id, template_vpc_id                  │
├─────────────────────────────────────────────────────────────┤
│ 2. Créer/récupérer le projet (POST /v2/projects)            │
│    └─> project_id                                           │
├─────────────────────────────────────────────────────────────┤
│ 3. Ouvrir le projet (POST /v2/projects/{id}/open)           │
├─────────────────────────────────────────────────────────────┤
│ 4. Créer les nodes (POST /v2/projects/{id}/templates/{id})  │
│    └─> switches, vpcs créés dans GNS3                       │
├─────────────────────────────────────────────────────────────┤
│ 5. Récupérer les nodes (GET /v2/projects/{id}/nodes)        │
│    └─> node_ids, console_ports                              │
├─────────────────────────────────────────────────────────────┤
│ 6. Créer les liens (POST /v2/projects/{id}/links)           │
│    └─> équipements connectés                                │
├─────────────────────────────────────────────────────────────┤
│ 7. Démarrer les nodes (POST /v2/projects/{id}/nodes/start)  │
│    └─> pause 30-90 secondes                                 │
├─────────────────────────────────────────────────────────────┤
│ 8. Sauvegarder switch_info.yml                              │
│    └─> ports console pour la configuration                  │
├─────────────────────────────────────────────────────────────┤
│ 9. Configurer les équipements (via script Python)           │
│    └─> VLANs, IPs, etc.                                     │
└─────────────────────────────────────────────────────────────┘
```

---

La suite dans le tutoriel sur le script Python `cisco_cli.py` !
