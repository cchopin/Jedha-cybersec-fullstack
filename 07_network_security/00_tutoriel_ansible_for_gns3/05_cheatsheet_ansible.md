# Cheatsheet Ansible

Référence rapide des commandes Ansible les plus utiles.

---

## Commandes de base

### Lancer un playbook

```bash
# Syntaxe de base
ansible-playbook playbook.yml

# Avec le chemin complet
ansible-playbook playbooks/00_full_lab.yml

# Spécifier un inventaire différent
ansible-playbook -i mon_inventory.yml playbook.yml
```

### Modes verbose (debug)

```bash
# Un peu de détails
ansible-playbook playbook.yml -v

# Plus de détails
ansible-playbook playbook.yml -vv

# Maximum de détails (pour debug)
ansible-playbook playbook.yml -vvv

# Mode ultra-verbose (connexions)
ansible-playbook playbook.yml -vvvv
```

### Vérification sans exécution

```bash
# Vérifier la syntaxe (ne lance rien)
ansible-playbook playbook.yml --syntax-check

# Dry-run / Mode check (simule sans exécuter)
ansible-playbook playbook.yml --check

# Lister les tâches qui seront exécutées
ansible-playbook playbook.yml --list-tasks

# Lister les hosts concernés
ansible-playbook playbook.yml --list-hosts
```

---

## Gestion de l'inventaire

### Afficher l'inventaire

```bash
# Voir la structure de l'inventaire
ansible-inventory --graph

# Voir avec les variables
ansible-inventory --graph --vars

# Format liste
ansible-inventory --list

# Voir un host spécifique
ansible-inventory --host localhost
```

### Tester la connexion

```bash
# Ping tous les hosts
ansible all -m ping

# Ping un host spécifique
ansible localhost -m ping

# Avec inventaire spécifique
ansible all -i inventory.yml -m ping
```

---

## Exécution de commandes ad-hoc

### Module debug (afficher des infos)

```bash
# Afficher un message
ansible localhost -m debug -a "msg='Hello World'"

# Afficher une variable
ansible localhost -m debug -a "var=ansible_version"

# Afficher les variables d'un host
ansible localhost -m setup
```

### Module shell (exécuter des commandes)

```bash
# Exécuter une commande
ansible localhost -m shell -a "echo Hello"

# Commande avec pipe
ansible localhost -m shell -a "cat /etc/hosts | grep localhost"
```

### Module uri (appels HTTP)

```bash
# Tester l'API GNS3
ansible localhost -m uri -a "url=http://192.168.190.174:80/v2/version"
```

---

## Options utiles des playbooks

### Limiter l'exécution

```bash
# Commencer à une tâche spécifique
ansible-playbook playbook.yml --start-at-task="Nom de la tâche"

# Exécuter une seule tâche (step by step)
ansible-playbook playbook.yml --step

# Limiter à certains hosts
ansible-playbook playbook.yml --limit "localhost"
```

### Tags (exécuter des parties)

```bash
# Lister les tags disponibles
ansible-playbook playbook.yml --list-tags

# Exécuter seulement certains tags
ansible-playbook playbook.yml --tags "config,verify"

# Tout sauf certains tags
ansible-playbook playbook.yml --skip-tags "cleanup"
```

### Variables en ligne de commande

```bash
# Passer une variable
ansible-playbook playbook.yml -e "gns3_host=192.168.1.100"

# Plusieurs variables
ansible-playbook playbook.yml -e "var1=value1" -e "var2=value2"

# Variables depuis un fichier
ansible-playbook playbook.yml -e "@variables.yml"
```

---

## Structure YAML des playbooks

### Playbook minimal

```yaml
---
- name: "Mon playbook"
  hosts: localhost
  gather_facts: false

  tasks:
    - name: "Ma tâche"
      debug:
        msg: "Hello World"
```

### Avec variables

```yaml
---
- name: "Playbook avec variables"
  hosts: localhost
  gather_facts: false

  vars:
    ma_variable: "valeur"
    ma_liste:
      - item1
      - item2

  tasks:
    - name: "Afficher variable"
      debug:
        msg: "{{ ma_variable }}"
```

### Charger des variables externes

```yaml
---
- name: "Playbook"
  hosts: localhost
  gather_facts: false

  vars_files:
    - ../group_vars/all.yml
    - ../switch_info.yml

  tasks:
    - debug:
        msg: "{{ gns3_server }}"
```

---

## Modules fréquents pour GNS3

### uri - Appels API REST

```yaml
# GET - Récupérer des données
- name: "Liste des projets"
  uri:
    url: "{{ gns3_server }}/v2/projects"
    method: GET
  register: result

# POST - Créer quelque chose
- name: "Créer un projet"
  uri:
    url: "{{ gns3_server }}/v2/projects"
    method: POST
    body_format: json
    body:
      name: "MonProjet"
    status_code: [200, 201]
  register: result

# Avec authentification (si nécessaire)
- name: "Appel authentifié"
  uri:
    url: "{{ url }}"
    method: GET
    user: "admin"
    password: "password"
    force_basic_auth: true
```

### script - Exécuter un script local

```yaml
# Script Python
- name: "Configurer le switch"
  script: ../scripts/cisco_cli.py --host {{ ip }} --port {{ port }} --commands "cmd1;cmd2"
  register: result

# Afficher la sortie
- debug:
    var: result.stdout_lines
```

### set_fact - Créer des variables

```yaml
# Variable simple
- set_fact:
    ma_var: "valeur"

# Depuis une expression
- set_fact:
    project_id: "{{ result.json.project_id }}"

# Dictionnaire
- set_fact:
    nodes_dict: "{{ nodes_dict | default({}) | combine({item.name: item}) }}"
  loop: "{{ nodes_list }}"
```

### debug - Afficher des infos

```yaml
# Message simple
- debug:
    msg: "Hello"

# Variable
- debug:
    var: ma_variable

# Liste de messages
- debug:
    msg:
      - "Ligne 1"
      - "Ligne 2"
      - "Variable: {{ ma_var }}"
```

### pause - Attendre

```yaml
# Attendre X secondes
- pause:
    seconds: 30

# Avec message
- pause:
    seconds: 30
    prompt: "Attente du démarrage..."

# Attendre une confirmation
- pause:
    prompt: "Appuyez sur Entrée pour continuer"
```

### copy - Créer/copier des fichiers

```yaml
# Créer un fichier avec contenu
- copy:
    content: |
      ligne1
      ligne2
      variable: {{ ma_var }}
    dest: /chemin/fichier.txt

# Copier un fichier
- copy:
    src: fichier_source.txt
    dest: /chemin/destination.txt
```

### fail - Arrêter avec erreur

```yaml
- fail:
    msg: "Erreur: la variable n'est pas définie"
  when: ma_var is not defined
```

---

## Boucles et conditions

### Boucle simple

```yaml
- name: "Créer plusieurs items"
  debug:
    msg: "Item: {{ item }}"
  loop:
    - item1
    - item2
    - item3
```

### Boucle sur variable

```yaml
- name: "Créer les switches"
  uri:
    url: "{{ gns3_server }}/..."
    body:
      name: "{{ item.name }}"
      x: "{{ item.x }}"
  loop: "{{ switches }}"
```

### Condition when

```yaml
# Si variable définie
- debug:
    msg: "OK"
  when: ma_var is defined

# Si variable a une valeur
- debug:
    msg: "OK"
  when: ma_var == "valeur"

# Si dans une liste
- debug:
    msg: "OK"
  when: item not in existing_items

# Conditions multiples
- debug:
    msg: "OK"
  when:
    - condition1
    - condition2
```

### Ignorer les erreurs

```yaml
- name: "Tâche qui peut échouer"
  uri:
    url: "{{ url }}"
  ignore_errors: true
  register: result

- debug:
    msg: "Erreur ignorée"
  when: result.failed
```

---

## Filtres Jinja2 utiles

### Manipulation de listes

```yaml
# Premier élément
{{ ma_liste | first }}

# Dernier élément
{{ ma_liste | last }}

# Longueur
{{ ma_liste | length }}

# Filtrer par attribut
{{ nodes | selectattr('name', 'equalto', 'Switch1') | list }}

# Extraire un attribut
{{ nodes | map(attribute='name') | list }}

# Joindre en string
{{ commands | join(';') }}
```

### Manipulation de strings

```yaml
# Minuscules
{{ name | lower }}

# Majuscules
{{ name | upper }}

# Remplacer
{{ name | replace('-', '_') }}

# Valeur par défaut
{{ variable | default('valeur_defaut') }}
```

### Conversion

```yaml
# En entier
{{ port | int }}

# En string
{{ number | string }}

# Division entière
{{ port // 4 }}

# Reste (modulo)
{{ port % 4 }}
```

---

## Fichiers de configuration

### ansible.cfg

```ini
[defaults]
# Ne pas vérifier les clés SSH
host_key_checking = False

# Interpréteur Python
interpreter_python = auto_silent

# Timeout (secondes)
timeout = 60

# Inventaire par défaut
inventory = inventory.yml

# Couleurs dans la sortie
force_color = True

# Nombre de tâches parallèles
forks = 10
```

### inventory.yml (pour GNS3)

```yaml
all:
  hosts:
    localhost:
      ansible_connection: local
```

---

## Raccourcis et astuces

| Besoin | Solution |
|--------|----------|
| Voir les variables d'un host | `ansible localhost -m setup` |
| Tester une connexion | `ansible all -m ping` |
| Lister les tâches | `ansible-playbook pb.yml --list-tasks` |
| Exécuter une tâche | `ansible-playbook pb.yml --start-at-task="Nom"` |
| Passer une variable | `-e "var=value"` |
| Mode debug | `-vvv` |
| Dry-run | `--check` |
| Syntaxe check | `--syntax-check` |

---

## Commandes GNS3 API fréquentes

| Action | Endpoint | Méthode |
|--------|----------|---------|
| Liste des projets | `/v2/projects` | GET |
| Créer un projet | `/v2/projects` | POST |
| Ouvrir un projet | `/v2/projects/{id}/open` | POST |
| Liste des templates | `/v2/templates` | GET |
| Créer un node | `/v2/projects/{id}/templates/{tid}` | POST |
| Liste des nodes | `/v2/projects/{id}/nodes` | GET |
| Créer un lien | `/v2/projects/{id}/links` | POST |
| Démarrer les nodes | `/v2/projects/{id}/nodes/start` | POST |
| Arrêter les nodes | `/v2/projects/{id}/nodes/stop` | POST |
| Version GNS3 | `/v2/version` | GET |

---

## Troubleshooting

### Problème de connexion

```bash
# Tester l'API GNS3
curl http://IP_GNS3:80/v2/version

# Vérifier l'inventaire
ansible-inventory --list

# Tester le ping local
ansible localhost -m ping
```

### Problème de variables

```bash
# Afficher toutes les variables
ansible localhost -m debug -a "var=hostvars[inventory_hostname]"

# Afficher une variable spécifique
ansible localhost -m debug -a "var=gns3_server"
```

### Playbook qui échoue

```bash
# Mode verbose pour plus de détails
ansible-playbook playbook.yml -vvv

# Commencer à la tâche qui échoue
ansible-playbook playbook.yml --start-at-task="Nom de la tâche"

# Mode step by step
ansible-playbook playbook.yml --step
```
