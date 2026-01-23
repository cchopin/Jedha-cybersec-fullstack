# Ansible pour la sécurité Linux

**Durée : 60 min**

## Ce que vous allez apprendre dans ce cours

Jusqu'à présent, vous avez appris à sécuriser des systèmes Linux individuellement. Mais comment gérer la sécurité de dizaines ou centaines de machines ? L'automatisation est la réponse. Dans cette leçon, vous apprendrez :

- ce qu'est Ansible et comment il fonctionne,
- comment écrire des playbooks de sécurisation,
- comment automatiser le durcissement de systèmes,
- les bonnes pratiques d'automatisation de la sécurité.

---

## Introduction à Ansible

### Qu'est-ce qu'Ansible ?

**Ansible** est un outil d'automatisation open source qui permet de configurer des systèmes, déployer des applications et orchestrer des tâches complexes. Il est particulièrement adapté à la sécurité car il est :

| Caractéristique | Avantage pour la sécurité |
|-----------------|---------------------------|
| **Agentless** | Pas de logiciel à installer sur les cibles |
| **Idempotent** | Peut être exécuté plusieurs fois sans effets indésirables |
| **Déclaratif** | Décrit l'état désiré plutôt que les étapes |
| **Auditable** | Playbooks versionnables et revues possibles |
| **Reproductible** | Même résultat sur toutes les machines |

### Architecture

```
+------------------+
| Machine de       |
| contrôle         |    SSH
| (Ansible)        |--------+
+------------------+        |
                            |
       +--------------------+--------------------+
       |                    |                    |
       v                    v                    v
+------------+       +------------+       +------------+
|  Serveur 1 |       |  Serveur 2 |       |  Serveur N |
|  (cible)   |       |  (cible)   |       |  (cible)   |
+------------+       +------------+       +------------+
```

### Installation

```bash
# Debian/Ubuntu
$ sudo apt install ansible

# pip (recommandé pour les dernières versions)
$ pip install ansible

# Vérifier l'installation
$ ansible --version
```

---

## Concepts de base

### Inventaire

L'inventaire définit les machines à gérer :

```ini
# /etc/ansible/hosts ou inventory.ini

[webservers]
web1.example.com
web2.example.com

[databases]
db1.example.com
db2.example.com

[production:children]
webservers
databases

[production:vars]
ansible_user=admin
ansible_ssh_private_key_file=~/.ssh/id_ed25519
```

### Modules

Les modules sont les unités de travail d'Ansible. Exemples courants :

| Module | Description |
|--------|-------------|
| `apt` / `yum` | Gestion des packages |
| `copy` | Copier des fichiers |
| `template` | Déployer des templates Jinja2 |
| `service` | Gérer les services |
| `user` | Gérer les utilisateurs |
| `file` | Gérer les permissions de fichiers |
| `lineinfile` | Modifier des lignes dans des fichiers |
| `ufw` | Configurer le pare-feu |
| `sysctl` | Modifier les paramètres noyau |

### Commandes ad-hoc

```bash
# Ping toutes les machines
$ ansible all -i inventory.ini -m ping

# Exécuter une commande
$ ansible webservers -i inventory.ini -m shell -a "uptime"

# Installer un package
$ ansible webservers -i inventory.ini -m apt -a "name=fail2ban state=present" --become
```

---

## Playbooks

Les playbooks sont des fichiers YAML décrivant les tâches à exécuter.

### Structure de base

```yaml
# security-baseline.yml
---
- name: Application de la baseline de sécurité
  hosts: all
  become: yes
  vars:
    ssh_port: 22

  tasks:
    - name: Mettre à jour les packages
      apt:
        update_cache: yes
        upgrade: dist

    - name: Installer les outils de sécurité
      apt:
        name:
          - fail2ban
          - ufw
          - unattended-upgrades
        state: present
```

### Exécuter un playbook

```bash
$ ansible-playbook -i inventory.ini security-baseline.yml

# Mode check (dry-run)
$ ansible-playbook -i inventory.ini security-baseline.yml --check

# Mode verbose
$ ansible-playbook -i inventory.ini security-baseline.yml -v

# Limiter à certains hôtes
$ ansible-playbook -i inventory.ini security-baseline.yml --limit webservers
```

---

## Playbook de durcissement SSH

```yaml
# harden-ssh.yml
---
- name: Durcissement SSH
  hosts: all
  become: yes

  vars:
    ssh_port: 22
    allowed_users:
      - admin
      - deployer

  tasks:
    - name: Configurer le port SSH
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?Port'
        line: "Port {{ ssh_port }}"

    - name: Désactiver le login root
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PermitRootLogin'
        line: "PermitRootLogin no"

    - name: Désactiver l'authentification par mot de passe
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PasswordAuthentication'
        line: "PasswordAuthentication no"

    - name: Activer l'authentification par clé
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PubkeyAuthentication'
        line: "PubkeyAuthentication yes"

    - name: Limiter les utilisateurs autorisés
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?AllowUsers'
        line: "AllowUsers {{ allowed_users | join(' ') }}"

    - name: Configurer les algorithmes de chiffrement
      blockinfile:
        path: /etc/ssh/sshd_config
        block: |
          Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
          MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
          KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
        marker: "# {mark} ANSIBLE MANAGED CRYPTO BLOCK"

    - name: Valider la configuration SSH
      command: sshd -t
      changed_when: false

    - name: Redémarrer SSH
      service:
        name: sshd
        state: restarted
```

---

## Playbook de configuration du pare-feu

```yaml
# firewall.yml
---
- name: Configuration du pare-feu
  hosts: all
  become: yes

  vars:
    allowed_tcp_ports:
      - 22
      - 80
      - 443
    allowed_ips:
      - 10.0.0.0/8

  tasks:
    - name: Installer ufw
      apt:
        name: ufw
        state: present

    - name: Politique par défaut - deny incoming
      ufw:
        direction: incoming
        default: deny

    - name: Politique par défaut - allow outgoing
      ufw:
        direction: outgoing
        default: allow

    - name: Autoriser les ports TCP
      ufw:
        rule: allow
        port: "{{ item }}"
        proto: tcp
      loop: "{{ allowed_tcp_ports }}"

    - name: Autoriser les IPs de confiance
      ufw:
        rule: allow
        src: "{{ item }}"
      loop: "{{ allowed_ips }}"

    - name: Activer ufw
      ufw:
        state: enabled
```

---

## Playbook de configuration fail2ban

```yaml
# fail2ban.yml
---
- name: Installation et configuration fail2ban
  hosts: all
  become: yes

  vars:
    fail2ban_bantime: 3600
    fail2ban_findtime: 600
    fail2ban_maxretry: 3

  tasks:
    - name: Installer fail2ban
      apt:
        name: fail2ban
        state: present

    - name: Configurer jail.local
      template:
        src: templates/jail.local.j2
        dest: /etc/fail2ban/jail.local
        mode: '0644'
      notify: Restart fail2ban

    - name: Activer et démarrer fail2ban
      service:
        name: fail2ban
        state: started
        enabled: yes

  handlers:
    - name: Restart fail2ban
      service:
        name: fail2ban
        state: restarted
```

Template `templates/jail.local.j2` :

```ini
[DEFAULT]
bantime = {{ fail2ban_bantime }}
findtime = {{ fail2ban_findtime }}
maxretry = {{ fail2ban_maxretry }}
banaction = nftables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = {{ fail2ban_maxretry }}
```

---

## Playbook de durcissement système

```yaml
# system-hardening.yml
---
- name: Durcissement système
  hosts: all
  become: yes

  tasks:
    # Paramètres noyau de sécurité
    - name: Configurer les paramètres sysctl
      sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        state: present
        reload: yes
      loop:
        # Réseau
        - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.accept_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.send_redirects', value: '0' }
        - { name: 'net.ipv4.icmp_echo_ignore_broadcasts', value: '1' }
        - { name: 'net.ipv4.tcp_syncookies', value: '1' }
        # Mémoire
        - { name: 'kernel.randomize_va_space', value: '2' }
        - { name: 'kernel.dmesg_restrict', value: '1' }
        - { name: 'kernel.kptr_restrict', value: '2' }

    # Permissions des fichiers sensibles
    - name: Sécuriser /etc/shadow
      file:
        path: /etc/shadow
        mode: '0640'
        owner: root
        group: shadow

    - name: Sécuriser /etc/gshadow
      file:
        path: /etc/gshadow
        mode: '0640'
        owner: root
        group: shadow

    # Désactiver les services inutiles
    - name: Désactiver les services non nécessaires
      service:
        name: "{{ item }}"
        state: stopped
        enabled: no
      loop:
        - cups
        - avahi-daemon
      ignore_errors: yes

    # Mises à jour automatiques
    - name: Configurer les mises à jour automatiques
      apt:
        name: unattended-upgrades
        state: present

    - name: Activer les mises à jour automatiques
      copy:
        dest: /etc/apt/apt.conf.d/20auto-upgrades
        content: |
          APT::Periodic::Update-Package-Lists "1";
          APT::Periodic::Unattended-Upgrade "1";
          APT::Periodic::AutocleanInterval "7";
```

---

## Rôles Ansible

Les rôles permettent d'organiser et réutiliser les playbooks.

### Structure d'un rôle

```
roles/
└── ssh-hardening/
    ├── defaults/
    │   └── main.yml      # Variables par défaut
    ├── handlers/
    │   └── main.yml      # Handlers
    ├── tasks/
    │   └── main.yml      # Tâches principales
    ├── templates/
    │   └── sshd_config.j2
    └── vars/
        └── main.yml      # Variables du rôle
```

### Utiliser un rôle

```yaml
# site.yml
---
- name: Appliquer la sécurité
  hosts: all
  become: yes

  roles:
    - ssh-hardening
    - firewall
    - fail2ban
```

### Rôles de sécurité existants

| Rôle | Description |
|------|-------------|
| `geerlingguy.security` | Baseline de sécurité |
| `dev-sec.os-hardening` | Durcissement OS (CIS) |
| `dev-sec.ssh-hardening` | Durcissement SSH |

```bash
# Installer un rôle depuis Ansible Galaxy
$ ansible-galaxy install dev-sec.os-hardening

# Utiliser
- hosts: all
  roles:
    - dev-sec.os-hardening
```

---

## Ansible Vault

Ansible Vault permet de chiffrer les données sensibles.

### Chiffrer un fichier

```bash
# Créer un fichier chiffré
$ ansible-vault create secrets.yml

# Chiffrer un fichier existant
$ ansible-vault encrypt secrets.yml

# Éditer un fichier chiffré
$ ansible-vault edit secrets.yml

# Déchiffrer
$ ansible-vault decrypt secrets.yml
```

### Utiliser des secrets

```yaml
# secrets.yml (chiffré)
---
db_password: "motdepasse_secret"
api_key: "cle_api_secrete"
```

```yaml
# playbook.yml
---
- hosts: all
  vars_files:
    - secrets.yml

  tasks:
    - name: Configurer la base de données
      template:
        src: db.conf.j2
        dest: /etc/myapp/db.conf
```

```bash
# Exécuter avec le vault
$ ansible-playbook playbook.yml --ask-vault-pass

# Ou avec un fichier de mot de passe
$ ansible-playbook playbook.yml --vault-password-file ~/.vault_pass
```

---

## Bonnes pratiques

### Organisation

```
ansible/
├── inventory/
│   ├── production
│   └── staging
├── group_vars/
│   ├── all.yml
│   ├── webservers.yml
│   └── databases.yml
├── host_vars/
│   └── web1.example.com.yml
├── roles/
├── playbooks/
│   ├── security-baseline.yml
│   └── deploy.yml
└── ansible.cfg
```

### Idempotence

Assurez-vous que vos playbooks peuvent être exécutés plusieurs fois sans effets de bord :

```yaml
# Bon : idempotent
- name: S'assurer que le fichier existe
  file:
    path: /etc/myapp/config
    state: touch
    mode: '0644'

# À éviter : non idempotent
- name: Ajouter une ligne
  shell: echo "config=value" >> /etc/myapp/config
```

### Tests

```bash
# Mode check (dry-run)
$ ansible-playbook playbook.yml --check --diff

# Syntax check
$ ansible-playbook playbook.yml --syntax-check

# Lint
$ ansible-lint playbook.yml
```

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Ansible** | Outil d'automatisation IT open source |
| **Playbook** | Fichier YAML définissant les tâches Ansible |
| **Inventory** | Liste des machines gérées par Ansible |
| **Module** | Unité de travail Ansible |
| **Role** | Collection réutilisable de tâches |
| **Handler** | Tâche déclenchée par une notification |
| **Idempotent** | Peut être exécuté plusieurs fois avec le même résultat |
| **Vault** | Système de chiffrement des secrets Ansible |
| **Galaxy** | Dépôt de rôles Ansible communautaires |
| **Ad-hoc** | Commande Ansible ponctuelle |

---

## Récapitulatif des commandes

### Commandes de base

| Commande | Description |
|----------|-------------|
| `ansible all -m ping` | Tester la connectivité |
| `ansible-playbook playbook.yml` | Exécuter un playbook |
| `ansible-playbook playbook.yml --check` | Mode dry-run |
| `ansible-playbook playbook.yml -v` | Mode verbose |
| `ansible-playbook playbook.yml --limit host` | Limiter aux hôtes |

### Vault

| Commande | Description |
|----------|-------------|
| `ansible-vault create fichier.yml` | Créer un fichier chiffré |
| `ansible-vault edit fichier.yml` | Éditer un fichier chiffré |
| `ansible-vault encrypt fichier.yml` | Chiffrer un fichier |
| `ansible-vault decrypt fichier.yml` | Déchiffrer un fichier |

### Galaxy

| Commande | Description |
|----------|-------------|
| `ansible-galaxy install role` | Installer un rôle |
| `ansible-galaxy list` | Lister les rôles installés |
| `ansible-galaxy init myrole` | Créer un nouveau rôle |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `ansible.cfg` | Configuration Ansible |
| `inventory.ini` | Inventaire des machines |
| `playbook.yml` | Playbook principal |
| `group_vars/` | Variables par groupe |
| `host_vars/` | Variables par hôte |
| `roles/` | Répertoire des rôles |

---

## Ressources

- Ansible Documentation - docs.ansible.com
- Ansible Security Automation - ansible.com/security
- Dev-Sec Hardening Roles - dev-sec.io
- CIS Benchmarks - cisecurity.org

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Ansible](https://tryhackme.com/room/dvansible) | Introduction à Ansible |
| TryHackMe | [Linux Hardening](https://tryhackme.com/room/dvlinuxhardening) | Durcissement à automatiser |
| TryHackMe | [DevSecOps](https://tryhackme.com/room/dvdevsecops) | Sécurité et automatisation |
| HackTheBox | [Pro Labs](https://app.hackthebox.com/prolabs) | Environnements enterprise |
