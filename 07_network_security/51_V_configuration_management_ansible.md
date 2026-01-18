# Gestion de Configuration et Ansible - Version Simplifiée

## L'idée en une phrase

**Ansible** permet d'écrire UNE fois la configuration désirée dans un fichier YAML, puis de l'appliquer automatiquement à des centaines d'équipements réseau via SSH, sans rien installer dessus.

---

## Le Problème : Gestion Manuelle

```
SANS AUTOMATISATION :
═════════════════════

[Admin] ──SSH──► Switch 1 ──► Taper les commandes ──► 10 min
        ──SSH──► Switch 2 ──► Taper les commandes ──► 10 min
        ──SSH──► Switch 3 ──► Taper les commandes ──► 10 min
        ...
        ──SSH──► Switch 100 ──► Taper les commandes ──► 10 min

Temps total : 16+ heures
Risque d'erreur : ÉLEVÉ
Traçabilité : AUCUNE


AVEC ANSIBLE :
══════════════

[Admin] ──► Écrit UN fichier YAML ──► ansible-playbook run

        Ansible ──► Switch 1 ──┐
                ──► Switch 2 ──┤
                ──► Switch 3 ──┼──► EN PARALLÈLE
                ...            │
                ──► Switch 100 ┘

Temps total : ~5 minutes
Risque d'erreur : FAIBLE (même commandes partout)
Traçabilité : TOTALE (fichier dans Git)
```

---

## Ansible : Les Bases

### C'est Quoi ?

- Outil d'automatisation **open-source** (Red Hat)
- **Sans agent** : pas besoin d'installer quoi que ce soit sur les équipements
- Utilise **SSH** pour se connecter
- Configuration en **YAML** (fichiers lisibles)

### Les 3 Fichiers Clés

```
┌─────────────────────────────────────────────────────────────┐
│              LES 3 FICHIERS ANSIBLE                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. INVENTORY (qui ?)                                       │
│   ────────────────────                                       │
│   Liste des équipements et leurs identifiants                │
│                                                              │
│   [switches]                                                 │
│   SW1 ansible_host=192.168.0.1                               │
│   SW2 ansible_host=192.168.0.2                               │
│                                                              │
│   [switches:vars]                                            │
│   ansible_user=admin                                         │
│   ansible_password=secret                                    │
│                                                              │
│   2. PLAYBOOK (quoi faire ?)                                 │
│   ──────────────────────────                                 │
│   Les instructions à exécuter                                │
│                                                              │
│   - name: Configure switches                                 │
│     hosts: switches                                          │
│     tasks:                                                   │
│       - name: Create VLAN 10                                 │
│         ios_config:                                          │
│           lines:                                             │
│             - vlan 10                                        │
│             - name Marketing                                 │
│                                                              │
│   3. COMMANDE (comment lancer ?)                             │
│   ──────────────────────────────                             │
│                                                              │
│   ansible-playbook -i inventory.yml playbook.yml             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Exemple Concret : Créer des VLANs

### 1. L'Inventory (qui cibler ?)

```yaml
# inventory.yml
[switches]
SW1 ansible_host=192.168.0.1
SW2 ansible_host=192.168.0.2
SW3 ansible_host=192.168.0.3

[switches:vars]
ansible_user=ansible            # Nom d'utilisateur pour se connecter
ansible_password=ansible123     # Mot de passe
ansible_network_os=ios          # Type d'équipement (ios = Cisco)
ansible_connection=network_cli  # Méthode de connexion (ligne de commande via SSH)
```

### 2. Le Playbook (quoi faire ?)

```yaml
# playbook.yml
- name: Configure VLANs on all switches    # Description de ce qu'on fait
  hosts: switches                           # Sur quels équipements (définis dans l'inventory)
  gather_facts: no                          # Ne pas collecter d'infos système (plus rapide)

  tasks:                                    # Liste des actions à faire
    - name: Create VLAN 10 Marketing        # Description de la tâche
      ios_config:                           # Module Ansible pour configurer Cisco IOS
        lines:                              # Commandes à taper (comme en CLI)
          - vlan 10
          - name Marketing

    - name: Create VLAN 20 Finance
      ios_config:                           # ios_config = "envoie ces commandes à un switch Cisco"
        lines:
          - vlan 20
          - name Finance
```

**Traduction** : Ce playbook dit "se connecter à tous les switches et taper ces commandes pour créer les VLANs".

### 3. Exécution

```bash
# Lancer le playbook
ansible-playbook -i inventory.yml playbook.yml

# Résultat
PLAY [Configure VLANs on all switches] *****

TASK [Create VLAN 10 Marketing] *****
changed: [SW1]
changed: [SW2]
changed: [SW3]

TASK [Create VLAN 20 Finance] *****
changed: [SW1]
changed: [SW2]
changed: [SW3]

PLAY RECAP *****
SW1 : ok=2 changed=2 failed=0
SW2 : ok=2 changed=2 failed=0
SW3 : ok=2 changed=2 failed=0
```

---

## Modules Courants par Vendeur

Un **module** Ansible = un outil spécialisé pour une action précise.
Chaque fabricant a ses propres modules.

```
┌─────────────────────────────────────────────────────────────┐
│                  MODULES PAR VENDEUR                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   CISCO IOS :                                                │
│   • ios_config  → Envoyer des commandes de configuration     │
│                   (comme si on tapait dans le terminal)      │
│   • ios_facts   → Récupérer des infos (version, interfaces)  │
│   • ios_command → Lancer des "show" (lecture seule)          │
│                                                              │
│   JUNIPER :                                                  │
│   • junos_config → Même chose pour équipements Juniper       │
│   • junos_facts  → Collecter les infos Juniper               │
│                                                              │
│   ARISTA :                                                   │
│   • eos_config   → Configuration switches Arista             │
│   • eos_vlan     → Créer des VLANs (simplifié)               │
│                                                              │
│   PALO ALTO :                                                │
│   • panos_security_rule → Créer des règles firewall          │
│                                                              │
│   Logique : [vendeur]_[action]                               │
│   ios_config, junos_config, eos_config → tous font la même   │
│   chose mais pour des équipements différents                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Cas d'Usage Courants

### 1. Pousser des Configs

```yaml
# Configurer une interface
- name: Configure interface
  ios_config:
    lines:
      - description Lien vers Serveurs
      - switchport mode trunk
    parents: interface GigabitEthernet0/1
```

### 2. Collecter des Infos

```yaml
# Récupérer les VLANs existants
- name: Get VLAN info
  ios_command:
    commands:
      - show vlan brief
  register: vlan_output

- name: Display VLANs
  debug:
    var: vlan_output.stdout
```

### 3. Vérifier la Conformité

```yaml
# Vérifier que NTP est configuré
- name: Check NTP
  ios_command:
    commands:
      - show running-config | include ntp
  register: ntp_check

- name: Fail if no NTP
  fail:
    msg: "NTP not configured!"
  when: "'ntp server' not in ntp_check.stdout[0]"
```

### 4. Sauvegarder les Configs

```yaml
# Backup de la config
- name: Backup running config
  ios_command:
    commands:
      - show running-config
  register: config

- name: Save to file
  copy:
    content: "{{ config.stdout[0] }}"
    dest: "backups/{{ inventory_hostname }}.cfg"
```

---

## L'Idempotence : Rejouer Sans Risque

```
QU'EST-CE QUE L'IDEMPOTENCE ?
═════════════════════════════

1ère exécution :
[Ansible] ──► "Créer VLAN 10" ──► [Switch] ──► VLAN 10 créé ✓

2ème exécution (même playbook) :
[Ansible] ──► "Créer VLAN 10" ──► [Switch] ──► "Déjà existe" ──► Rien à faire ✓

= Le playbook peut être relancé 100 fois
  → Il ne fera que ce qui est nécessaire
  → Pas de doublons, pas d'erreurs
```

---

## Outils de Backup : RANCID / Oxidized

### Pourquoi Sauvegarder ?

```
MÊME AVEC ANSIBLE, IL FAUT DES BACKUPS :
════════════════════════════════════════

• Quelqu'un fait un changement manuel → on veut le détecter
• Incident → on veut comparer avant/après
• Audit → prouver l'état à un instant T
• Rollback → revenir à une version précédente
```

### Comment Ça Marche ?

```
┌─────────────────────────────────────────────────────────────┐
│              OXIDIZED (outil de backup)                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Toutes les heures :                                        │
│                                                              │
│   [Oxidized] ──SSH──► [Switch 1] ──► Récupère running-config │
│              ──SSH──► [Switch 2] ──► Récupère running-config │
│              ──SSH──► [Switch 3] ──► Récupère running-config │
│                             │                                │
│                             ▼                                │
│                      Compare avec la version précédente      │
│                             │                                │
│                    ┌────────┴────────┐                       │
│                    │                 │                       │
│               Différent ?        Identique ?                 │
│                    │                 │                       │
│                    ▼                 │                       │
│            Commit dans Git      Rien à faire                 │
│            + Alerte email                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Workflow Complet : GitOps Réseau

```
┌─────────────────────────────────────────────────────────────┐
│                 WORKFLOW GITOPS RÉSEAU                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. DÉVELOPPEMENT                                           │
│   ────────────────                                           │
│   [Admin] écrit playbook.yml                                 │
│       │                                                      │
│       ▼                                                      │
│   git commit + push                                          │
│                                                              │
│   2. REVIEW                                                  │
│   ────────                                                   │
│   Merge Request / Pull Request                               │
│   → Collègue vérifie                                         │
│   → Tests automatiques (lint, check)                         │
│       │                                                      │
│       ▼                                                      │
│   Merge dans main                                            │
│                                                              │
│   3. DÉPLOIEMENT                                             │
│   ─────────────                                              │
│   CI/CD lance : ansible-playbook deploy.yml                  │
│       │                                                      │
│       ▼                                                      │
│   [Équipements] configurés                                   │
│                                                              │
│   4. MONITORING                                              │
│   ────────────                                               │
│   [Oxidized] détecte les changements                         │
│   → Alerte si drift (changement non prévu)                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Les Termes à Retenir

| Terme | Définition simple |
|-------|-------------------|
| **Ansible** | Outil d'automatisation sans agent |
| **Playbook** | Fichier YAML avec les instructions |
| **Inventory** | Liste des équipements cibles |
| **Module** | Code qui fait une action spécifique |
| **Task** | Une action dans un playbook |
| **Idempotent** | Peut être rejoué sans effet de bord |
| **Facts** | Infos collectées sur un équipement |
| **RANCID/Oxidized** | Outils de backup de configs |
| **GitOps** | Gestion du réseau via Git |
| **Drift** | Écart entre config voulue et réelle |

---

## Résumé en 30 Secondes

```
ANSIBLE = Automatiser la configuration réseau
═══════════════════════════════════════════

AVANT :
• SSH sur chaque équipement
• Taper les commandes à la main
• Risque d'erreur, pas de traçabilité

APRÈS :
• UN fichier YAML (playbook)
• UNE commande : ansible-playbook
• Configuration identique sur tous les équipements

FICHIERS :
1. inventory.yml = QUI cibler
2. playbook.yml  = QUOI faire
3. ansible-playbook = COMMENT lancer

BONUS :
• RANCID/Oxidized = backup automatique des configs
• Git = versioning et traçabilité
• CI/CD = déploiement automatique après validation
```

---

## Schéma Récapitulatif

```
COMPOSANTS ANSIBLE :
════════════════════

   inventory.yml          playbook.yml
   ─────────────          ────────────
   [switches]             - name: Config
   SW1 192.168.0.1          tasks:
   SW2 192.168.0.2            - ios_config: ...
           │                        │
           └──────────┬─────────────┘
                      │
                      ▼
              ansible-playbook
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
      [SW1]        [SW2]        [SW3]


WORKFLOW COMPLET :
══════════════════

   [Admin] ──► Écrit playbook ──► Git push
                                    │
                                    ▼
                               CI/CD Tests
                                    │
                                    ▼
                               Merge OK
                                    │
                                    ▼
                            ansible-playbook
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
               [Switches]      [Routers]     [Firewalls]
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                                    ▼
                               [Oxidized]
                               (Backup)
                                    │
                                    ▼
                                 [Git]
                            (Historique)


IDEMPOTENCE :
═════════════

1ère fois : "Créer VLAN 10" → Créé ✓
2ème fois : "Créer VLAN 10" → "Déjà fait" → Rien ✓

= Rejouer sans risque
```
