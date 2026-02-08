# Detect Attack with Ansible - Rapport de Lab

**Auteur :** Clemence Chopin
**Date :** 2026-02-08
**Classification :** Exercice de Lab - Identité et Automatisation

---

## Contexte

Nyanflix, une plateforme de streaming de vidéos de chats, a subi un incident de cybersécurité. L'infrastructure se compose de trois machines :

| Machine | Rôle | IP |
|---------|------|----|
| `web-frontend` | Interface web | 11.10.10.23 |
| `db-backend` | Base de données métriques et habitudes | 11.10.10.24 |
| `logs-collector` | Agrégation de logs et statistiques | 11.10.10.25 |

Trois indicateurs de compromission (IOC) ont été identifiés sur `web-frontend` :
1. Un utilisateur malveillant `syscheck`
2. Une mauvaise configuration SSH (PasswordAuthentication + PermitRootLogin activés)
3. Des scripts `.sh` suspects dans `/tmp`

**Objectif :** Utiliser Ansible pour automatiser la détection et la remédiation sur toutes les machines.

---

## Étape 1 : Vérification de la connectivité

```bash
ansible all -i /ansible/inventory -m ping
```

**Résultat :** Les trois nœuds ont répondu `pong` - connectivité confirmée.

---

## Étape 2 : Détection de l'utilisateur malveillant

**Méthode :** `getent passwd syscheck` via le module `shell`.

**Résultats :**

| Machine | Utilisateur syscheck trouvé ? |
|---------|-------------------------------|
| `web-frontend` | OUI |
| `db-backend` | NON |
| `logs-collector` | OUI |

**Réponse à la question de l'exercice :** `logs-collector` est l'autre machine compromise.

---

## Étape 3 : Détection de la mauvaise configuration SSH

**Méthode :** `grep` sur `/etc/ssh/sshd_config` pour rechercher `PasswordAuthentication yes` et `PermitRootLogin yes`.

**Résultats :**

| Machine | PasswordAuth=yes | RootLogin=yes |
|---------|-------------------|---------------|
| `web-frontend` | OUI | OUI |
| `db-backend` | NON | NON |
| `logs-collector` | OUI | OUI |

---

## Étape 4 : Détection des scripts suspects

**Méthode :** Module `find` d'Ansible pour rechercher les fichiers `*.sh` dans `/tmp`.

**Résultats :**

| Machine | Scripts trouvés |
|---------|-----------------|
| `web-frontend` | `/tmp/malware.sh` (41 octets, propriétaire root) |
| `db-backend` | Aucun |
| `logs-collector` | `/tmp/malware.sh` (41 octets, propriétaire root) |

---

## Étape 5 : Organisation des playbooks

Les playbooks sont organisés en rôles Ansible avec des tags `detect` et `fix` :

```
ansible-volume/
├── inventory/
│   ├── frontend              # [frontend] web-frontend
│   └── backend               # [backend] db-backend, logs-collector
├── detect.yml                # Playbook simple de détection (Étapes 2-4)
├── site.yml                  # Playbook avec rôles et tags (Étapes 5-6)
└── roles/
    ├── rogue_user/
    │   └── tasks/main.yml    # Détection + suppression utilisateur syscheck
    ├── ssh_config/
    │   └── tasks/main.yml    # Détection + durcissement config SSH
    └── suspicious_scripts/
        └── tasks/main.yml    # Détection + suppression scripts dans /tmp
```

**Utilisation :**
- Détection uniquement : `ansible-playbook -i /ansible/inventory /ansible/site.yml --tags detect`
- Correction uniquement : `ansible-playbook -i /ansible/inventory /ansible/site.yml --tags fix`
- Les deux : `ansible-playbook -i /ansible/inventory /ansible/site.yml`

---

## Étape 6 : Remédiation

**Actions effectuées par le playbook de correction :**

| Action | Module utilisé | Détails |
|--------|----------------|---------|
| Supprimer l'utilisateur `syscheck` | `user` | `state: absent`, `remove: yes` |
| Désactiver PasswordAuthentication | `lineinfile` | Remplacé par `no` dans sshd_config |
| Désactiver PermitRootLogin | `lineinfile` | Remplacé par `no` dans sshd_config |
| Supprimer les scripts dans `/tmp` | `file` | `state: absent` sur chaque fichier `.sh` trouvé |

**Vérification :** Après l'exécution de la correction, une seconde passe de détection a confirmé que les trois machines sont propres (toutes les tâches de détection ont été ignorées = aucun problème trouvé).

---

## Synthèse

| Machine | Compromise ? | Problèmes trouvés | État après correction |
|---------|-------------|--------------------|-----------------------|
| `web-frontend` | OUI | utilisateur syscheck, mauvaise config SSH, /tmp/malware.sh | PROPRE |
| `db-backend` | NON | Aucun | PROPRE |
| `logs-collector` | OUI | utilisateur syscheck, mauvaise config SSH, /tmp/malware.sh | PROPRE |

Tous les indicateurs de compromission ont été détectés et corrigés avec succès grâce à l'automatisation Ansible.
