# Tutoriel Ansible pour GNS3

Bienvenue dans ce tutoriel pour automatiser vos labs GNS3 avec Ansible.

## Objectif

Apprendre à utiliser Ansible pour :
- Créer des topologies réseau automatiquement
- Configurer des switches et routeurs Cisco
- Éviter de tout faire à la main dans GNS3

## Structure du tutoriel

```
00_tutoriel_ansible_for_gns3/
├── README.md                          # Ce fichier
├── 01_installation_ansible.md         # Installation Mac/Windows
├── 02_tutoriel_inventory.md           # Comprendre l'inventaire
├── 03_tutoriel_playbooks.md           # Les playbooks pas à pas
├── 04_script_python_cisco_cli.md      # Le script de configuration
├── 05_cheatsheet_ansible.md           # Cheatsheet des commandes
│
├── ansible.cfg                        # Config Ansible
├── inventory.yml                      # Inventaire (localhost)
├── group_vars/
│   └── all.yml                        # Variables du lab
├── playbooks/
│   ├── 00_full_lab.yml               # Lance tout
│   ├── 01_create_topology.yml        # Crée la topologie
│   ├── 02_configure_switch.yml       # Configure le switch
│   ├── 03_configure_vpcs.yml         # Configure les VPCs
│   └── 04_verify.yml                 # Vérifie la config
└── scripts/
    └── cisco_cli.py                  # Script de configuration
```

## Ordre de lecture recommandé

1. **01_installation_ansible.md** - Installer Ansible sur votre machine
2. **02_tutoriel_inventory.md** - Comprendre la structure des fichiers
3. **03_tutoriel_playbooks.md** - Apprendre à écrire des playbooks
4. **04_script_python_cisco_cli.md** - Comprendre le script de config
5. **05_cheatsheet_ansible.md** - Référence rapide (à garder sous la main)

## Prérequis

- GNS3 avec la VM GNS3 fonctionnelle
- Templates installés dans GNS3 :
  - Cisco IOU L2 (switch)
  - VPCS
- Python 3.x
- Ansible installé (voir le guide d'installation)

## Quick Start

### 1. Vérifier l'IP de votre VM GNS3

L'IP s'affiche au démarrage de la VM GNS3. Notez-la.

### 2. Modifier la configuration

Éditez `group_vars/all.yml` :

```yaml
# Remplacez par l'IP de votre VM GNS3
gns3_server: "http://VOTRE_IP:80"
gns3_host: "VOTRE_IP"
```

### 3. Lancer le lab

```bash
cd 00_tutoriel_ansible_for_gns3
ansible-playbook playbooks/00_full_lab.yml
```

### 4. Vérifier

```bash
ansible-playbook playbooks/04_verify.yml
```

## Ce que fait le mini lab

Le lab de démonstration crée :

```
          ┌──────────┐
          │ Switch1  │
          │ (IOU L2) │
          └────┬─────┘
               │
        ┌──────┴──────┐
        │             │
   ┌────┴───┐    ┌────┴───┐
   │  PC1   │    │  PC2   │
   │ .10.10 │    │ .10.20 │
   └────────┘    └────────┘

   Réseau : 192.168.10.0/24
```

- **Switch1** : Switch Cisco IOU L2 avec VLAN 10
- **PC1** : VPC avec IP 192.168.10.10
- **PC2** : VPC avec IP 192.168.10.20

Les deux PCs peuvent se pinguer car ils sont sur le même VLAN.

## Commandes utiles

| Action | Commande |
|--------|----------|
| Tout lancer | `ansible-playbook playbooks/00_full_lab.yml` |
| Seulement la topologie | `ansible-playbook playbooks/01_create_topology.yml` |
| Seulement la config switch | `ansible-playbook playbooks/02_configure_switch.yml` |
| Seulement les VPCs | `ansible-playbook playbooks/03_configure_vpcs.yml` |
| Vérifier | `ansible-playbook playbooks/04_verify.yml` |
| Mode verbose | `ansible-playbook playbooks/00_full_lab.yml -v` |
| Mode debug | `ansible-playbook playbooks/00_full_lab.yml -vvv` |

## Troubleshooting

### "Connection refused"

1. Vérifiez que la VM GNS3 est démarrée
2. Vérifiez l'IP dans `group_vars/all.yml`
3. Testez : `curl http://IP_GNS3:80/v2/version`

### "Template not found"

Vérifiez que vous avez importé les templates dans GNS3 :
- Edit > Preferences > IOS on UNIX
- Edit > Preferences > VPCS

### Les VPCs ne répondent pas au ping

1. Attendez 30 secondes après le démarrage
2. Vérifiez les IPs dans la console des VPCs
3. Lancez `04_verify.yml` pour diagnostiquer

### Le switch met du temps à démarrer

Normal ! Les switches Cisco IOU prennent 30-90 secondes pour démarrer.
Le playbook attend automatiquement.

## Pour aller plus loin

Une fois ce tutoriel maîtrisé, regardez les labs plus avancés :
- `20_VLAN_trunk_configuration/` - VLANs et trunks
- `21_STP_role_identification/` - Spanning Tree Protocol
- `22_ARP_Spoofing/` - Attaque ARP avec Kali Linux

Bon apprentissage !
