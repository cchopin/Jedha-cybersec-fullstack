# Lab 35 - OSPF Basics

## Scénario

**TechBridge Solutions** est une entreprise de conseil IT qui possède trois bureaux en Europe :
- **Paris** (siège social)
- **Berlin** (bureau régional)
- **Rome** (bureau régional)

Chaque bureau possède un routeur Cisco C2691. Les trois routeurs sont interconnectés en **topologie triangulaire** pour assurer la redondance. Votre mission est de configurer le protocole **OSPF** (Open Shortest Path First) pour permettre une communication optimale entre tous les sites.

## Topologie

```
                    ┌─────────────┐
                    │     R1      │
                    │   (Paris)   │
                    │   C2691     │
                    └──┬───────┬──┘
                 f0/0  │       │  f0/1
          192.168.12.1 │       │ 192.168.31.1
                       │       │
                       │       │
          192.168.12.2 │       │ 192.168.31.2
                 f0/0  │       │  f0/1
                    ┌──┴──┐ ┌──┴──┐
                    │ R2  │ │ R3  │
                    │(Berlin)│(Rome)│
                    │C2691│ │C2691│
                    └──┬──┘ └──┬──┘
                 f0/1  │       │  f0/0
          192.168.23.1 │       │ 192.168.23.2
                       │       │
                       └───────┘
```

## Plan d'adressage IP

| Routeur | Interface | Adresse IP | Masque | Description |
|---------|-----------|------------|--------|-------------|
| R1 (Paris) | FastEthernet0/0 | 192.168.12.1 | 255.255.255.0 | Lien vers R2 |
| R1 (Paris) | FastEthernet0/1 | 192.168.31.1 | 255.255.255.0 | Lien vers R3 |
| R2 (Berlin) | FastEthernet0/0 | 192.168.12.2 | 255.255.255.0 | Lien vers R1 |
| R2 (Berlin) | FastEthernet0/1 | 192.168.23.1 | 255.255.255.0 | Lien vers R3 |
| R3 (Rome) | FastEthernet0/0 | 192.168.23.2 | 255.255.255.0 | Lien vers R2 |
| R3 (Rome) | FastEthernet0/1 | 192.168.31.2 | 255.255.255.0 | Lien vers R1 |

## Réseaux OSPF

| Réseau | Description |
|--------|-------------|
| 192.168.12.0/24 | Lien R1 ↔ R2 (Paris - Berlin) |
| 192.168.23.0/24 | Lien R2 ↔ R3 (Berlin - Rome) |
| 192.168.31.0/24 | Lien R3 ↔ R1 (Rome - Paris) |

## Configuration OSPF

- **Process ID** : 1
- **Area** : 0 (Backbone)
- **Router ID** : Basé sur la plus haute IP de loopback ou interface

## Prérequis

- GNS3 installé et fonctionnel
- Image Cisco C2691 disponible dans GNS3
- Python 3.x avec les modules : `requests`, `ansible`
- Accès au serveur GNS3 : `192.168.144.120`

## Structure du Lab

```
35_OSPF_basics/
├── README.md
├── ansible.cfg
├── inventory.yml
├── group_vars/
│   └── all.yml
├── playbooks/
│   ├── 00_full_lab.yml
│   ├── 01_create_topology.yml
│   ├── 02_configure_ospf.yml
│   └── 03_verify.yml
└── scripts/
    └── cisco_cli.py
```

## Utilisation

### 1. Créer la topologie dans GNS3

```bash
ansible-playbook playbooks/01_create_topology.yml
```

### 2. Configurer OSPF sur les routeurs

```bash
ansible-playbook playbooks/02_configure_ospf.yml
```

### 3. Vérifier la configuration

```bash
ansible-playbook playbooks/03_verify.yml
```

### 4. Exécuter le lab complet

```bash
ansible-playbook playbooks/00_full_lab.yml
```

## Commandes de vérification OSPF

Une fois le lab configuré, vérifiez avec ces commandes sur chaque routeur :

```
# Voir les voisins OSPF
show ip ospf neighbor

# Voir la table de routage OSPF
show ip route ospf

# Voir la base de données OSPF
show ip ospf database

# Voir les interfaces OSPF
show ip ospf interface brief

# Tester la connectivité
ping 192.168.12.2    # Depuis R1 vers R2
ping 192.168.23.2    # Depuis R2 vers R3
ping 192.168.31.1    # Depuis R3 vers R1
```

## Résultats attendus

Après configuration, chaque routeur doit :
1. Avoir **2 voisins OSPF** en état FULL
2. Apprendre **2 routes** via OSPF (les réseaux non directement connectés)
3. Pouvoir **ping** toutes les interfaces des autres routeurs

### Exemple de sortie `show ip ospf neighbor` sur R1

```
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.23.1      1   FULL/DR         00:00:38    192.168.12.2    FastEthernet0/0
192.168.31.2      1   FULL/DR         00:00:35    192.168.31.2    FastEthernet0/1
```

### Exemple de sortie `show ip route ospf` sur R1

```
O    192.168.23.0/24 [110/2] via 192.168.12.2, 00:05:23, FastEthernet0/0
                     [110/2] via 192.168.31.2, 00:05:23, FastEthernet0/1
```

## Concepts OSPF abordés

- **Area 0** : Zone backbone, obligatoire dans OSPF
- **Neighbor** : Routeur adjacent avec qui on échange des LSA
- **LSA** (Link State Advertisement) : Messages décrivant l'état des liens
- **SPF** (Shortest Path First) : Algorithme de Dijkstra pour calculer les routes
- **Cost** : Métrique OSPF basée sur la bande passante (10^8 / bandwidth)
- **DR/BDR** : Designated Router sur les réseaux multi-accès

## Dépannage

Si OSPF ne fonctionne pas :

1. **Vérifier les interfaces** : `show ip interface brief`
2. **Vérifier OSPF activé** : `show ip protocols`
3. **Vérifier les voisins** : `show ip ospf neighbor`
4. **Vérifier les timers** : Hello (10s) et Dead (40s) doivent correspondre
5. **Vérifier les masques** : Doivent être identiques sur un même lien
