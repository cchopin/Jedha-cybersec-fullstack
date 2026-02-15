# Principes de conception d'infrastructure

**Module** : concevoir une infrastructure fiable, sécurisée et évolutive

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Distinguer les trois types d'infrastructure (physique, virtuelle, cloud) et leurs cas d'usage
- Comprendre l'architecture hybride et pourquoi la plupart des entreprises combinent plusieurs approches
- Maîtriser les quatre piliers de conception d'infrastructure : disponibilité, sécurité, scalabilité, maintenabilité
- Évaluer une architecture existante et identifier ses forces et faiblesses
- Comprendre la relation entre coût et qualité d'une infrastructure

---

## 1. Les trois types d'infrastructure

### 1.1 Infrastructure physique (bare metal)

L'infrastructure physique repose sur des serveurs dédiés installés dans un datacenter détenu ou loué par l'entreprise. Chaque machine est entièrement consacrée à une charge de travail spécifique.

| Aspect | Description |
|---|---|
| **Contrôle** | Total : l'entreprise maîtrise le matériel, le système d'exploitation et la configuration |
| **Performance** | Maximale : aucune couche de virtualisation ne vient consommer des ressources |
| **Coût initial** | Élevé : achat de serveurs, location de baies, électricité, refroidissement |
| **Scalabilité** | Limitée : ajouter de la capacité implique commander, recevoir et installer du matériel physique (délai de plusieurs semaines) |
| **Cas d'usage** | Applications nécessitant des performances maximales (bases de données critiques, calcul haute performance, systèmes temps réel) |

> **À noter** : le bare metal reste pertinent dans des contextes où la latence et les performances brutes sont prioritaires, ou lorsque des contraintes réglementaires imposent un contrôle physique total sur les données.

### 1.2 Infrastructure virtuelle

L'infrastructure virtuelle repose sur des **hyperviseurs** qui permettent d'exécuter plusieurs machines virtuelles (VM) sur un même serveur physique. Chaque VM dispose de son propre système d'exploitation et fonctionne comme une machine indépendante.

Les principaux hyperviseurs du marché :

| Hyperviseur | Éditeur | Type |
|---|---|---|
| **VMware ESXi** | Broadcom (anciennement VMware) | Type 1 (bare metal) |
| **KVM** | Open source (intégré au noyau Linux) | Type 1 (bare metal) |
| **Hyper-V** | Microsoft | Type 1 (bare metal) |
| **VirtualBox** | Oracle | Type 2 (hosted) |

Avantages de la virtualisation :

- **Meilleure utilisation des ressources** : un serveur physique peut héberger 10, 20, voire 50 VM
- **Isolation** : chaque VM est isolée des autres, limitant l'impact d'un incident
- **Flexibilité** : création, clonage et suppression de VM en quelques minutes
- **Snapshots** : possibilité de capturer l'état d'une VM à un instant donné pour restauration rapide

### 1.3 Infrastructure cloud

L'infrastructure cloud est fournie par des providers externes qui mettent à disposition des ressources de calcul, de stockage et de réseau à la demande.

| Provider | Nom complet | Part de marché (estimation) |
|---|---|---|
| **AWS** | Amazon Web Services | ~32% |
| **Azure** | Microsoft Azure | ~23% |
| **GCP** | Google Cloud Platform | ~10% |

Le modèle cloud repose sur le principe du **pay-as-you-go** : l'entreprise ne paie que pour les ressources qu'elle consomme. Ce modèle transforme les dépenses d'investissement (CAPEX) en dépenses opérationnelles (OPEX).

| Aspect | Description |
|---|---|
| **Scalabilité** | Quasi illimitée : ajout de ressources en quelques secondes via les API du provider |
| **Coût initial** | Faible : aucun investissement matériel |
| **Contrôle** | Partiel : le provider gère l'infrastructure sous-jacente (modèle de responsabilité partagée) |
| **Disponibilité** | Élevée : les providers offrent des SLA à 99.9% ou plus, avec des datacenters répartis géographiquement |

---

## 2. Architecture hybride

### 2.1 Pourquoi les entreprises combinent les approches

Dans la réalité, la plupart des entreprises ne s'appuient pas sur un seul type d'infrastructure. Elles combinent les trois approches selon les besoins de chaque application :

```
Infrastructure hybride typique
================================

[Bare metal]           [VMs on-premise]         [Cloud public]
Base de données        Serveurs applicatifs     Frontend web
critique (Oracle)      internes (ERP, CRM)      Auto-scaling
                       Environnements de test   CDN
                                                Sauvegardes
```

### 2.2 Critères de répartition

Le choix de l'emplacement d'une charge de travail repose sur plusieurs critères :

| Critère | Bare metal | VM on-premise | Cloud |
|---|---|---|---|
| **Données sensibles / réglementées** | Adapté | Adapté | À évaluer (localisation, chiffrement) |
| **Charge variable** | Peu adapté | Moyennement adapté | Idéal (auto-scaling) |
| **Performance prévisible** | Idéal | Bon | Variable (noisy neighbors) |
| **Budget initial limité** | Inadapté | Inadapté | Idéal |
| **Expertise interne limitée** | Exigeant | Exigeant | Services managés disponibles |

> **Bonne pratique** : avant de choisir un type d'infrastructure, il est essentiel de réaliser un inventaire des charges de travail et de les classer selon leur criticité, leur sensibilité et leur profil de charge.

---

## 3. Les quatre piliers de conception

### 3.1 Disponibilité

La disponibilité mesure la capacité d'un système à rester opérationnel et accessible aux utilisateurs. L'objectif est de minimiser les temps d'indisponibilité, qu'ils soient planifiés (maintenance) ou non (pannes).

**Principe fondamental** : éliminer les points uniques de défaillance (Single Points of Failure, SPOF). Chaque composant critique doit avoir un équivalent de secours capable de prendre le relais automatiquement.

| Mécanisme | Description |
|---|---|
| **Load balancers** | Répartissent le trafic entre plusieurs serveurs. Si un serveur tombe, le trafic est redirigé vers les serveurs restants |
| **Clustering** | Plusieurs serveurs travaillent ensemble comme une unité logique. Le cluster continue de fonctionner même si un nœud tombe |
| **Réplication** | Les données sont copiées sur plusieurs serveurs ou sites géographiques. Une panne d'un serveur n'entraîne pas de perte de données |
| **Failover automatique** | Basculement automatique vers un système de secours en cas de défaillance du système principal |

Les niveaux de disponibilité sont généralement exprimés en pourcentage :

| Niveau | Indisponibilité annuelle | Indisponibilité mensuelle |
|---|---|---|
| 99% | 3.65 jours | ~7.3 heures |
| 99.9% | 8.76 heures | ~43.8 minutes |
| 99.99% | 52.56 minutes | ~4.38 minutes |
| 99.999% | 5.26 minutes | ~26.3 secondes |

> **À noter** : la haute disponibilité (HA) ne signifie pas 100% de disponibilité. Le 100% est un objectif théorique inatteignable. Chaque "9" supplémentaire dans le SLA augmente considérablement le coût et la complexité de l'infrastructure.

### 3.2 Sécurité

La sécurité détermine **qui accède à quoi** et dans quelles conditions. Elle doit être pensée à chaque couche de l'infrastructure, du réseau physique jusqu'à l'application.

| Mécanisme | Description |
|---|---|
| **Segmentation réseau** | Diviser le réseau en zones isolées (DMZ, réseau interne, réseau de gestion) pour limiter la propagation d'une attaque |
| **VPN** | Chiffrer les communications entre les sites distants et les utilisateurs nomades |
| **IAM** (Identity and Access Management) | Gérer les identités, les rôles et les permissions de manière centralisée |
| **Firewalls** | Filtrer le trafic réseau entrant et sortant selon des règles explicites |
| **Chiffrement** | Protéger les données au repos (at rest) et en transit (in transit) |

**Principe du moindre privilège** : chaque utilisateur, service ou processus ne doit disposer que des permissions strictement nécessaires à l'accomplissement de sa tâche. Ce principe s'applique à tous les niveaux :

- Comptes utilisateurs : pas de droits administrateur par défaut
- Services applicatifs : accès limité aux seules bases de données nécessaires
- Règles firewall : autoriser uniquement les flux identifiés, tout le reste est bloqué

> **Bonne pratique** : la sécurité n'est pas une couche ajoutée après coup. Elle doit être intégrée dès la phase de conception de l'infrastructure (approche "Security by Design").

### 3.3 Scalabilité

La scalabilité mesure la capacité d'un système à gérer la croissance, que ce soit en nombre d'utilisateurs, en volume de données ou en charge de traitement.

| Type | Description | Exemple |
|---|---|---|
| **Scalabilité verticale** (scale up) | Augmenter les ressources d'un serveur existant (CPU, RAM, disque) | Passer de 16 Go à 64 Go de RAM |
| **Scalabilité horizontale** (scale out) | Ajouter des serveurs supplémentaires pour répartir la charge | Passer de 2 à 10 serveurs web derrière un load balancer |

La scalabilité horizontale est généralement préférée car elle n'a pas de plafond théorique et elle améliore également la disponibilité (redondance naturelle).

Mécanismes de scalabilité :

| Mécanisme | Description |
|---|---|
| **Auto-scaling** | Ajout et suppression automatiques de serveurs en fonction de la charge (CPU, nombre de requêtes, etc.) |
| **Services stateless** | Les serveurs applicatifs ne stockent pas d'état de session localement, ce qui permet d'ajouter ou de retirer des instances sans impact |
| **Bases de données shardées** | Les données sont réparties sur plusieurs serveurs de base de données (shards) pour distribuer la charge de lecture/écriture |
| **CDN** (Content Delivery Network) | Le contenu statique (images, CSS, JS) est distribué sur des serveurs proches des utilisateurs finaux |

### 3.4 Maintenabilité

La maintenabilité mesure la facilité avec laquelle un système peut être opéré, mis à jour et dépanné au quotidien. Une infrastructure performante mais impossible à maintenir est un échec à moyen terme.

| Mécanisme | Description |
|---|---|
| **IaC** (Infrastructure as Code) | Définir l'infrastructure via du code versionné plutôt que par des configurations manuelles. Outils : **Terraform**, **Ansible**, **Pulumi**, **CloudFormation** |
| **Logging centralisé** | Agréger les logs de tous les composants dans un système central (ELK Stack, Splunk, Datadog) pour faciliter le diagnostic |
| **Monitoring** | Surveiller en continu les métriques de performance, de disponibilité et de sécurité |
| **CI/CD** (Continuous Integration / Continuous Deployment) | Automatiser les tests et les déploiements pour réduire les erreurs humaines et accélérer les mises en production |

L'IaC est un changement de paradigme fondamental :

```
Approche manuelle (à éviter)
============================
1. Se connecter au serveur en SSH
2. Installer les paquets manuellement
3. Modifier les fichiers de configuration
4. Espérer se souvenir de ce qu'on a fait

Approche IaC (recommandée)
==========================
1. Écrire la configuration dans un fichier versionné (Terraform, Ansible)
2. Exécuter le code : l'infrastructure est créée/modifiée automatiquement
3. Committer le changement dans Git
4. L'historique complet des modifications est tracé et reproductible
```

> **Bonne pratique** : toute modification d'infrastructure doit être traçable, reproductible et réversible. L'IaC combinée au versionnement Git est le moyen le plus fiable d'atteindre cet objectif.

---

## 4. Études de cas

### 4.1 Bonne architecture : application e-commerce

```
                        Internet
                           |
                    [Load Balancer]
                     /           \
              [Web Server 1]  [Web Server 2]    <- Auto-scaling group
                     \           /
                    [Application Layer]
                           |
                  [RDS Multi-AZ (PostgreSQL)]   <- Réplication automatique
                           |
                    [S3 - Stockage objets]      <- Sauvegardes automatisées
                           |
                  [CloudWatch - Monitoring]      <- Alertes en temps réel

Réseau :
- Subnets privés pour la base de données et les serveurs applicatifs
- Subnets publics uniquement pour le load balancer
- Security groups restrictifs (ports et sources limités)
```

**Points forts de cette architecture** :

| Élément | Bénéfice |
|---|---|
| Load balancer | Pas de point unique de défaillance sur la couche web |
| Auto-scaling | La capacité s'adapte automatiquement à la charge |
| RDS Multi-AZ | La base de données est répliquée dans une autre zone de disponibilité |
| Monitoring | Les problèmes sont détectés avant qu'ils n'impactent les utilisateurs |
| Subnets privés | La base de données n'est pas accessible directement depuis Internet |

### 4.2 Mauvaise architecture : application sur un seul VPS

```
                        Internet
                           |
                     [VPS unique]
                    - Apache/Nginx
                    - Application PHP
                    - MySQL
                    - Fichiers utilisateurs
                    - Pas de backup
                    - SSH direct en root
                    - Mots de passe en dur
                      dans le code source
```

**Problèmes de cette architecture** :

| Problème | Risque |
|---|---|
| **Serveur unique** | Point unique de défaillance : si le VPS tombe, tout est down |
| **Pas de backup** | Perte définitive des données en cas de panne disque ou d'attaque |
| **SSH direct en root** | Un brute force réussi donne un accès total au serveur |
| **Mots de passe en dur** | Compromission immédiate si le code source est exposé (dépôt Git public, fuite) |
| **Pas de monitoring** | Les problèmes sont découverts quand les utilisateurs se plaignent |
| **Pas de segmentation** | Une vulnérabilité dans l'application donne accès à la base de données sur la même machine |

> **À noter** : cette architecture est malheureusement courante dans les petites entreprises et les projets lancés rapidement sans budget infrastructure. Elle peut fonctionner temporairement mais constitue une dette technique et un risque de sécurité majeurs.

---

## 5. Coût et qualité

### 5.1 Le piège du "moins cher"

Il est tentant de choisir l'infrastructure la moins coûteuse à court terme. Cependant, une infrastructure sous-dimensionnée ou mal conçue génère des coûts cachés importants :

| Coût caché | Description |
|---|---|
| **Temps d'indisponibilité** | Perte de revenus, atteinte à la réputation, pénalités contractuelles |
| **Incidents de sécurité** | Coût moyen d'une violation de données : plusieurs millions d'euros (étude IBM) |
| **Dette technique** | Plus l'infrastructure est négligée, plus sa mise à niveau coûtera cher |
| **Temps d'intervention** | Sans monitoring ni automatisation, chaque incident mobilise des ingénieurs pendant des heures |

### 5.2 Trouver le bon équilibre

Le bon équilibre consiste à dimensionner l'infrastructure en fonction des besoins réels et des risques identifiés :

- **Identifier les composants critiques** : tous les services n'ont pas besoin du même niveau de disponibilité
- **Évaluer le coût de l'indisponibilité** : combien coûte une heure de panne pour chaque service ?
- **Investir proportionnellement** : les composants critiques méritent de la redondance, les composants secondaires peuvent tolérer un niveau de risque plus élevé
- **Revoir régulièrement** : les besoins évoluent, l'infrastructure doit suivre

> **Bonne pratique** : une infrastructure simple n'est pas nécessairement moins chère à long terme. Le coût total de possession (TCO) doit inclure la maintenance, les incidents, la sécurité et l'évolution, pas seulement le coût d'achat initial.

---

## Pour aller plus loin

- [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html)
- [Microsoft Azure Architecture Center](https://learn.microsoft.com/en-us/azure/architecture/)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework)
- [Terraform -- Introduction à l'Infrastructure as Code](https://developer.hashicorp.com/terraform/intro)
- [The Twelve-Factor App](https://12factor.net/)
