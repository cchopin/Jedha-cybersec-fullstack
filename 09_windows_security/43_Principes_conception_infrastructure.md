# Principes de conception d'infrastructure

**Module** : concevoir une infrastructure fiable, securisee et evolutive

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Distinguer les trois types d'infrastructure (physique, virtuelle, cloud) et leurs cas d'usage
- Comprendre l'architecture hybride et pourquoi la plupart des entreprises combinent plusieurs approches
- Maitriser les quatre piliers de conception d'infrastructure : disponibilite, securite, scalabilite, maintenabilite
- Evaluer une architecture existante et identifier ses forces et faiblesses
- Comprendre la relation entre cout et qualite d'une infrastructure

---

## 1. Les trois types d'infrastructure

### 1.1 Infrastructure physique (bare metal)

L'infrastructure physique repose sur des serveurs dedies installes dans un datacenter detenu ou loue par l'entreprise. Chaque machine est entierement consacree a une charge de travail specifique.

| Aspect | Description |
|---|---|
| **Controle** | Total : l'entreprise maitrise le materiel, le systeme d'exploitation et la configuration |
| **Performance** | Maximale : aucune couche de virtualisation ne vient consommer des ressources |
| **Cout initial** | Eleve : achat de serveurs, location de baies, electricite, refroidissement |
| **Scalabilite** | Limitee : ajouter de la capacite implique commander, recevoir et installer du materiel physique (delai de plusieurs semaines) |
| **Cas d'usage** | Applications necessitant des performances maximales (bases de donnees critiques, calcul haute performance, systemes temps reel) |

> **A noter** : le bare metal reste pertinent dans des contextes ou la latence et les performances brutes sont prioritaires, ou lorsque des contraintes reglementaires imposent un controle physique total sur les donnees.

### 1.2 Infrastructure virtuelle

L'infrastructure virtuelle repose sur des **hyperviseurs** qui permettent d'executer plusieurs machines virtuelles (VM) sur un meme serveur physique. Chaque VM dispose de son propre systeme d'exploitation et fonctionne comme une machine independante.

Les principaux hyperviseurs du marche :

| Hyperviseur | Editeur | Type |
|---|---|---|
| **VMware ESXi** | Broadcom (anciennement VMware) | Type 1 (bare metal) |
| **KVM** | Open source (integre au noyau Linux) | Type 1 (bare metal) |
| **Hyper-V** | Microsoft | Type 1 (bare metal) |
| **VirtualBox** | Oracle | Type 2 (hosted) |

Avantages de la virtualisation :

- **Meilleure utilisation des ressources** : un serveur physique peut heberger 10, 20, voire 50 VM
- **Isolation** : chaque VM est isolee des autres, limitant l'impact d'un incident
- **Flexibilite** : creation, clonage et suppression de VM en quelques minutes
- **Snapshots** : possibilite de capturer l'etat d'une VM a un instant donne pour restauration rapide

### 1.3 Infrastructure cloud

L'infrastructure cloud est fournie par des providers externes qui mettent a disposition des ressources de calcul, de stockage et de reseau a la demande.

| Provider | Nom complet | Part de marche (estimation) |
|---|---|---|
| **AWS** | Amazon Web Services | ~32% |
| **Azure** | Microsoft Azure | ~23% |
| **GCP** | Google Cloud Platform | ~10% |

Le modele cloud repose sur le principe du **pay-as-you-go** : l'entreprise ne paie que pour les ressources qu'elle consomme. Ce modele transforme les depenses d'investissement (CAPEX) en depenses operationnelles (OPEX).

| Aspect | Description |
|---|---|
| **Scalabilite** | Quasi illimitee : ajout de ressources en quelques secondes via les API du provider |
| **Cout initial** | Faible : aucun investissement materiel |
| **Controle** | Partiel : le provider gere l'infrastructure sous-jacente (modele de responsabilite partagee) |
| **Disponibilite** | Elevee : les providers offrent des SLA a 99.9% ou plus, avec des datacenters repartis geographiquement |

---

## 2. Architecture hybride

### 2.1 Pourquoi les entreprises combinent les approches

Dans la realite, la plupart des entreprises ne s'appuient pas sur un seul type d'infrastructure. Elles combinent les trois approches selon les besoins de chaque application :

```
Infrastructure hybride typique
================================

[Bare metal]           [VMs on-premise]         [Cloud public]
Base de donnees        Serveurs applicatifs     Frontend web
critique (Oracle)      internes (ERP, CRM)      Auto-scaling
                       Environnements de test   CDN
                                                Sauvegardes
```

### 2.2 Criteres de repartition

Le choix de l'emplacement d'une charge de travail repose sur plusieurs criteres :

| Critere | Bare metal | VM on-premise | Cloud |
|---|---|---|---|
| **Donnees sensibles / reglementees** | Adapte | Adapte | A evaluer (localisation, chiffrement) |
| **Charge variable** | Peu adapte | Moyennement adapte | Ideal (auto-scaling) |
| **Performance previsible** | Ideal | Bon | Variable (noisy neighbors) |
| **Budget initial limite** | Inadapte | Inadapte | Ideal |
| **Expertise interne limitee** | Exigeant | Exigeant | Services manages disponibles |

> **Bonne pratique** : avant de choisir un type d'infrastructure, il est essentiel de realiser un inventaire des charges de travail et de les classer selon leur criticite, leur sensibilite et leur profil de charge.

---

## 3. Les quatre piliers de conception

### 3.1 Disponibilite

La disponibilite mesure la capacite d'un systeme a rester operationnel et accessible aux utilisateurs. L'objectif est de minimiser les temps d'indisponibilite, qu'ils soient planifies (maintenance) ou non (pannes).

**Principe fondamental** : eliminer les points uniques de defaillance (Single Points of Failure, SPOF). Chaque composant critique doit avoir un equivalent de secours capable de prendre le relais automatiquement.

| Mecanisme | Description |
|---|---|
| **Load balancers** | Repartissent le trafic entre plusieurs serveurs. Si un serveur tombe, le trafic est redirige vers les serveurs restants |
| **Clustering** | Plusieurs serveurs travaillent ensemble comme une unite logique. Le cluster continue de fonctionner meme si un noeud tombe |
| **Replication** | Les donnees sont copiees sur plusieurs serveurs ou sites geographiques. Une panne d'un serveur n'entraine pas de perte de donnees |
| **Failover automatique** | Basculement automatique vers un systeme de secours en cas de defaillance du systeme principal |

Les niveaux de disponibilite sont generalement exprimes en pourcentage :

| Niveau | Indisponibilite annuelle | Indisponibilite mensuelle |
|---|---|---|
| 99% | 3.65 jours | ~7.3 heures |
| 99.9% | 8.76 heures | ~43.8 minutes |
| 99.99% | 52.56 minutes | ~4.38 minutes |
| 99.999% | 5.26 minutes | ~26.3 secondes |

> **A noter** : la haute disponibilite (HA) ne signifie pas 100% de disponibilite. Le 100% est un objectif theorique inatteignable. Chaque "9" supplementaire dans le SLA augmente considerablement le cout et la complexite de l'infrastructure.

### 3.2 Securite

La securite determine **qui accede a quoi** et dans quelles conditions. Elle doit etre pensee a chaque couche de l'infrastructure, du reseau physique jusqu'a l'application.

| Mecanisme | Description |
|---|---|
| **Segmentation reseau** | Diviser le reseau en zones isolees (DMZ, reseau interne, reseau de gestion) pour limiter la propagation d'une attaque |
| **VPN** | Chiffrer les communications entre les sites distants et les utilisateurs nomades |
| **IAM** (Identity and Access Management) | Gerer les identites, les roles et les permissions de maniere centralisee |
| **Firewalls** | Filtrer le trafic reseau entrant et sortant selon des regles explicites |
| **Chiffrement** | Proteger les donnees au repos (at rest) et en transit (in transit) |

**Principe du moindre privilege** : chaque utilisateur, service ou processus ne doit disposer que des permissions strictement necessaires a l'accomplissement de sa tache. Ce principe s'applique a tous les niveaux :

- Comptes utilisateurs : pas de droits administrateur par defaut
- Services applicatifs : acces limite aux seules bases de donnees necessaires
- Regles firewall : autoriser uniquement les flux identifies, tout le reste est bloque

> **Bonne pratique** : la securite n'est pas une couche ajoutee apres coup. Elle doit etre integree des la phase de conception de l'infrastructure (approche "Security by Design").

### 3.3 Scalabilite

La scalabilite mesure la capacite d'un systeme a gerer la croissance, que ce soit en nombre d'utilisateurs, en volume de donnees ou en charge de traitement.

| Type | Description | Exemple |
|---|---|---|
| **Scalabilite verticale** (scale up) | Augmenter les ressources d'un serveur existant (CPU, RAM, disque) | Passer de 16 Go a 64 Go de RAM |
| **Scalabilite horizontale** (scale out) | Ajouter des serveurs supplementaires pour repartir la charge | Passer de 2 a 10 serveurs web derriere un load balancer |

La scalabilite horizontale est generalement preferee car elle n'a pas de plafond theorique et elle ameliore egalement la disponibilite (redondance naturelle).

Mecanismes de scalabilite :

| Mecanisme | Description |
|---|---|
| **Auto-scaling** | Ajout et suppression automatiques de serveurs en fonction de la charge (CPU, nombre de requetes, etc.) |
| **Services stateless** | Les serveurs applicatifs ne stockent pas d'etat de session localement, ce qui permet d'ajouter ou de retirer des instances sans impact |
| **Bases de donnees shardees** | Les donnees sont reparties sur plusieurs serveurs de base de donnees (shards) pour distribuer la charge de lecture/ecriture |
| **CDN** (Content Delivery Network) | Le contenu statique (images, CSS, JS) est distribue sur des serveurs proches des utilisateurs finaux |

### 3.4 Maintenabilite

La maintenabilite mesure la facilite avec laquelle un systeme peut etre opere, mis a jour et depanne au quotidien. Une infrastructure performante mais impossible a maintenir est un echec a moyen terme.

| Mecanisme | Description |
|---|---|
| **IaC** (Infrastructure as Code) | Definir l'infrastructure via du code versionne plutot que par des configurations manuelles. Outils : **Terraform**, **Ansible**, **Pulumi**, **CloudFormation** |
| **Logging centralise** | Agreger les logs de tous les composants dans un systeme central (ELK Stack, Splunk, Datadog) pour faciliter le diagnostic |
| **Monitoring** | Surveiller en continu les metriques de performance, de disponibilite et de securite |
| **CI/CD** (Continuous Integration / Continuous Deployment) | Automatiser les tests et les deploiements pour reduire les erreurs humaines et accelerer les mises en production |

L'IaC est un changement de paradigme fondamental :

```
Approche manuelle (a eviter)
============================
1. Se connecter au serveur en SSH
2. Installer les paquets manuellement
3. Modifier les fichiers de configuration
4. Esperer se souvenir de ce qu'on a fait

Approche IaC (recommandee)
==========================
1. Ecrire la configuration dans un fichier versionne (Terraform, Ansible)
2. Executer le code : l'infrastructure est creee/modifiee automatiquement
3. Committer le changement dans Git
4. L'historique complet des modifications est trace et reproductible
```

> **Bonne pratique** : toute modification d'infrastructure doit etre tracable, reproductible et reversible. L'IaC combinee au versionnement Git est le moyen le plus fiable d'atteindre cet objectif.

---

## 4. Etudes de cas

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
                  [RDS Multi-AZ (PostgreSQL)]   <- Replication automatique
                           |
                    [S3 - Stockage objets]      <- Sauvegardes automatisees
                           |
                  [CloudWatch - Monitoring]      <- Alertes en temps reel

Reseau :
- Subnets prives pour la base de donnees et les serveurs applicatifs
- Subnets publics uniquement pour le load balancer
- Security groups restrictifs (ports et sources limites)
```

**Points forts de cette architecture** :

| Element | Benefice |
|---|---|
| Load balancer | Pas de point unique de defaillance sur la couche web |
| Auto-scaling | La capacite s'adapte automatiquement a la charge |
| RDS Multi-AZ | La base de donnees est repliquee dans une autre zone de disponibilite |
| Monitoring | Les problemes sont detectes avant qu'ils n'impactent les utilisateurs |
| Subnets prives | La base de donnees n'est pas accessible directement depuis Internet |

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

**Problemes de cette architecture** :

| Probleme | Risque |
|---|---|
| **Serveur unique** | Point unique de defaillance : si le VPS tombe, tout est down |
| **Pas de backup** | Perte definitive des donnees en cas de panne disque ou d'attaque |
| **SSH direct en root** | Un brute force reussi donne un acces total au serveur |
| **Mots de passe en dur** | Compromission immediate si le code source est expose (depot Git public, fuite) |
| **Pas de monitoring** | Les problemes sont decouverts quand les utilisateurs se plaignent |
| **Pas de segmentation** | Une vulnerabilite dans l'application donne acces a la base de donnees sur la meme machine |

> **A noter** : cette architecture est malheureusement courante dans les petites entreprises et les projets lances rapidement sans budget infrastructure. Elle peut fonctionner temporairement mais constitue une dette technique et un risque de securite majeurs.

---

## 5. Cout et qualite

### 5.1 Le piege du "moins cher"

Il est tentant de choisir l'infrastructure la moins couteuse a court terme. Cependant, une infrastructure sous-dimensionnee ou mal concue genere des couts caches importants :

| Cout cache | Description |
|---|---|
| **Temps d'indisponibilite** | Perte de revenus, atteinte a la reputation, penalites contractuelles |
| **Incidents de securite** | Cout moyen d'une violation de donnees : plusieurs millions d'euros (etude IBM) |
| **Dette technique** | Plus l'infrastructure est negligee, plus sa mise a niveau coutera cher |
| **Temps d'intervention** | Sans monitoring ni automatisation, chaque incident mobilise des ingenieurs pendant des heures |

### 5.2 Trouver le bon equilibre

Le bon equilibre consiste a dimensionner l'infrastructure en fonction des besoins reels et des risques identifies :

- **Identifier les composants critiques** : tous les services n'ont pas besoin du meme niveau de disponibilite
- **Evaluer le cout de l'indisponibilite** : combien coute une heure de panne pour chaque service ?
- **Investir proportionnellement** : les composants critiques meritent de la redondance, les composants secondaires peuvent tolerer un niveau de risque plus eleve
- **Revoir regulierement** : les besoins evoluent, l'infrastructure doit suivre

> **Bonne pratique** : une infrastructure simple n'est pas necessairement moins chere a long terme. Le cout total de possession (TCO) doit inclure la maintenance, les incidents, la securite et l'evolution, pas seulement le cout d'achat initial.

---

## Pour aller plus loin

- [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html)
- [Microsoft Azure Architecture Center](https://learn.microsoft.com/en-us/azure/architecture/)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework)
- [Terraform -- Introduction a l'Infrastructure as Code](https://developer.hashicorp.com/terraform/intro)
- [The Twelve-Factor App](https://12factor.net/)
