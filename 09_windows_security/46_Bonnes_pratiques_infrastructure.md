# Bonnes pratiques d'infrastructure

**Module** : sécuriser, surveiller, automatiser et documenter une infrastructure

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Appliquer les principes de sécurité par l'isolation (RBAC, VLANs, firewalls)
- Mettre en place un monitoring efficace en distinguant le signal du bruit
- Comprendre l'automatisation de l'infrastructure (IaC, CI/CD, auto-scaling)
- Documenter une infrastructure de manière structurée et maintenable
- Gérer les passations de responsabilité sans perte de connaissance

---

## 1. Sécurité par l'isolation

### 1.1 RBAC (Role-Based Access Control)

Le **RBAC** (contrôle d'accès basé sur les rôles) est un modèle de gestion des permissions où les droits d'accès sont attribués à des **rôles** plutôt qu'à des utilisateurs individuels. Chaque utilisateur se voit assigner un ou plusieurs rôles, et hérite des permissions associées.

| Principe | Description |
|---|---|
| **Permissions minimales** | Chaque rôle ne dispose que des permissions strictement nécessaires à l'accomplissement de ses tâches |
| **Séparation des rôles** | Un administrateur de base de données n'a pas besoin d'accès aux serveurs web, et inversement |
| **Révision régulière** | Les attributions de rôles doivent être revues périodiquement pour détecter les dérives (accumulation de droits) |

Exemple de matrice RBAC pour une application web :

| Rôle | Serveurs web | Base de données | Logs | Firewall | DNS |
|---|---|---|---|---|---|
| **Développeur** | Lecture logs | Lecture (env. dev uniquement) | Lecture | Aucun | Aucun |
| **DBA** | Aucun | Lecture/Écriture (tous env.) | Lecture | Aucun | Aucun |
| **Ops/SRE** | Administration | Lecture | Lecture/Écriture | Administration | Administration |
| **RSSI** | Audit | Audit | Lecture/Écriture | Audit | Audit |
| **Manager** | Aucun | Aucun | Lecture (dashboards) | Aucun | Aucun |

> **Bonne pratique** : lorsqu'un employé change de poste ou quitte l'entreprise, ses rôles doivent être immédiatement mis à jour ou révoqués. L'accumulation de droits au fil des changements de poste (privilege creep) est l'un des vecteurs les plus courants de violation du principe du moindre privilège.

### 1.2 VLANs (Virtual LANs)

Les **VLANs** permettent de segmenter un réseau physique en plusieurs réseaux logiques isolés. Le trafic entre deux VLANs ne peut transiter que via un routeur ou un firewall, ce qui permet de contrôler finement les flux.

Exemple de segmentation par VLANs :

| VLAN | Nom | Contenu | Accès autorisé vers |
|---|---|---|---|
| VLAN 10 | Production Web | Serveurs web frontaux | VLAN 20 (base de données), Internet |
| VLAN 20 | Production DB | Serveurs de base de données | Aucun accès sortant, répond uniquement à VLAN 10 |
| VLAN 30 | Développement | Environnements de dev/test | Internet (pour les mises à jour), VLAN 40 |
| VLAN 40 | Management | Outils de monitoring, bastion SSH | Tous les VLANs (en lecture/monitoring) |
| VLAN 50 | Utilisateurs | Postes de travail des employés | Internet, VLAN 30 (pour les devs) |

```
Segmentation VLAN typique
=========================

Internet
    |
[Firewall]
    |
    |--- VLAN 10 [Production Web] --- serveurs web
    |        |
    |        v
    |--- VLAN 20 [Production DB] --- bases de données
    |
    |--- VLAN 30 [Développement] --- serveurs dev/test
    |
    |--- VLAN 40 [Management] --- monitoring, bastion
    |
    |--- VLAN 50 [Utilisateurs] --- postes de travail
```

> **À noter** : sans segmentation VLAN, un attaquant qui compromet un poste utilisateur se retrouve sur le même segment réseau que les bases de données de production. La segmentation limite considérablement les possibilités de mouvement latéral.

### 1.3 Firewalls

Les **firewalls** filtrent le trafic réseau en fonction de règles explicites. Le principe fondamental est le **deny by default** : tout ce qui n'est pas explicitement autorisé est bloqué.

| Type de firewall | Description | Cas d'usage |
|---|---|---|
| **Firewall réseau** (L3/L4) | Filtre par adresse IP, port et protocole | Contrôle du trafic entre VLANs, entre le réseau interne et Internet |
| **WAF** (Web Application Firewall) | Filtre au niveau applicatif (L7), analyse le contenu HTTP | Protection contre les injections SQL, XSS, CSRF et autres attaques web |
| **Firewall hôte** | Firewall logiciel sur chaque serveur (iptables, Windows Firewall) | Défense en profondeur, même au sein d'un VLAN |

Règles de bonne configuration :

| Règle | Description |
|---|---|
| **Listes d'autorisation explicites** | Définir les flux autorisés par source, destination, port et protocole |
| **Ports et protocoles limités** | N'ouvrir que les ports strictement nécessaires (ex. 443 pour HTTPS, pas "tous les ports") |
| **Logging** | Activer les logs de trafic bloqué et autorisé pour analyse ultérieure |
| **Révision régulière** | Les règles obsolètes (ancien serveur décommissionné, ancien prestataire) doivent être supprimées |

> **Bonne pratique** : une règle firewall "allow any any" (autoriser tout le trafic de n'importe quelle source vers n'importe quelle destination) annule l'utilité du firewall. Chaque règle doit être spécifique, documentée et justifiée.

---

## 2. Monitoring et alerting

### 2.1 Signal vs bruit

Le monitoring est essentiel pour détecter les problèmes avant qu'ils n'impactent les utilisateurs. Cependant, un monitoring mal configuré génère plus de bruit que de signal, ce qui conduit à la **fatigue d'alertes** : les équipes finissent par ignorer les notifications.

### 2.2 Signaux importants (à alerter)

| Signal | Description | Action attendue |
|---|---|---|
| **Panne de service** | Un service critique est down ou ne répond plus | Intervention immédiate, déclenchement du runbook |
| **Brèche de sécurité** | Connexion suspecte, tentative d'intrusion détectée, escalade de privilèges | Investigation immédiate, isolation du système si nécessaire |
| **Dégradation de performance** | Temps de réponse > seuil défini pendant > 5 minutes | Diagnostic, scaling si nécessaire |
| **Stockage critique** | Espace disque < 10% restant | Extension du stockage, nettoyage des fichiers temporaires |
| **Échec de sauvegarde** | Une sauvegarde planifiée a échoué | Relance manuelle, vérification de l'intégrité des sauvegardes précédentes |
| **Certificat SSL expirant** | Un certificat expire dans < 7 jours | Renouvellement du certificat |

### 2.3 Bruit (à ne pas alerter)

| Signal | Pourquoi c'est du bruit | Meilleure approche |
|---|---|---|
| **Pic CPU temporaire** (< 2 min) | Normal lors du déploiement, du démarrage d'un service ou d'un traitement batch | Dashboard, pas d'alerte |
| **Pic mémoire temporaire** | Le garbage collector ou le cache provoquent des variations normales | Dashboard, alerte uniquement si > 95% pendant > 10 min |
| **Micro-coupure réseau** (< 30 sec) | Les micro-coupures sont fréquentes et se résolvent d'elles-mêmes | Log, pas d'alerte |
| **Utilisation élevée pendant la maintenance** | La maintenance planifiée génère de la charge, c'est attendu | Désactiver les alertes pendant la fenêtre de maintenance |

### 2.4 Réduire la fatigue d'alertes

| Action | Description |
|---|---|
| **Ajuster les seuils** | Un seuil CPU à 70% génère du bruit. Un seuil à 90% pendant 5 minutes est plus pertinent |
| **Désactiver les alertes non actionnables** | Si personne ne fait rien quand l'alerte se déclenche, elle ne sert à rien |
| **Grouper les alertes** | Éviter d'envoyer 50 alertes pour un seul incident. Grouper par service ou par incident |
| **Hiérarchiser** | Distinguer les alertes critiques (notification immédiate) des avertissements (revue lors du standup) |
| **Documenter les runbooks** | Chaque alerte doit avoir une procédure de réponse documentée. Si la procédure n'existe pas, l'alerte est prématurée |

> **Bonne pratique** : si une alerte se déclenche plus de 3 fois par semaine sans action corrective, c'est soit que le seuil est mal calibré, soit que le problème sous-jacent doit être corrigé définitivement.

---

## 3. Automatisation

### 3.1 Infrastructure as Code (IaC)

L'**IaC** consiste à définir et gérer l'infrastructure via des fichiers de configuration versionnés plutôt que par des opérations manuelles. On distingue deux catégories d'outils :

**Outils de provisioning** (création de l'infrastructure) :

| Outil | Éditeur | Approche |
|---|---|---|
| **Terraform** | HashiCorp | Déclaratif, multi-cloud, état géré dans un fichier tfstate |
| **CloudFormation** | AWS | Déclaratif, spécifique AWS, intégré nativement |
| **Pulumi** | Pulumi | Déclaratif, multi-cloud, utilise des langages de programmation (Python, TypeScript, Go) |

**Outils de configuration** (configuration des serveurs) :

| Outil | Éditeur | Approche |
|---|---|---|
| **Ansible** | Red Hat | Déclaratif, agentless (connexion SSH), playbooks YAML |
| **Puppet** | Perforce | Déclaratif, agent installé sur chaque serveur, manifestes Ruby |
| **Chef** | Progress | Impératif, agent installé sur chaque serveur, recettes Ruby |

Exemple de workflow IaC typique :

```
1. Le développeur écrit le code Terraform (fichier .tf)
2. Il soumet une Pull Request sur Git
3. La PR est revue par un pair
4. Après approbation, un pipeline CI/CD exécute "terraform plan"
5. Le plan est validé (pas de destruction inattendue)
6. "terraform apply" est exécuté : l'infrastructure est créée/modifiée
7. L'état de l'infrastructure est stocké dans le fichier tfstate
```

### 3.2 Déploiements automatisés et CI/CD

| Concept | Description |
|---|---|
| **CI** (Continuous Integration) | Chaque modification de code est automatiquement testée (tests unitaires, intégration, sécurité) |
| **CD** (Continuous Deployment) | Les modifications validées sont automatiquement déployées en production |
| **Auto-scaling** | Le nombre de serveurs s'ajuste automatiquement en fonction de la charge |
| **Blue/Green deployment** | Deux environnements identiques : le nouveau code est déployé sur l'un, puis le trafic est basculé |
| **Canary deployment** | Le nouveau code est déployé sur un petit pourcentage de serveurs, puis progressivement étendu |

### 3.3 Automatiser avec discernement

L'automatisation est un investissement : elle a un coût initial (temps de développement, tests, documentation) qui doit être compensé par les gains futurs.

| Automatiser | Ne pas automatiser (dans un premier temps) |
|---|---|
| Tâches répétitives exécutées quotidiennement | Tâches ponctuelles exécutées une fois par an |
| Deployments en production | Décisions d'architecture qui nécessitent un jugement humain |
| Tests de régression | Diagnostics complexes d'incidents uniques |
| Provisioning de serveurs | Négociations de contrats fournisseurs |
| Rotation des secrets et certificats | Choix stratégiques d'investissement |

> **Bonne pratique** : commencer par automatiser les tâches répétitives à **valeur claire** : les déploiements, les sauvegardes, le provisioning de serveurs. Une fois ces fondations en place, étendre progressivement l'automatisation aux tâches moins fréquentes.

---

## 4. Documentation et passation

### 4.1 Que documenter ?

| Élément | Format recommandé | Contenu |
|---|---|---|
| **Architecture** | Diagrammes (draw.io, Lucidchart, Mermaid) | Vue d'ensemble des composants, flux réseau, dépendances entre services |
| **Infrastructure** | Scripts IaC (Terraform, Ansible) | La configuration de l'infrastructure EST la documentation (code = vérité) |
| **Procédures opérationnelles** | SOPs (Standard Operating Procedures) | Étapes détaillées pour les opérations courantes (déploiement, rollback, incident) |
| **Credentials et accès** | Gestionnaire de secrets (Vault, AWS Secrets Manager, 1Password) | Jamais en clair dans un document ou un dépôt Git |
| **Décisions d'architecture** | ADR (Architecture Decision Records) | Pourquoi telle technologie a été choisie, quelles alternatives ont été écartées |

### 4.2 Règles d'une bonne documentation

| Règle | Description |
|---|---|
| **Langage clair** | Éviter le jargon inutile. Un nouvel arrivant doit pouvoir comprendre sans contexte préalable |
| **Structurée et cherchable** | Organisation en sections, titres descriptifs, index. La documentation doit être trouvable en < 30 secondes |
| **Mise à jour régulière** | Documentation obsolète = documentation dangereuse. Intégrer la mise à jour dans le processus de changement |
| **Versionnée** | Utiliser Git pour la documentation, comme pour le code. Historique des modifications traçable |
| **Proche du code** | Privilégier la documentation dans le même dépôt que le code (README, docs/) plutôt que dans un wiki externe déconnecté |

### 4.3 Tester la documentation

La documentation doit être testée comme le code :

| Méthode | Description |
|---|---|
| **Test par un nouvel arrivant** | Demander à un nouveau membre de l'équipe de suivre une procédure et noter les points bloqués |
| **Revue périodique** | Revue trimestrielle par l'équipe pour identifier les sections obsolètes |
| **Exercices de reprise** | Suivre les procédures de PRA pour vérifier qu'elles sont complètes et à jour |
| **Automatisation** | Quand c'est possible, remplacer la documentation par de l'automatisation (un script est toujours à jour, un document rarement) |

> **À noter** : la meilleure documentation est celle qui n'a pas besoin d'exister car le système est auto-explicatif (nommage clair, IaC, pipelines CI/CD). La documentation doit couvrir le **pourquoi**, pas le **comment** quand celui-ci est évident.

### 4.4 Passation de responsabilité

Lorsqu'un membre de l'équipe quitte le projet ou change de poste, une passation structurée est essentielle pour éviter la perte de connaissance.

| Étape | Description |
|---|---|
| **Réunions de transition** | Sessions de transfert de connaissance entre la personne sortante et la personne entrante. Minimum 3 sessions sur des sujets distincts |
| **Documentation des accès** | Inventaire complet de tous les accès (serveurs, services cloud, outils SaaS, VPN, certificats) |
| **Révocation des accès** | Révocation immédiate de tous les accès de la personne sortante le jour de son départ. Pas de délai |
| **Assignation explicite de propriété** | Chaque système, service et responsabilité doit avoir un propriétaire clairement identifié. Pas de zone grise |
| **Période de recouvrement** | Idéalement, une période où les deux personnes travaillent en parallèle pour faciliter le transfert |

> **Bonne pratique** : tester la documentation régulièrement en simulant le départ d'un membre clé de l'équipe. Si les opérations s'arrêtent quand une seule personne est absente, c'est le signe d'un "bus factor" de 1, ce qui constitue un risque majeur pour l'organisation.

---

## Pour aller plus loin

- [HashiCorp -- Introduction à Terraform](https://developer.hashicorp.com/terraform/intro)
- [Ansible -- Documentation officielle](https://docs.ansible.com/ansible/latest/index.html)
- [Google SRE Book -- Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [NIST -- Security and Privacy Controls for Information Systems](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Atlassian -- Incident Management Best Practices](https://www.atlassian.com/incident-management/best-practices)
- [Architecture Decision Records](https://adr.github.io/)
