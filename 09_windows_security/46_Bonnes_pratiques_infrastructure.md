# Bonnes pratiques d'infrastructure

**Module** : securiser, surveiller, automatiser et documenter une infrastructure

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Appliquer les principes de securite par l'isolation (RBAC, VLANs, firewalls)
- Mettre en place un monitoring efficace en distinguant le signal du bruit
- Comprendre l'automatisation de l'infrastructure (IaC, CI/CD, auto-scaling)
- Documenter une infrastructure de maniere structuree et maintenable
- Gerer les passations de responsabilite sans perte de connaissance

---

## 1. Securite par l'isolation

### 1.1 RBAC (Role-Based Access Control)

Le **RBAC** (controle d'acces base sur les roles) est un modele de gestion des permissions ou les droits d'acces sont attribues a des **roles** plutot qu'a des utilisateurs individuels. Chaque utilisateur se voit assigner un ou plusieurs roles, et herite des permissions associees.

| Principe | Description |
|---|---|
| **Permissions minimales** | Chaque role ne dispose que des permissions strictement necessaires a l'accomplissement de ses taches |
| **Separation des roles** | Un administrateur de base de donnees n'a pas besoin d'acces aux serveurs web, et inversement |
| **Revision reguliere** | Les attributions de roles doivent etre revues periodiquement pour detecter les derives (accumulation de droits) |

Exemple de matrice RBAC pour une application web :

| Role | Serveurs web | Base de donnees | Logs | Firewall | DNS |
|---|---|---|---|---|---|
| **Developpeur** | Lecture logs | Lecture (env. dev uniquement) | Lecture | Aucun | Aucun |
| **DBA** | Aucun | Lecture/Ecriture (tous env.) | Lecture | Aucun | Aucun |
| **Ops/SRE** | Administration | Lecture | Lecture/Ecriture | Administration | Administration |
| **RSSI** | Audit | Audit | Lecture/Ecriture | Audit | Audit |
| **Manager** | Aucun | Aucun | Lecture (dashboards) | Aucun | Aucun |

> **Bonne pratique** : lorsqu'un employe change de poste ou quitte l'entreprise, ses roles doivent etre immediatement mis a jour ou revoques. L'accumulation de droits au fil des changements de poste (privilege creep) est l'un des vecteurs les plus courants de violation du principe du moindre privilege.

### 1.2 VLANs (Virtual LANs)

Les **VLANs** permettent de segmenter un reseau physique en plusieurs reseaux logiques isoles. Le trafic entre deux VLANs ne peut transiter que via un routeur ou un firewall, ce qui permet de controler finement les flux.

Exemple de segmentation par VLANs :

| VLAN | Nom | Contenu | Acces autorise vers |
|---|---|---|---|
| VLAN 10 | Production Web | Serveurs web frontaux | VLAN 20 (base de donnees), Internet |
| VLAN 20 | Production DB | Serveurs de base de donnees | Aucun acces sortant, repond uniquement a VLAN 10 |
| VLAN 30 | Developpement | Environnements de dev/test | Internet (pour les mises a jour), VLAN 40 |
| VLAN 40 | Management | Outils de monitoring, bastion SSH | Tous les VLANs (en lecture/monitoring) |
| VLAN 50 | Utilisateurs | Postes de travail des employes | Internet, VLAN 30 (pour les devs) |

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
    |--- VLAN 20 [Production DB] --- bases de donnees
    |
    |--- VLAN 30 [Developpement] --- serveurs dev/test
    |
    |--- VLAN 40 [Management] --- monitoring, bastion
    |
    |--- VLAN 50 [Utilisateurs] --- postes de travail
```

> **A noter** : sans segmentation VLAN, un attaquant qui compromet un poste utilisateur se retrouve sur le meme segment reseau que les bases de donnees de production. La segmentation limite considerablement les possibilites de mouvement lateral.

### 1.3 Firewalls

Les **firewalls** filtrent le trafic reseau en fonction de regles explicites. Le principe fondamental est le **deny by default** : tout ce qui n'est pas explicitement autorise est bloque.

| Type de firewall | Description | Cas d'usage |
|---|---|---|
| **Firewall reseau** (L3/L4) | Filtre par adresse IP, port et protocole | Controle du trafic entre VLANs, entre le reseau interne et Internet |
| **WAF** (Web Application Firewall) | Filtre au niveau applicatif (L7), analyse le contenu HTTP | Protection contre les injections SQL, XSS, CSRF et autres attaques web |
| **Firewall hote** | Firewall logiciel sur chaque serveur (iptables, Windows Firewall) | Defense en profondeur, meme au sein d'un VLAN |

Regles de bonne configuration :

| Regle | Description |
|---|---|
| **Listes d'autorisation explicites** | Definir les flux autorises par source, destination, port et protocole |
| **Ports et protocoles limites** | N'ouvrir que les ports strictement necessaires (ex. 443 pour HTTPS, pas "tous les ports") |
| **Logging** | Activer les logs de trafic bloque et autorise pour analyse ulterieure |
| **Revision reguliere** | Les regles obsoletes (ancien serveur decommissionne, ancien prestataire) doivent etre supprimees |

> **Bonne pratique** : une regle firewall "allow any any" (autoriser tout le trafic de n'importe quelle source vers n'importe quelle destination) annule l'utilite du firewall. Chaque regle doit etre specifique, documentee et justifiee.

---

## 2. Monitoring et alerting

### 2.1 Signal vs bruit

Le monitoring est essentiel pour detecter les problemes avant qu'ils n'impactent les utilisateurs. Cependant, un monitoring mal configure genere plus de bruit que de signal, ce qui conduit a la **fatigue d'alertes** : les equipes finissent par ignorer les notifications.

### 2.2 Signaux importants (a alerter)

| Signal | Description | Action attendue |
|---|---|---|
| **Panne de service** | Un service critique est down ou ne repond plus | Intervention immediate, declenchement du runbook |
| **Breche de securite** | Connexion suspecte, tentative d'intrusion detectee, escalade de privileges | Investigation immediate, isolation du systeme si necessaire |
| **Degradation de performance** | Temps de reponse > seuil defini pendant > 5 minutes | Diagnostic, scaling si necessaire |
| **Stockage critique** | Espace disque < 10% restant | Extension du stockage, nettoyage des fichiers temporaires |
| **Echec de sauvegarde** | Une sauvegarde planifiee a echoue | Relance manuelle, verification de l'integrite des sauvegardes precedentes |
| **Certificat SSL expirant** | Un certificat expire dans < 7 jours | Renouvellement du certificat |

### 2.3 Bruit (a ne pas alerter)

| Signal | Pourquoi c'est du bruit | Meilleure approche |
|---|---|---|
| **Pic CPU temporaire** (< 2 min) | Normal lors du deploiement, du demarrage d'un service ou d'un traitement batch | Dashboard, pas d'alerte |
| **Pic memoire temporaire** | Le garbage collector ou le cache provoquent des variations normales | Dashboard, alerte uniquement si > 95% pendant > 10 min |
| **Micro-coupure reseau** (< 30 sec) | Les micro-coupures sont frequentes et se resolvent d'elles-memes | Log, pas d'alerte |
| **Utilisation elevee pendant la maintenance** | La maintenance planifiee genere de la charge, c'est attendu | Desactiver les alertes pendant la fenetre de maintenance |

### 2.4 Reduire la fatigue d'alertes

| Action | Description |
|---|---|
| **Ajuster les seuils** | Un seuil CPU a 70% genere du bruit. Un seuil a 90% pendant 5 minutes est plus pertinent |
| **Desactiver les alertes non actionnables** | Si personne ne fait rien quand l'alerte se declenche, elle ne sert a rien |
| **Grouper les alertes** | Eviter d'envoyer 50 alertes pour un seul incident. Grouper par service ou par incident |
| **Hierarchiser** | Distinguer les alertes critiques (notification immediate) des avertissements (revue lors du standup) |
| **Documenter les runbooks** | Chaque alerte doit avoir une procedure de reponse documentee. Si la procedure n'existe pas, l'alerte est prematuree |

> **Bonne pratique** : si une alerte se declenche plus de 3 fois par semaine sans action corrective, c'est soit que le seuil est mal calibre, soit que le probleme sous-jacent doit etre corrige definitivement.

---

## 3. Automatisation

### 3.1 Infrastructure as Code (IaC)

L'**IaC** consiste a definir et gerer l'infrastructure via des fichiers de configuration versionnes plutot que par des operations manuelles. On distingue deux categories d'outils :

**Outils de provisioning** (creation de l'infrastructure) :

| Outil | Editeur | Approche |
|---|---|---|
| **Terraform** | HashiCorp | Declaratif, multi-cloud, etat gere dans un fichier tfstate |
| **CloudFormation** | AWS | Declaratif, specifique AWS, integre nativement |
| **Pulumi** | Pulumi | Declaratif, multi-cloud, utilise des langages de programmation (Python, TypeScript, Go) |

**Outils de configuration** (configuration des serveurs) :

| Outil | Editeur | Approche |
|---|---|---|
| **Ansible** | Red Hat | Declaratif, agentless (connexion SSH), playbooks YAML |
| **Puppet** | Perforce | Declaratif, agent installe sur chaque serveur, manifestes Ruby |
| **Chef** | Progress | Imperatif, agent installe sur chaque serveur, recettes Ruby |

Exemple de workflow IaC typique :

```
1. Le developpeur ecrit le code Terraform (fichier .tf)
2. Il soumet une Pull Request sur Git
3. La PR est revue par un pair
4. Apres approbation, un pipeline CI/CD execute "terraform plan"
5. Le plan est valide (pas de destruction inattendue)
6. "terraform apply" est execute : l'infrastructure est creee/modifiee
7. L'etat de l'infrastructure est stocke dans le fichier tfstate
```

### 3.2 Deploiements automatises et CI/CD

| Concept | Description |
|---|---|
| **CI** (Continuous Integration) | Chaque modification de code est automatiquement testee (tests unitaires, integration, securite) |
| **CD** (Continuous Deployment) | Les modifications validees sont automatiquement deployees en production |
| **Auto-scaling** | Le nombre de serveurs s'ajuste automatiquement en fonction de la charge |
| **Blue/Green deployment** | Deux environnements identiques : le nouveau code est deploye sur l'un, puis le trafic est bascule |
| **Canary deployment** | Le nouveau code est deploye sur un petit pourcentage de serveurs, puis progressivement etendu |

### 3.3 Automatiser avec discernement

L'automatisation est un investissement : elle a un cout initial (temps de developpement, tests, documentation) qui doit etre compense par les gains futurs.

| Automatiser | Ne pas automatiser (dans un premier temps) |
|---|---|
| Taches repetitives executees quotidiennement | Taches ponctuelles executees une fois par an |
| Deployments en production | Decisions d'architecture qui necessitent un jugement humain |
| Tests de regression | Diagnostics complexes d'incidents uniques |
| Provisioning de serveurs | Negociations de contrats fournisseurs |
| Rotation des secrets et certificats | Choix strategiques d'investissement |

> **Bonne pratique** : commencer par automatiser les taches repetitives a **valeur claire** : les deploiements, les sauvegardes, le provisioning de serveurs. Une fois ces fondations en place, etendre progressivement l'automatisation aux taches moins frequentes.

---

## 4. Documentation et passation

### 4.1 Que documenter ?

| Element | Format recommande | Contenu |
|---|---|---|
| **Architecture** | Diagrammes (draw.io, Lucidchart, Mermaid) | Vue d'ensemble des composants, flux reseau, dependances entre services |
| **Infrastructure** | Scripts IaC (Terraform, Ansible) | La configuration de l'infrastructure EST la documentation (code = verite) |
| **Procedures operationnelles** | SOPs (Standard Operating Procedures) | Etapes detaillees pour les operations courantes (deploiement, rollback, incident) |
| **Credentials et acces** | Gestionnaire de secrets (Vault, AWS Secrets Manager, 1Password) | Jamais en clair dans un document ou un depot Git |
| **Decisions d'architecture** | ADR (Architecture Decision Records) | Pourquoi telle technologie a ete choisie, quelles alternatives ont ete ecartees |

### 4.2 Regles d'une bonne documentation

| Regle | Description |
|---|---|
| **Langage clair** | Eviter le jargon inutile. Un nouvel arrivant doit pouvoir comprendre sans contexte prealable |
| **Structuree et cherchable** | Organisation en sections, titres descriptifs, index. La documentation doit etre trouvable en < 30 secondes |
| **Mise a jour reguliere** | Documentation obsolete = documentation dangereuse. Integrer la mise a jour dans le processus de changement |
| **Versionnnee** | Utiliser Git pour la documentation, comme pour le code. Historique des modifications tracable |
| **Proche du code** | Privilegier la documentation dans le meme depot que le code (README, docs/) plutot que dans un wiki externe deconnecte |

### 4.3 Tester la documentation

La documentation doit etre testee comme le code :

| Methode | Description |
|---|---|
| **Test par un nouvel arrivant** | Demander a un nouveau membre de l'equipe de suivre une procedure et noter les points bloques |
| **Revue periodique** | Revue trimestrielle par l'equipe pour identifier les sections obsoletes |
| **Exercices de reprise** | Suivre les procedures de PRA pour verifier qu'elles sont completes et a jour |
| **Automatisation** | Quand c'est possible, remplacer la documentation par de l'automatisation (un script est toujours a jour, un document rarement) |

> **A noter** : la meilleure documentation est celle qui n'a pas besoin d'exister car le systeme est auto-explicatif (nommage clair, IaC, pipelines CI/CD). La documentation doit couvrir le **pourquoi**, pas le **comment** quand celui-ci est evident.

### 4.4 Passation de responsabilite

Lorsqu'un membre de l'equipe quitte le projet ou change de poste, une passation structuree est essentielle pour eviter la perte de connaissance.

| Etape | Description |
|---|---|
| **Reunions de transition** | Sessions de transfert de connaissance entre la personne sortante et la personne entrante. Minimum 3 sessions sur des sujets distincts |
| **Documentation des acces** | Inventaire complet de tous les acces (serveurs, services cloud, outils SaaS, VPN, certificats) |
| **Revocation des acces** | Revocation immediate de tous les acces de la personne sortante le jour de son depart. Pas de delai |
| **Assignation explicite de propriete** | Chaque systeme, service et responsabilite doit avoir un proprietaire clairement identifie. Pas de zone grise |
| **Periode de recouvrement** | Idealement, une periode ou les deux personnes travaillent en parallele pour faciliter le transfert |

> **Bonne pratique** : tester la documentation regulierement en simulant le depart d'un membre cle de l'equipe. Si les operations s'arretent quand une seule personne est absente, c'est le signe d'un "bus factor" de 1, ce qui constitue un risque majeur pour l'organisation.

---

## Pour aller plus loin

- [HashiCorp -- Introduction a Terraform](https://developer.hashicorp.com/terraform/intro)
- [Ansible -- Documentation officielle](https://docs.ansible.com/ansible/latest/index.html)
- [Google SRE Book -- Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [NIST -- Security and Privacy Controls for Information Systems](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Atlassian -- Incident Management Best Practices](https://www.atlassian.com/incident-management/best-practices)
- [Architecture Decision Records](https://adr.github.io/)
