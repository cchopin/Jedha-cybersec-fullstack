# Analyse et interprétation des besoins client

**Module** : traduire les besoins business en solutions techniques

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Distinguer les exigences fonctionnelles des exigences non-fonctionnelles
- Identifier les besoins implicites que le client ne formule pas spontanément
- Maîtriser le processus de mapping entre besoins business et solutions techniques
- Justifier chaque choix technique par un besoin business identifié
- Repérer les red flags dans un cahier des charges et poser les bonnes questions

---

## 1. Exigences fonctionnelles

### 1.1 Définition

Les exigences fonctionnelles décrivent **ce que le système doit faire**. Elles répondent aux questions : **qui** utilise le système, **quoi** (quelle action) et **pourquoi** (quel objectif business).

Une exigence fonctionnelle bien formulée est :

- **Spécifique** : elle décrit un comportement précis et observable
- **Vérifiable** : on peut tester si elle est satisfaite ou non
- **Liée à un acteur** : elle identifie qui interagit avec le système

### 1.2 Exemples d'exigences fonctionnelles

| Exigence | Qui | Quoi | Pourquoi |
|---|---|---|---|
| Reset de mot de passe en self-service | Utilisateur final | Réinitialiser son mot de passe via un lien email | Réduire les tickets au support IT |
| Intégration paiement Stripe | Client e-commerce | Payer par carte bancaire lors du checkout | Permettre les ventes en ligne |
| Export CSV des rapports | Manager | Télécharger les données de reporting au format CSV | Analyser les données dans Excel |
| Authentification SSO | Employé | Se connecter avec ses identifiants Active Directory | Simplifier l'accès aux outils internes |
| Notification par email | Système | Envoyer un email lors d'un événement critique | Informer les équipes en temps réel |

### 1.3 Collecte des exigences fonctionnelles

La collecte s'effectue par :

- **Entretiens avec les parties prenantes** : utilisateurs finaux, managers, équipe IT
- **Observation des processus existants** : comment le travail est réalisé aujourd'hui
- **Analyse des systèmes existants** : quelles fonctionnalités sont déjà en place et doivent être conservées
- **User stories** : "En tant que [rôle], je souhaite [action] afin de [bénéfice]"

> **Bonne pratique** : toujours valider les exigences fonctionnelles avec les utilisateurs finaux, pas uniquement avec le management. Les besoins réels du terrain diffèrent souvent de la vision stratégique.

---

## 2. Exigences non-fonctionnelles

### 2.1 Définition

Les exigences non-fonctionnelles décrivent **comment le système doit performer**. Elles ne portent pas sur les fonctionnalités elles-mêmes mais sur les qualités du système : performance, sécurité, disponibilité, conformité.

### 2.2 Catégories et exemples

| Catégorie | Exigence | Métrique |
|---|---|---|
| **Disponibilité** | Le système doit être disponible 99.9% du temps | SLA 99.9%, soit moins de 8.76 heures d'indisponibilité par an |
| **Performance** | Le temps de réponse des pages doit être inférieur à 200 ms | P95 latence < 200 ms |
| **Capacité** | Le système doit supporter 10 000 utilisateurs concurrents | Tests de charge validant 10 000 sessions simultanées |
| **Sécurité** | Les données personnelles doivent être chiffrées au repos | Chiffrement AES-256 pour les bases de données |
| **Conformité** | Le système doit être conforme au RGPD | Audit de conformité, DPO nommé, registre des traitements |
| **Sauvegarde** | Les données doivent être sauvegardées quotidiennement | RPO < 24 heures, sauvegardes testées mensuellement |
| **Accessibilité** | L'interface doit être conforme WCAG 2.1 AA | Audit d'accessibilité automatisé et manuel |

### 2.3 Le problème des exigences non-fonctionnelles

Les exigences non-fonctionnelles sont **souvent oubliées par les clients**. Lors des discussions initiales, le client se concentre naturellement sur ce que le système doit faire (les fonctionnalités) et néglige les contraintes de qualité.

C'est au professionnel technique de poser les questions qui permettent de révéler ces exigences :

| Question | Exigence révélée |
|---|---|
| "Combien de temps pouvez-vous tolérer une panne ?" | Disponibilité, RTO |
| "Combien de données pouvez-vous vous permettre de perdre ?" | RPO, stratégie de sauvegarde |
| "Combien d'utilisateurs simultanément ?" | Capacité, scalabilité |
| "Y a-t-il des contraintes réglementaires ?" | Conformité (RGPD, PCI-DSS, HDS, etc.) |
| "Quels sont vos délais de mise en production ?" | Processus CI/CD, environnements de test |

> **À noter** : les exigences non-fonctionnelles ont un impact majeur sur l'architecture et le coût de la solution. Un système qui doit supporter 100 utilisateurs et un système qui doit en supporter 100 000 ne se conçoivent pas de la même manière, même si les fonctionnalités sont identiques.

---

## 3. Mapping besoins business vers solutions techniques

### 3.1 Le processus en trois étapes

Le passage du besoin business à la solution technique suit un processus structuré en trois étapes :

```
Étape 1                    Étape 2                       Étape 3
Comprendre l'objectif  ->  Évaluer contraintes    ->  Sélectionner les
business                   et opportunités              technologies
```

### 3.2 Étape 1 : comprendre l'objectif business

Avant de proposer une solution technique, il faut comprendre **le problème que le client cherche à résoudre**. La technologie n'est qu'un moyen, pas une fin.

| Besoin formulé par le client | Objectif business réel |
|---|---|
| "On veut un site web" | Vendre des produits en ligne et augmenter le chiffre d'affaires |
| "On veut migrer dans le cloud" | Réduire les coûts d'infrastructure et gagner en flexibilité |
| "On veut un tableau de bord" | Prendre des décisions basées sur les données en temps réel |
| "On veut sécuriser notre SI" | Protéger les données clients et être conforme aux obligations légales |

### 3.3 Étape 2 : évaluer les contraintes et les opportunités

| Type de contrainte | Exemples |
|---|---|
| **Budget** | Enveloppe fixe, préférence CAPEX ou OPEX, coût récurrent maximal |
| **Délais** | Date de mise en production imposée, jalons intermédiaires |
| **Équipe** | Compétences disponibles en interne, capacité à opérer la solution |
| **Existant** | Systèmes en place avec lesquels la nouvelle solution doit s'intégrer |
| **Réglementaire** | Localisation des données, certifications requises, audits |

### 3.4 Étape 3 : sélectionner les technologies

La sélection technologique doit être **justifiée par les besoins identifiés** aux étapes précédentes.

Exemple de mapping complet :

| Besoin business | Exigence technique | Solution retenue | Justification |
|---|---|---|---|
| Vendre en ligne 24/7 | Disponibilité 99.9% | Load balancer + auto-scaling AWS | Redondance multi-AZ, basculement automatique |
| Accepter les paiements | Intégration paiement sécurisé | API Stripe | Conforme PCI-DSS, SDK bien documenté, pas de gestion de cartes en interne |
| Protéger les données clients | Chiffrement + conformité RGPD | RDS chiffré + politique de rétention | Chiffrement AES-256 au repos, logs d'accès audités |
| Gérer les pics de trafic (soldes) | Support de 10x la charge normale | Auto-scaling + CDN CloudFront | Ajout automatique de capacité, contenu statique en cache |
| Équipe de 3 devs sans ops | Solution facile à opérer | Services managés AWS (RDS, ECS Fargate) | Pas de gestion de serveurs, mises à jour automatiques |

> **Bonne pratique** : chaque choix technique doit pouvoir être justifié par un besoin business. Si une technologie est dans l'architecture sans justification claire, elle n'a probablement pas sa place.

---

## 4. Red flags dans un cahier des charges

### 4.1 Identifier les signaux d'alerte

Certains éléments dans les demandes client doivent déclencher une vigilance particulière :

| Red flag | Exemple | Problème |
|---|---|---|
| **Exigences vagues** | "Le système doit être rapide" | Impossible à mesurer et à vérifier. Rapide par rapport à quoi ? |
| **Attentes irréalistes** | "Le système doit avoir 100% de disponibilité" | Le 100% est physiquement impossible. Même AWS ne le garantit pas |
| **Solutions techniques imposées** | "Il faut utiliser MongoDB 3.6 spécifiquement" | Pourquoi cette version précise ? Y a-t-il une raison technique ou est-ce une préférence personnelle ? |
| **Sécurité remise à plus tard** | "On sécurisera après le lancement" | La sécurité est exponentiellement plus coûteuse à ajouter après coup |
| **Absence de budget pour les tests** | "On testera en production" | Garantie d'incidents en production et de dégradation de la confiance des utilisateurs |

### 4.2 Questions à poser pour chaque red flag

**Face à une exigence vague** :

- "Quand vous dites rapide, quel temps de réponse serait acceptable ?"
- "Pouvez-vous donner un exemple de ce qui est trop lent aujourd'hui ?"
- "Quels sont les scénarios les plus critiques en termes de performance ?"

**Face à des attentes irréalistes** :

- "Quel est le coût d'une heure d'indisponibilité pour votre activité ?"
- "Quel niveau de disponibilité est réellement nécessaire pour chaque composant ?"
- "Êtes-vous prêt à investir dans l'infrastructure nécessaire pour atteindre ce niveau ?"

**Face à une solution technique imposée** :

- "Quelle est la raison de ce choix spécifique ?"
- "Y a-t-il des contraintes de compatibilité avec un système existant ?"
- "Êtes-vous ouvert à des alternatives si elles répondent mieux au besoin ?"

**Face à la sécurité remise à plus tard** :

- "Quelles données sensibles le système va-t-il manipuler ?"
- "Quelles sont vos obligations légales en matière de protection des données ?"
- "Quel serait l'impact d'une violation de données sur votre activité et votre réputation ?"

---

## 5. Principe directeur : demander tôt et souvent

### 5.1 Ne jamais supposer

Le piège le plus courant dans l'analyse des besoins est de **supposer** ce que le client veut au lieu de lui demander. Les suppositions mènent à :

- Des fonctionnalités développées mais jamais utilisées
- Des contraintes techniques découvertes trop tard
- Des dépassements de budget et de délais
- Des livraisons qui ne correspondent pas aux attentes

### 5.2 Bonnes pratiques de communication

| Pratique | Description |
|---|---|
| **Réunions régulières** | Points d'avancement hebdomadaires avec le client, pas seulement au début et à la fin |
| **Prototypage rapide** | Montrer un prototype fonctionnel tôt pour valider la direction |
| **Documentation partagée** | Cahier des charges vivant, accessible et modifiable par toutes les parties |
| **Reformulation** | Reformuler les demandes du client pour s'assurer de la bonne compréhension : "Si je comprends bien, vous avez besoin de..." |
| **Questions ouvertes** | Privilégier les questions ouvertes ("Comment imaginez-vous...") aux questions fermées ("Voulez-vous un bouton ici ?") |

> **Bonne pratique** : un besoin mal compris au début du projet coûte 10x plus cher à corriger en développement et 100x plus cher à corriger en production. Investir du temps dans l'analyse des besoins est le meilleur investissement possible.

---

## Pour aller plus loin

- [IEEE 830 -- Recommended Practice for Software Requirements Specifications](https://standards.ieee.org/ieee/830/1222/)
- [RGPD -- Texte officiel (CNIL)](https://www.cnil.fr/fr/rgpd-de-quoi-parle-t-on)
- [AWS Well-Architected Framework -- Pillar: Operational Excellence](https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/welcome.html)
- [The Twelve-Factor App -- Configuration](https://12factor.net/config)
- [OWASP -- Security by Design Principles](https://owasp.org/www-project-developer-guide/draft/design/web_app_checklist/)
