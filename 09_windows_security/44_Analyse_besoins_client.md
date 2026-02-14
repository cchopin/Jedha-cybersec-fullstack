# Analyse et interpretation des besoins client

**Module** : traduire les besoins business en solutions techniques

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Distinguer les exigences fonctionnelles des exigences non-fonctionnelles
- Identifier les besoins implicites que le client ne formule pas spontanement
- Maitriser le processus de mapping entre besoins business et solutions techniques
- Justifier chaque choix technique par un besoin business identifie
- Reperer les red flags dans un cahier des charges et poser les bonnes questions

---

## 1. Exigences fonctionnelles

### 1.1 Definition

Les exigences fonctionnelles decrivent **ce que le systeme doit faire**. Elles repondent aux questions : **qui** utilise le systeme, **quoi** (quelle action) et **pourquoi** (quel objectif business).

Une exigence fonctionnelle bien formulee est :

- **Specifique** : elle decrit un comportement precis et observable
- **Verifiable** : on peut tester si elle est satisfaite ou non
- **Liee a un acteur** : elle identifie qui interagit avec le systeme

### 1.2 Exemples d'exigences fonctionnelles

| Exigence | Qui | Quoi | Pourquoi |
|---|---|---|---|
| Reset de mot de passe en self-service | Utilisateur final | Reinitialiser son mot de passe via un lien email | Reduire les tickets au support IT |
| Integration paiement Stripe | Client e-commerce | Payer par carte bancaire lors du checkout | Permettre les ventes en ligne |
| Export CSV des rapports | Manager | Telecharger les donnees de reporting au format CSV | Analyser les donnees dans Excel |
| Authentification SSO | Employe | Se connecter avec ses identifiants Active Directory | Simplifier l'acces aux outils internes |
| Notification par email | Systeme | Envoyer un email lors d'un evenement critique | Informer les equipes en temps reel |

### 1.3 Collecte des exigences fonctionnelles

La collecte s'effectue par :

- **Entretiens avec les parties prenantes** : utilisateurs finaux, managers, equipe IT
- **Observation des processus existants** : comment le travail est realise aujourd'hui
- **Analyse des systemes existants** : quelles fonctionnalites sont deja en place et doivent etre conservees
- **User stories** : "En tant que [role], je souhaite [action] afin de [benefice]"

> **Bonne pratique** : toujours valider les exigences fonctionnelles avec les utilisateurs finaux, pas uniquement avec le management. Les besoins reels du terrain different souvent de la vision strategique.

---

## 2. Exigences non-fonctionnelles

### 2.1 Definition

Les exigences non-fonctionnelles decrivent **comment le systeme doit performer**. Elles ne portent pas sur les fonctionnalites elles-memes mais sur les qualites du systeme : performance, securite, disponibilite, conformite.

### 2.2 Categories et exemples

| Categorie | Exigence | Metrique |
|---|---|---|
| **Disponibilite** | Le systeme doit etre disponible 99.9% du temps | SLA 99.9%, soit moins de 8.76 heures d'indisponibilite par an |
| **Performance** | Le temps de reponse des pages doit etre inferieur a 200 ms | P95 latence < 200 ms |
| **Capacite** | Le systeme doit supporter 10 000 utilisateurs concurrents | Tests de charge validant 10 000 sessions simultanees |
| **Securite** | Les donnees personnelles doivent etre chiffrees au repos | Chiffrement AES-256 pour les bases de donnees |
| **Conformite** | Le systeme doit etre conforme au RGPD | Audit de conformite, DPO nomme, registre des traitements |
| **Sauvegarde** | Les donnees doivent etre sauvegardees quotidiennement | RPO < 24 heures, sauvegardes testees mensuellement |
| **Accessibilite** | L'interface doit etre conforme WCAG 2.1 AA | Audit d'accessibilite automatise et manuel |

### 2.3 Le probleme des exigences non-fonctionnelles

Les exigences non-fonctionnelles sont **souvent oubliees par les clients**. Lors des discussions initiales, le client se concentre naturellement sur ce que le systeme doit faire (les fonctionnalites) et neglige les contraintes de qualite.

C'est au professionnel technique de poser les questions qui permettent de reveler ces exigences :

| Question | Exigence revelee |
|---|---|
| "Combien de temps pouvez-vous tolerer une panne ?" | Disponibilite, RTO |
| "Combien de donnees pouvez-vous vous permettre de perdre ?" | RPO, strategie de sauvegarde |
| "Combien d'utilisateurs simultanement ?" | Capacite, scalabilite |
| "Y a-t-il des contraintes reglementaires ?" | Conformite (RGPD, PCI-DSS, HDS, etc.) |
| "Quels sont vos delais de mise en production ?" | Processus CI/CD, environnements de test |

> **A noter** : les exigences non-fonctionnelles ont un impact majeur sur l'architecture et le cout de la solution. Un systeme qui doit supporter 100 utilisateurs et un systeme qui doit en supporter 100 000 ne se concoivent pas de la meme maniere, meme si les fonctionnalites sont identiques.

---

## 3. Mapping besoins business vers solutions techniques

### 3.1 Le processus en trois etapes

Le passage du besoin business a la solution technique suit un processus structure en trois etapes :

```
Etape 1                    Etape 2                       Etape 3
Comprendre l'objectif  ->  Evaluer contraintes    ->  Selectionner les
business                   et opportunites              technologies
```

### 3.2 Etape 1 : comprendre l'objectif business

Avant de proposer une solution technique, il faut comprendre **le probleme que le client cherche a resoudre**. La technologie n'est qu'un moyen, pas une fin.

| Besoin formule par le client | Objectif business reel |
|---|---|
| "On veut un site web" | Vendre des produits en ligne et augmenter le chiffre d'affaires |
| "On veut migrer dans le cloud" | Reduire les couts d'infrastructure et gagner en flexibilite |
| "On veut un tableau de bord" | Prendre des decisions basees sur les donnees en temps reel |
| "On veut securiser notre SI" | Proteger les donnees clients et etre conforme aux obligations legales |

### 3.3 Etape 2 : evaluer les contraintes et les opportunites

| Type de contrainte | Exemples |
|---|---|
| **Budget** | Enveloppe fixe, preference CAPEX ou OPEX, cout recurrent maximal |
| **Delais** | Date de mise en production imposee, jalons intermediaires |
| **Equipe** | Competences disponibles en interne, capacite a operer la solution |
| **Existant** | Systemes en place avec lesquels la nouvelle solution doit s'integrer |
| **Reglementaire** | Localisation des donnees, certifications requises, audits |

### 3.4 Etape 3 : selectionner les technologies

La selection technologique doit etre **justifiee par les besoins identifies** aux etapes precedentes.

Exemple de mapping complet :

| Besoin business | Exigence technique | Solution retenue | Justification |
|---|---|---|---|
| Vendre en ligne 24/7 | Disponibilite 99.9% | Load balancer + auto-scaling AWS | Redondance multi-AZ, basculement automatique |
| Accepter les paiements | Integration paiement securise | API Stripe | Conforme PCI-DSS, SDK bien documente, pas de gestion de cartes en interne |
| Proteger les donnees clients | Chiffrement + conformite RGPD | RDS chiffre + politique de retention | Chiffrement AES-256 au repos, logs d'acces audites |
| Gerer les pics de trafic (soldes) | Support de 10x la charge normale | Auto-scaling + CDN CloudFront | Ajout automatique de capacite, contenu statique en cache |
| Equipe de 3 devs sans ops | Solution facile a operer | Services manages AWS (RDS, ECS Fargate) | Pas de gestion de serveurs, mises a jour automatiques |

> **Bonne pratique** : chaque choix technique doit pouvoir etre justifie par un besoin business. Si une technologie est dans l'architecture sans justification claire, elle n'a probablement pas sa place.

---

## 4. Red flags dans un cahier des charges

### 4.1 Identifier les signaux d'alerte

Certains elements dans les demandes client doivent declencher une vigilance particuliere :

| Red flag | Exemple | Probleme |
|---|---|---|
| **Exigences vagues** | "Le systeme doit etre rapide" | Impossible a mesurer et a verifier. Rapide par rapport a quoi ? |
| **Attentes irrealistes** | "Le systeme doit avoir 100% de disponibilite" | Le 100% est physiquement impossible. Meme AWS ne le garantit pas |
| **Solutions techniques imposees** | "Il faut utiliser MongoDB 3.6 specifiquement" | Pourquoi cette version precise ? Y a-t-il une raison technique ou est-ce une preference personnelle ? |
| **Securite remise a plus tard** | "On securisera apres le lancement" | La securite est exponentiellement plus couteuse a ajouter apres coup |
| **Absence de budget pour les tests** | "On testera en production" | Garantie d'incidents en production et de degradation de la confiance des utilisateurs |

### 4.2 Questions a poser pour chaque red flag

**Face a une exigence vague** :

- "Quand vous dites rapide, quel temps de reponse serait acceptable ?"
- "Pouvez-vous donner un exemple de ce qui est trop lent aujourd'hui ?"
- "Quels sont les scenarios les plus critiques en termes de performance ?"

**Face a des attentes irrealistes** :

- "Quel est le cout d'une heure d'indisponibilite pour votre activite ?"
- "Quel niveau de disponibilite est reellement necessaire pour chaque composant ?"
- "Etes-vous pret a investir dans l'infrastructure necessaire pour atteindre ce niveau ?"

**Face a une solution technique imposee** :

- "Quelle est la raison de ce choix specifique ?"
- "Y a-t-il des contraintes de compatibilite avec un systeme existant ?"
- "Etes-vous ouvert a des alternatives si elles repondent mieux au besoin ?"

**Face a la securite remise a plus tard** :

- "Quelles donnees sensibles le systeme va-t-il manipuler ?"
- "Quelles sont vos obligations legales en matiere de protection des donnees ?"
- "Quel serait l'impact d'une violation de donnees sur votre activite et votre reputation ?"

---

## 5. Principe directeur : demander tot et souvent

### 5.1 Ne jamais supposer

Le piege le plus courant dans l'analyse des besoins est de **supposer** ce que le client veut au lieu de lui demander. Les suppositions menent a :

- Des fonctionnalites developpees mais jamais utilisees
- Des contraintes techniques decouvertes trop tard
- Des depassements de budget et de delais
- Des livraisons qui ne correspondent pas aux attentes

### 5.2 Bonnes pratiques de communication

| Pratique | Description |
|---|---|
| **Reunions regulieres** | Points d'avancement hebdomadaires avec le client, pas seulement au debut et a la fin |
| **Prototypage rapide** | Montrer un prototype fonctionnel tot pour valider la direction |
| **Documentation partagee** | Cahier des charges vivant, accessible et modifiable par toutes les parties |
| **Reformulation** | Reformuler les demandes du client pour s'assurer de la bonne comprehension : "Si je comprends bien, vous avez besoin de..." |
| **Questions ouvertes** | Privilegier les questions ouvertes ("Comment imaginez-vous...") aux questions fermees ("Voulez-vous un bouton ici ?") |

> **Bonne pratique** : un besoin mal compris au debut du projet coute 10x plus cher a corriger en developpement et 100x plus cher a corriger en production. Investir du temps dans l'analyse des besoins est le meilleur investissement possible.

---

## Pour aller plus loin

- [IEEE 830 -- Recommended Practice for Software Requirements Specifications](https://standards.ieee.org/ieee/830/1222/)
- [RGPD -- Texte officiel (CNIL)](https://www.cnil.fr/fr/rgpd-de-quoi-parle-t-on)
- [AWS Well-Architected Framework -- Pillar: Operational Excellence](https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/welcome.html)
- [The Twelve-Factor App -- Configuration](https://12factor.net/config)
- [OWASP -- Security by Design Principles](https://owasp.org/www-project-developer-guide/draft/design/web_app_checklist/)
