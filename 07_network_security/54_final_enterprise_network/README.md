# Lab 54: Final enterprise network

Conception d'une architecture réseau d'entreprise complète pour Greentech Dynamics Inc.

**Durée estimée** : 135 minutes

**Niveau** : Exercice final du module Network Security

**Type** : Discussion architecturale et conception

---

## Table des matières

1. [Contexte](#contexte)
2. [Présentation de l'entreprise](#présentation-de-lentreprise)
3. [Exigences techniques](#exigences-techniques)
4. [Questions de conception](#questions-de-conception)
5. [Livrables attendus](#livrables-attendus)
6. [Critères d'évaluation](#critères-dévaluation)

---

## Contexte

Greentech Dynamics Inc. est une entreprise en forte croissance spécialisée dans les solutions d'énergie durable et l'infrastructure intelligente. L'entreprise planifie l'ouverture d'un nouveau siège social à Lyon, France.

L'objectif est de proposer une architecture réseau d'entreprise complète supportant :

- Haute disponibilité
- Redondance
- Sécurité
- Évolutivité
- Automatisation
- Optimisation WAN

---

## Présentation de l'entreprise

### Infrastructure prévue

| Élément | Description |
|---------|-------------|
| Effectif sur site | 400 employés |
| Data centers | 2 (1 production, 1 reprise d'activité) |
| Bureau distant | Paris (accès distant requis) |
| Intégrations cloud | Office 365, AWS (données IoT), Salesforce |
| Départements sensibles | R&D, IoT, Finance |
| Opérations | 24/7 avec SLA pour clients Europe et Amérique du Nord |

### Départements et besoins

| Département | Niveau de sécurité | Besoins spécifiques |
|-------------|-------------------|---------------------|
| R&D | Critique | Isolation, protection IP |
| Finance | Élevé | Conformité, audit |
| IoT | Élevé | Segmentation, monitoring |
| Marketing | Standard | Accès Internet, collaboration |
| RH | Standard | Données personnelles |
| Direction | Élevé | Confidentialité |

---

## Exigences techniques

### Haute disponibilité

- Aucun point de défaillance unique (SPOF)
- Basculement automatique < 50ms pour les liens critiques
- SLA 99.99% pour les services critiques

### Sécurité

- Segmentation stricte entre départements
- Contrôle d'accès réseau (NAC)
- Protection contre les menaces internes et externes
- Conformité RGPD pour les données personnelles

### Évolutivité

- Support de la croissance jusqu'à 1000 employés
- Expansion future en Amérique du Nord
- Intégration de nouveaux services cloud

### Automatisation

- Déploiement automatisé des configurations
- Sauvegarde et versioning des configurations
- Monitoring centralisé

---

## Questions de conception

### 1. Architecture réseau d'entreprise

- Quel modèle de conception réseau utiliser (Core-Distribution-Access vs Leaf-Spine) ? Justification ?
- Où placer les liens redondants et pourquoi ?
- Comment segmenter le trafic entre les départements (R&D, Finance, Marketing) ?
- Quels mécanismes de policy enforcement implémenter au niveau accès ?

### 2. Redondance WAN et Internet

- Quelles techniques de WAN failover et traffic engineering implémenter ?
- BGP multihoming, MPLS, SD-WAN, ou combinaison ?
- Comment connecter le bureau de Paris au siège de manière sécurisée ?

### 3. Topologie data center

- Utiliser une topologie Leaf-Spine dans le data center ? Pourquoi ?
- Comment assurer l'efficacité et l'évolutivité du trafic est-ouest ?
- Comment implémenter le basculement entre les sites production et DR ?

### 4. Automatisation et gestion réseau

- Quels outils utiliser pour la gestion de configuration et l'automatisation ?
- Comment utiliser Ansible, Oxidized, ou RANCID dans cet environnement ?
- Quelle stratégie de sauvegarde et versioning pour les configurations critiques ?

### 5. Sécurité et policy enforcement

- Quel type de NAC (Network Access Control) implémenter ?
- Comment appliquer les vérifications de posture et mettre en quarantaine les appareils inconnus ?
- Comment gérer le contrôle d'accès aux segments réseau sensibles ?

### 6. Considérations bonus

- Comment le design évolue-t-il si Greentech Dynamics s'étend en Amérique du Nord ?
- Quelles intégrations cloud et optimisations WAN hybrides envisager ?
- Comment intégrer les principes Zero Trust dans le réseau ?

---

## Livrables attendus

À la fin de cette session :

1. **Schéma d'architecture**
   - Vue d'ensemble style whiteboard du design proposé
   - Identification des composants clés
   - Flux de trafic principaux

2. **Justifications architecturales**
   - Points bullet pour chaque décision majeure
   - Mapping entre les technologies vues en cours et la solution proposée

3. **Plan de sécurité**
   - Stratégie de segmentation
   - Points de contrôle de sécurité
   - Politique NAC

4. **Plan d'automatisation**
   - Outils sélectionnés
   - Workflows de déploiement
   - Stratégie de backup

---

## Critères d'évaluation

| Critère | Poids |
|---------|-------|
| Cohérence de l'architecture globale | 25% |
| Justification des choix technologiques | 25% |
| Prise en compte de la sécurité | 20% |
| Évolutivité et flexibilité | 15% |
| Automatisation et opérations | 15% |

### Grille d'évaluation détaillée

**Architecture (25%)**
- [ ] Modèle de design approprié et justifié
- [ ] Redondance correctement placée
- [ ] Segmentation logique des départements

**Choix technologiques (25%)**
- [ ] Technologies adaptées aux besoins
- [ ] Justifications techniques solides
- [ ] Mapping avec le contenu du cours

**Sécurité (20%)**
- [ ] NAC implémenté
- [ ] Segmentation efficace
- [ ] Contrôles d'accès définis

**Évolutivité (15%)**
- [ ] Design modulaire
- [ ] Capacité d'extension géographique
- [ ] Support de croissance

**Automatisation (15%)**
- [ ] Outils appropriés sélectionnés
- [ ] Stratégie de backup définie
- [ ] Workflows documentés

---

## Ressources

- Document PDF de présentation Greentech Dynamics (voir dossier `resources/`)
- Cours 47 : Network design models
- Cours 48 : Redundancy enterprise
- Cours 49 : WAN failover traffic engineering
- Cours 50 : SD-WAN basics
- Cours 51 : Configuration management Ansible
- Cours 52 : Policy enforcement NAC

---

## Solution

Une fois l'exercice terminé (ou en cas de blocage), consulter `SOLUTION.md` pour les éléments de réponse attendus.
