# Continuité d'activité et reprise après sinistre

**Module** : BCA (Plan de Continuité d'Activité) et PRA (Plan de Reprise d'Activité)

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre la différence entre un BCA (Plan de Continuité d'Activité) et un PRA (Plan de Reprise d'Activité)
- Maîtriser les concepts de RTO (Recovery Time Objective) et RPO (Recovery Point Objective)
- Savoir structurer un BCA et un PRA adaptés aux besoins de l'entreprise
- Évaluer le coût de l'indisponibilité pour dimensionner correctement les plans de reprise
- Identifier les erreurs courantes dans la mise en œuvre des plans de continuité et de reprise

---

## 1. BCA : Plan de Continuité d'Activité

### 1.1 Définition

Le **BCA** (Business Continuity Access, ou Plan de Continuité d'Activité -- PCA en français) est un plan proactif qui définit comment une organisation maintient ses opérations essentielles pendant et après une perturbation majeure.

Le BCA couvre l'ensemble de l'organisation : les processus métier, les personnes, les locaux, les fournisseurs et les systèmes IT. Son objectif est de garantir que l'activité business continue, même en mode dégradé.

### 1.2 Types de perturbations couvertes

| Type de perturbation | Exemples |
|---|---|
| **Catastrophes naturelles** | Inondation, séisme, tempête, incendie |
| **Cyberattaques** | Ransomware, attaque DDoS, compromission de données |
| **Pannes techniques** | Panne de datacenter, défaillance d'un fournisseur cloud, panne réseau |
| **Pandémies** | Impossibilité d'accéder aux locaux, absentéisme massif |
| **Pannes humaines** | Départ de personnel clé, erreur humaine critique |
| **Problèmes fournisseurs** | Faillite d'un prestataire, rupture de contrat, indisponibilité d'un service tiers |

### 1.3 Périmètre du BCA

Le BCA ne se limite pas à l'IT. Il couvre :

- **Les processus métier** : quels processus sont critiques et doivent être maintenus en priorité ?
- **Les personnes** : qui est responsable de quoi en cas de crise ? Comment communiquer avec les équipes ?
- **Les locaux** : existe-t-il un site de repli ? Le télétravail est-il possible ?
- **Les fournisseurs** : quelles dépendances externes sont critiques ?
- **Les systèmes IT** : quels systèmes doivent être restaurés en priorité ? (cette partie est couverte par le PRA)

---

## 2. PRA : Plan de Reprise d'Activité

### 2.1 Définition

Le **PRA** (Plan de Reprise d'Activité, ou DRP -- Disaster Recovery Plan en anglais) est un plan focalisé sur la **récupération technique des systèmes IT** après un sinistre. Contrairement au BCA qui couvre l'ensemble de l'organisation, le PRA se concentre spécifiquement sur l'infrastructure informatique.

### 2.2 Composants du PRA

| Composant | Description |
|---|---|
| **Sauvegardes** | Copies régulières des données stockées dans un emplacement distinct du site principal |
| **Stratégies de failover** | Mécanismes de basculement automatique ou manuel vers un site de secours |
| **Équipe de récupération** | Personnes désignées avec des rôles et responsabilités clairs pour piloter la reprise |
| **Procédures de restauration** | Étapes documentées pour restaurer chaque système dans un ordre de priorité défini |
| **Communication** | Protocole de notification des parties prenantes (équipes internes, clients, autorités) |

### 2.3 BCA vs PRA : complémentaires, pas interchangeables

| Aspect | BCA | PRA |
|---|---|---|
| **Périmètre** | Organisation entière (business, RH, logistique, IT) | Systèmes IT et données |
| **Objectif** | Maintenir l'activité business | Restaurer les systèmes techniques |
| **Temporalité** | Pendant la perturbation | Après la perturbation |
| **Responsable** | Direction générale, responsable continuité | DSI, équipe infrastructure |
| **Focus** | Processus métier critiques | Serveurs, bases de données, réseaux, applications |

> **À noter** : un PRA sans BCA est incomplet (les systèmes sont restaurés mais personne ne sait comment reprendre l'activité). Un BCA sans PRA est inopérant (le plan existe mais les systèmes ne sont pas restaurables). Les deux sont nécessaires et doivent être alignés.

---

## 3. RTO et RPO

### 3.1 RTO : Recovery Time Objective

Le **RTO** (Recovery Time Objective) définit la durée maximale d'interruption acceptable pour un système ou un processus. En d'autres termes : **combien de temps le business peut-il rester down ?**

```
     Incident                     Reprise complète
        |                              |
        |<--- RTO (durée maximale) --->|
        |                              |
   Le système                    Le système est
   est down                      de nouveau opérationnel
```

### 3.2 RPO : Recovery Point Objective

Le **RPO** (Recovery Point Objective) définit la quantité maximale de données que l'organisation peut se permettre de perdre. En d'autres termes : **combien de données peut-on perdre ?**

```
   Dernière                    Incident
   sauvegarde                     |
      |                           |
      |<--- RPO (perte max) ---->|
      |                           |
   Données                    Données entre la
   sauvegardées               dernière sauvegarde
                              et l'incident sont
                              perdues
```

### 3.3 Exemples concrets par type de système

| Système | RTO | RPO | Justification |
|---|---|---|---|
| **Plateforme e-commerce** | < 1 heure | < 5 minutes | Chaque minute d'indisponibilité = perte de revenus directe. Les transactions ne doivent pas être perdues |
| **Transactions financières** | < 30 minutes | < 5 minutes | Obligations réglementaires, impact financier direct, réconciliation impossible si données perdues |
| **CRM (gestion clients)** | < 4 heures | < 1 heure | L'équipe commerciale peut travailler temporairement sans le CRM, mais la perte de données clients est coûteuse |
| **Email interne** | < 4 heures | < 1 heure | L'email n'est pas critique à la minute près, mais les équipes ne peuvent pas fonctionner longtemps sans |
| **Archives / documentation** | < 24 heures | < 24 heures | Accès non critique, les équipes peuvent utiliser des copies locales temporairement |
| **Logs applicatifs** | < 24 heures | < 24 heures | Utiles pour le diagnostic mais pas essentiels au fonctionnement quotidien |

### 3.4 Relation entre RTO/RPO et coût

Plus le RTO et le RPO sont bas, plus l'infrastructure nécessaire est complexe et coûteuse :

| Niveau | Mécanismes requis | Coût relatif |
|---|---|---|
| RPO < 5 min, RTO < 30 min | Réplication synchrone, hot standby, failover automatique | Très élevé |
| RPO < 1h, RTO < 4h | Réplication asynchrone, warm standby, basculement semi-automatique | Élevé |
| RPO < 24h, RTO < 24h | Sauvegardes quotidiennes, cold standby, restauration manuelle | Modéré |
| RPO > 24h, RTO > 24h | Sauvegardes hebdomadaires, pas de site de secours | Faible |

> **Bonne pratique** : le RTO et le RPO doivent être alignés avec la criticité réelle de chaque système. Appliquer un RPO de 5 minutes à un système d'archives est un gaspillage de ressources. Inversement, un RPO de 24 heures pour une base de transactions financières est inacceptable.

---

## 4. Structure d'un BCA

### 4.1 Sections d'un BCA

Un BCA complet contient les sections suivantes :

| Section | Contenu |
|---|---|
| **1. Introduction et objectifs** | Périmètre du plan, objectifs de continuité, parties prenantes, historique des révisions |
| **2. BIA (Business Impact Analysis)** | Identification des processus critiques, évaluation de l'impact financier et opérationnel de leur interruption, classification par ordre de priorité |
| **3. Plan de communication** | Arbre d'appel, canaux de communication de secours, modèles de notification (interne, clients, autorités, médias) |
| **4. Procédures de continuité** | Procédures détaillées pour maintenir chaque processus critique en mode dégradé |
| **5. Formation et tests** | Programme de sensibilisation, exercices réguliers, retours d'expérience |

### 4.2 Le BIA (Business Impact Analysis)

Le **BIA** est la pierre angulaire du BCA. Il identifie les processus critiques et évalue l'impact de leur interruption :

| Processus | Impact si indisponible 1h | Impact si indisponible 24h | Priorité de reprise |
|---|---|---|---|
| Paiements en ligne | Perte de CA directe | Perte majeure + atteinte réputation | 1 (critique) |
| Service client | Clients insatisfaits | Perte de clients, avis négatifs | 2 (important) |
| Paie des employés | Aucun impact immédiat | Aucun impact (cycle mensuel) | 3 (normal) |
| Site web vitrine | Visibilité réduite | Impact SEO, prospects perdus | 2 (important) |

### 4.3 Tests du BCA

Un BCA qui n'est pas testé est un BCA qui ne fonctionne pas. Les types de tests :

| Type de test | Description | Fréquence recommandée |
|---|---|---|
| **Revue documentaire** | Relecture du plan par les parties prenantes | Trimestrielle |
| **Exercice sur table** | Simulation théorique d'un scénario de crise en réunion | Semestrielle |
| **Exercice partiel** | Test réel d'un composant spécifique (ex. basculement d'un serveur) | Semestrielle |
| **Exercice complet** | Simulation grandeur nature d'un sinistre | Annuelle |

---

## 5. Structure d'un PRA

### 5.1 Sections d'un PRA

| Section | Contenu |
|---|---|
| **1. Périmètre** | Systèmes couverts, RTO et RPO par système, critères de déclenchement du PRA |
| **2. Équipe de réponse** | Noms, rôles, coordonnées, chaîne d'escalade, suppléants |
| **3. Procédures de récupération** | Étapes détaillées pour restaurer chaque système, dans l'ordre de priorité défini par le BIA |
| **4. Sauvegarde et restauration** | Politique de sauvegarde (fréquence, rétention, emplacement), procédures de restauration testées |
| **5. Stratégies failover / failback** | Mécanismes de basculement vers le site de secours (failover) et de retour vers le site principal (failback) |
| **6. Tests et validation** | Plan de test, résultats des derniers tests, actions correctives |

### 5.2 Failover et failback

| Concept | Définition |
|---|---|
| **Failover** | Basculement du site principal vers le site de secours en cas de sinistre |
| **Failback** | Retour du site de secours vers le site principal une fois celui-ci restauré |

Le failback est souvent plus complexe que le failover car il nécessite de synchroniser les données qui ont été modifiées sur le site de secours pendant la période de fonctionnement en mode dégradé.

```
Site principal          Site de secours
[Actif]                 [Passif]
    |                       |
    | --- SINISTRE ---      |
    |                       |
[Down]                  [Actif]        <- Failover
    |                       |
    | --- RÉPARATION ---    |
    |                       |
[Actif]                 [Passif]       <- Failback (+ synchronisation)
```

### 5.3 Types de sites de secours

| Type | Description | RTO | Coût |
|---|---|---|---|
| **Cold site** | Local équipé en électricité et réseau, mais sans serveurs. Les serveurs doivent être commandés et installés | > 24 heures | Faible |
| **Warm site** | Local équipé avec des serveurs pré-configurés mais pas totalement à jour. Nécessite une synchronisation des données | 4 à 24 heures | Modéré |
| **Hot site** | Réplique quasi identique du site principal, avec réplication en temps réel. Basculement possible en minutes | < 1 heure | Élevé |
| **Cloud DR** | Site de secours provisionné dans le cloud, activé à la demande | 1 à 4 heures | Variable (pay-as-you-go) |

---

## 6. Erreurs courantes

### 6.1 Ignorer les facteurs non techniques

Le PRA ne peut pas fonctionner si les aspects humains et organisationnels sont négligés :

- **Personnel** : les membres de l'équipe de récupération sont-ils disponibles en dehors des heures de bureau ? Ont-ils été formés ?
- **Fournisseurs** : les contrats de support prévoient-ils une intervention en cas de sinistre ? Quels sont les SLA ?
- **Communication** : comment prévenir les clients si le système de communication principal est hors service ?

### 6.2 Tests insuffisants

| Problème | Conséquence |
|---|---|
| Le PRA n'a jamais été testé | On découvre le jour du sinistre que les procédures ne fonctionnent pas |
| Les sauvegardes ne sont pas testées | Les fichiers de sauvegarde sont corrompus ou incomplets |
| L'équipe n'a jamais fait d'exercice | Panique, perte de temps, erreurs en chaîne |
| Le plan n'a pas été mis à jour | Les procédures font référence à des systèmes qui n'existent plus |

> **Bonne pratique** : une sauvegarde qui n'a pas été testée par une restauration réelle n'est pas une sauvegarde. Planifier des tests de restauration réguliers et documenter les résultats.

### 6.3 Dépendance excessive aux fournisseurs cloud

Le cloud offre des mécanismes de reprise puissants (réplication multi-région, snapshots automatiques, etc.) mais il ne dispense pas d'un PRA :

- Les fournisseurs cloud connaissent aussi des pannes majeures (AWS us-east-1 en 2017, Azure AD en 2021, etc.)
- Le modèle de responsabilité partagée signifie que le provider est responsable de l'infrastructure, mais le client est responsable de ses données et de ses configurations
- Une erreur de configuration (suppression accidentelle d'une base de données, mauvaise politique de rétention) ne sera pas corrigée par le provider

### 6.4 Rôles mal définis

| Situation | Conséquence |
|---|---|
| Personne n'est désigné comme responsable du PRA | Le plan existe mais personne ne le maintient ni ne le déclenche |
| Un seul responsable sans suppléant | Si cette personne est indisponible lors du sinistre, le plan est bloqué |
| Les rôles ne sont pas communiqués | Chacun attend que quelqu'un d'autre agisse |
| Pas de chaîne d'escalade | Les décisions tardent, le temps de reprise s'allonge |

> **À noter** : le BCA et le PRA sont des documents vivants. Ils doivent être révisés et mis à jour à chaque changement significatif de l'infrastructure, de l'organisation ou des processus métier. Un plan obsolète est aussi dangereux qu'un plan inexistant.

---

## Pour aller plus loin

- [ISO 22301 -- Systèmes de management de la continuité d'activité](https://www.iso.org/standard/75106.html)
- [ANSSI -- Guide de continuité d'activité](https://cyber.gouv.fr/publications/guide-pour-realiser-un-plan-de-continuite-dactivite)
- [AWS -- Disaster Recovery Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-workloads-on-aws.html)
- [NIST SP 800-34 -- Contingency Planning Guide for Federal Information Systems](https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final)
- [Uptime Institute -- Tier Classification System](https://uptimeinstitute.com/tiers)
