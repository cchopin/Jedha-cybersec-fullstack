# Continuite d'activite et reprise apres sinistre

**Module** : BCA (Plan de Continuite d'Activite) et PRA (Plan de Reprise d'Activite)

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre la difference entre un BCA (Plan de Continuite d'Activite) et un PRA (Plan de Reprise d'Activite)
- Maitriser les concepts de RTO (Recovery Time Objective) et RPO (Recovery Point Objective)
- Savoir structurer un BCA et un PRA adaptes aux besoins de l'entreprise
- Evaluer le cout de l'indisponibilite pour dimensionner correctement les plans de reprise
- Identifier les erreurs courantes dans la mise en oeuvre des plans de continuite et de reprise

---

## 1. BCA : Plan de Continuite d'Activite

### 1.1 Definition

Le **BCA** (Business Continuity Access, ou Plan de Continuite d'Activite -- PCA en francais) est un plan proactif qui definit comment une organisation maintient ses operations essentielles pendant et apres une perturbation majeure.

Le BCA couvre l'ensemble de l'organisation : les processus metier, les personnes, les locaux, les fournisseurs et les systemes IT. Son objectif est de garantir que l'activite business continue, meme en mode degrade.

### 1.2 Types de perturbations couvertes

| Type de perturbation | Exemples |
|---|---|
| **Catastrophes naturelles** | Inondation, seisme, tempete, incendie |
| **Cyberattaques** | Ransomware, attaque DDoS, compromission de donnees |
| **Pannes techniques** | Panne de datacenter, defaillance d'un fournisseur cloud, panne reseau |
| **Pandemies** | Impossibilite d'acceder aux locaux, absenteisme massif |
| **Pannes humaines** | Depart de personnel cle, erreur humaine critique |
| **Problemes fournisseurs** | Faillite d'un prestataire, rupture de contrat, indisponibilite d'un service tiers |

### 1.3 Perimetre du BCA

Le BCA ne se limite pas a l'IT. Il couvre :

- **Les processus metier** : quels processus sont critiques et doivent etre maintenus en priorite ?
- **Les personnes** : qui est responsable de quoi en cas de crise ? Comment communiquer avec les equipes ?
- **Les locaux** : existe-t-il un site de repli ? Le teletravail est-il possible ?
- **Les fournisseurs** : quelles dependances externes sont critiques ?
- **Les systemes IT** : quels systemes doivent etre restaures en priorite ? (cette partie est couverte par le PRA)

---

## 2. PRA : Plan de Reprise d'Activite

### 2.1 Definition

Le **PRA** (Plan de Reprise d'Activite, ou DRP -- Disaster Recovery Plan en anglais) est un plan focalise sur la **recuperation technique des systemes IT** apres un sinistre. Contrairement au BCA qui couvre l'ensemble de l'organisation, le PRA se concentre specifiquement sur l'infrastructure informatique.

### 2.2 Composants du PRA

| Composant | Description |
|---|---|
| **Sauvegardes** | Copies regulieres des donnees stockees dans un emplacement distinct du site principal |
| **Strategies de failover** | Mecanismes de basculement automatique ou manuel vers un site de secours |
| **Equipe de recuperation** | Personnes designees avec des roles et responsabilites clairs pour piloter la reprise |
| **Procedures de restauration** | Etapes documentees pour restaurer chaque systeme dans un ordre de priorite defini |
| **Communication** | Protocole de notification des parties prenantes (equipes internes, clients, autorites) |

### 2.3 BCA vs PRA : complementaires, pas interchangeables

| Aspect | BCA | PRA |
|---|---|---|
| **Perimetre** | Organisation entiere (business, RH, logistique, IT) | Systemes IT et donnees |
| **Objectif** | Maintenir l'activite business | Restaurer les systemes techniques |
| **Temporalite** | Pendant la perturbation | Apres la perturbation |
| **Responsable** | Direction generale, responsable continuite | DSI, equipe infrastructure |
| **Focus** | Processus metier critiques | Serveurs, bases de donnees, reseaux, applications |

> **A noter** : un PRA sans BCA est incomplet (les systemes sont restaures mais personne ne sait comment reprendre l'activite). Un BCA sans PRA est inoperant (le plan existe mais les systemes ne sont pas restaurables). Les deux sont necessaires et doivent etre alignes.

---

## 3. RTO et RPO

### 3.1 RTO : Recovery Time Objective

Le **RTO** (Recovery Time Objective) definit la duree maximale d'interruption acceptable pour un systeme ou un processus. En d'autres termes : **combien de temps le business peut-il rester down ?**

```
     Incident                     Reprise complete
        |                              |
        |<--- RTO (duree maximale) --->|
        |                              |
   Le systeme                    Le systeme est
   est down                      de nouveau operationnel
```

### 3.2 RPO : Recovery Point Objective

Le **RPO** (Recovery Point Objective) definit la quantite maximale de donnees que l'organisation peut se permettre de perdre. En d'autres termes : **combien de donnees peut-on perdre ?**

```
   Derniere                    Incident
   sauvegarde                     |
      |                           |
      |<--- RPO (perte max) ---->|
      |                           |
   Donnees                    Donnees entre la
   sauvegardees               derniere sauvegarde
                              et l'incident sont
                              perdues
```

### 3.3 Exemples concrets par type de systeme

| Systeme | RTO | RPO | Justification |
|---|---|---|---|
| **Plateforme e-commerce** | < 1 heure | < 5 minutes | Chaque minute d'indisponibilite = perte de revenus directe. Les transactions ne doivent pas etre perdues |
| **Transactions financieres** | < 30 minutes | < 5 minutes | Obligations reglementaires, impact financier direct, reconciliation impossible si donnees perdues |
| **CRM (gestion clients)** | < 4 heures | < 1 heure | L'equipe commerciale peut travailler temporairement sans le CRM, mais la perte de donnees clients est couteuse |
| **Email interne** | < 4 heures | < 1 heure | L'email n'est pas critique a la minute pres, mais les equipes ne peuvent pas fonctionner longtemps sans |
| **Archives / documentation** | < 24 heures | < 24 heures | Acces non critique, les equipes peuvent utiliser des copies locales temporairement |
| **Logs applicatifs** | < 24 heures | < 24 heures | Utiles pour le diagnostic mais pas essentiels au fonctionnement quotidien |

### 3.4 Relation entre RTO/RPO et cout

Plus le RTO et le RPO sont bas, plus l'infrastructure necessaire est complexe et couteuse :

| Niveau | Mecanismes requis | Cout relatif |
|---|---|---|
| RPO < 5 min, RTO < 30 min | Replication synchrone, hot standby, failover automatique | Tres eleve |
| RPO < 1h, RTO < 4h | Replication asynchrone, warm standby, basculement semi-automatique | Eleve |
| RPO < 24h, RTO < 24h | Sauvegardes quotidiennes, cold standby, restauration manuelle | Modere |
| RPO > 24h, RTO > 24h | Sauvegardes hebdomadaires, pas de site de secours | Faible |

> **Bonne pratique** : le RTO et le RPO doivent etre alignes avec la criticite reelle de chaque systeme. Appliquer un RPO de 5 minutes a un systeme d'archives est un gaspillage de ressources. Inversement, un RPO de 24 heures pour une base de transactions financieres est inacceptable.

---

## 4. Structure d'un BCA

### 4.1 Sections d'un BCA

Un BCA complet contient les sections suivantes :

| Section | Contenu |
|---|---|
| **1. Introduction et objectifs** | Perimetre du plan, objectifs de continuite, parties prenantes, historique des revisions |
| **2. BIA (Business Impact Analysis)** | Identification des processus critiques, evaluation de l'impact financier et operationnel de leur interruption, classification par ordre de priorite |
| **3. Plan de communication** | Arbre d'appel, canaux de communication de secours, modeles de notification (interne, clients, autorites, medias) |
| **4. Procedures de continuite** | Procedures detaillees pour maintenir chaque processus critique en mode degrade |
| **5. Formation et tests** | Programme de sensibilisation, exercices reguliers, retours d'experience |

### 4.2 Le BIA (Business Impact Analysis)

Le **BIA** est la pierre angulaire du BCA. Il identifie les processus critiques et evalue l'impact de leur interruption :

| Processus | Impact si indisponible 1h | Impact si indisponible 24h | Priorite de reprise |
|---|---|---|---|
| Paiements en ligne | Perte de CA directe | Perte majeure + atteinte reputation | 1 (critique) |
| Service client | Clients insatisfaits | Perte de clients, avis negatifs | 2 (important) |
| Paie des employes | Aucun impact immediat | Aucun impact (cycle mensuel) | 3 (normal) |
| Site web vitrine | Visibilite reduite | Impact SEO, prospects perdus | 2 (important) |

### 4.3 Tests du BCA

Un BCA qui n'est pas teste est un BCA qui ne fonctionne pas. Les types de tests :

| Type de test | Description | Frequence recommandee |
|---|---|---|
| **Revue documentaire** | Relecture du plan par les parties prenantes | Trimestrielle |
| **Exercice sur table** | Simulation theorique d'un scenario de crise en reunion | Semestrielle |
| **Exercice partiel** | Test reel d'un composant specifique (ex. basculement d'un serveur) | Semestrielle |
| **Exercice complet** | Simulation grandeur nature d'un sinistre | Annuelle |

---

## 5. Structure d'un PRA

### 5.1 Sections d'un PRA

| Section | Contenu |
|---|---|
| **1. Perimetre** | Systemes couverts, RTO et RPO par systeme, criteres de declenchement du PRA |
| **2. Equipe de reponse** | Noms, roles, coordonnees, chaine d'escalade, suppleants |
| **3. Procedures de recuperation** | Etapes detaillees pour restaurer chaque systeme, dans l'ordre de priorite defini par le BIA |
| **4. Sauvegarde et restauration** | Politique de sauvegarde (frequence, retention, emplacement), procedures de restauration testees |
| **5. Strategies failover / failback** | Mecanismes de basculement vers le site de secours (failover) et de retour vers le site principal (failback) |
| **6. Tests et validation** | Plan de test, resultats des derniers tests, actions correctives |

### 5.2 Failover et failback

| Concept | Definition |
|---|---|
| **Failover** | Basculement du site principal vers le site de secours en cas de sinistre |
| **Failback** | Retour du site de secours vers le site principal une fois celui-ci restaure |

Le failback est souvent plus complexe que le failover car il necessite de synchroniser les donnees qui ont ete modifiees sur le site de secours pendant la periode de fonctionnement en mode degrade.

```
Site principal          Site de secours
[Actif]                 [Passif]
    |                       |
    | --- SINISTRE ---      |
    |                       |
[Down]                  [Actif]        <- Failover
    |                       |
    | --- REPARATION ---    |
    |                       |
[Actif]                 [Passif]       <- Failback (+ synchronisation)
```

### 5.3 Types de sites de secours

| Type | Description | RTO | Cout |
|---|---|---|---|
| **Cold site** | Local equipe en electricite et reseau, mais sans serveurs. Les serveurs doivent etre commandes et installes | > 24 heures | Faible |
| **Warm site** | Local equipe avec des serveurs pre-configures mais pas totalement a jour. Necessite une synchronisation des donnees | 4 a 24 heures | Modere |
| **Hot site** | Replique quasi identique du site principal, avec replication en temps reel. Basculement possible en minutes | < 1 heure | Eleve |
| **Cloud DR** | Site de secours provisionne dans le cloud, active a la demande | 1 a 4 heures | Variable (pay-as-you-go) |

---

## 6. Erreurs courantes

### 6.1 Ignorer les facteurs non techniques

Le PRA ne peut pas fonctionner si les aspects humains et organisationnels sont negliges :

- **Personnel** : les membres de l'equipe de recuperation sont-ils disponibles en dehors des heures de bureau ? Ont-ils ete formes ?
- **Fournisseurs** : les contrats de support prevoient-ils une intervention en cas de sinistre ? Quels sont les SLA ?
- **Communication** : comment prevenir les clients si le systeme de communication principal est hors service ?

### 6.2 Tests insuffisants

| Probleme | Consequence |
|---|---|
| Le PRA n'a jamais ete teste | On decouvre le jour du sinistre que les procedures ne fonctionnent pas |
| Les sauvegardes ne sont pas testees | Les fichiers de sauvegarde sont corrompus ou incomplets |
| L'equipe n'a jamais fait d'exercice | Panique, perte de temps, erreurs en chaine |
| Le plan n'a pas ete mis a jour | Les procedures font reference a des systemes qui n'existent plus |

> **Bonne pratique** : une sauvegarde qui n'a pas ete testee par une restauration reelle n'est pas une sauvegarde. Planifier des tests de restauration reguliers et documenter les resultats.

### 6.3 Dependance excessive aux fournisseurs cloud

Le cloud offre des mecanismes de reprise puissants (replication multi-region, snapshots automatiques, etc.) mais il ne dispense pas d'un PRA :

- Les fournisseurs cloud connaissent aussi des pannes majeures (AWS us-east-1 en 2017, Azure AD en 2021, etc.)
- Le modele de responsabilite partagee signifie que le provider est responsable de l'infrastructure, mais le client est responsable de ses donnees et de ses configurations
- Une erreur de configuration (suppression accidentelle d'une base de donnees, mauvaise politique de retention) ne sera pas corrigee par le provider

### 6.4 Roles mal definis

| Situation | Consequence |
|---|---|
| Personne n'est designe comme responsable du PRA | Le plan existe mais personne ne le maintient ni ne le declenche |
| Un seul responsable sans suppleant | Si cette personne est indisponible lors du sinistre, le plan est bloque |
| Les roles ne sont pas communiques | Chacun attend que quelqu'un d'autre agisse |
| Pas de chaine d'escalade | Les decisions tardent, le temps de reprise s'allonge |

> **A noter** : le BCA et le PRA sont des documents vivants. Ils doivent etre revises et mis a jour a chaque changement significatif de l'infrastructure, de l'organisation ou des processus metier. Un plan obsolete est aussi dangereux qu'un plan inexistant.

---

## Pour aller plus loin

- [ISO 22301 -- Systemes de management de la continuite d'activite](https://www.iso.org/standard/75106.html)
- [ANSSI -- Guide de continuite d'activite](https://cyber.gouv.fr/publications/guide-pour-realiser-un-plan-de-continuite-dactivite)
- [AWS -- Disaster Recovery Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-workloads-on-aws.html)
- [NIST SP 800-34 -- Contingency Planning Guide for Federal Information Systems](https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final)
- [Uptime Institute -- Tier Classification System](https://uptimeinstitute.com/tiers)
