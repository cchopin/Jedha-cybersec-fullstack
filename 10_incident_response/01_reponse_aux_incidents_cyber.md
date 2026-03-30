# Réponse aux incidents cyber

**Durée : 45 min**

## Ce que vous allez apprendre dans ce cours

La réponse aux incidents est au coeur de la cybersécurité opérationnelle. Lorsqu'une attaque survient, la capacité d'une organisation à réagir rapidement et méthodiquement fait la différence entre un incident maîtrisé et une catastrophe. Dans cette leçon, vous apprendrez :

- la différence fondamentale entre un événement de sécurité et un incident de sécurité,
- pourquoi la réponse aux incidents est critique pour toute organisation,
- les deux frameworks de référence : NIST SP 800-61 et SANS,
- les rôles et responsabilités au sein d'une équipe CSIRT/CERT,
- comment classifier et prioriser les incidents,
- la chaîne de communication et d'escalade lors d'un incident,
- les obligations légales et réglementaires (RGPD, ANSSI),
- les KPIs essentiels pour mesurer l'efficacité de votre réponse.

---

## Événement de sécurité vs incident de sécurité

Avant toute chose, il est essentiel de distinguer deux notions souvent confondues.

| Concept | Définition | Exemple |
|---------|------------|---------|
| **Événement de sécurité** | Toute occurrence observable dans un système ou un réseau. La majorité des événements sont bénins. | Un utilisateur se connecte au VPN, un scan de ports est détecté, un email de spam est filtré |
| **Incident de sécurité** | Un événement ou une série d'événements qui compromettent (ou menacent de compromettre) la confidentialité, l'intégrité ou la disponibilité d'un système d'information. | Un ransomware chiffre des fichiers, un attaquant exfiltre des données clients, un compte administrateur est compromis |

En d'autres termes : **tous les incidents sont des événements, mais tous les événements ne sont pas des incidents**. Le travail d'un analyste SOC consiste précisément à trier les événements pour identifier ceux qui constituent de véritables incidents.

Le NIST SP 800-61 définit un incident de sécurité informatique comme *"une violation ou une menace imminente de violation des politiques de sécurité informatique, des politiques d'utilisation acceptable ou des pratiques de sécurité standard"*.

### Le flux de traitement

```
Événements de sécurité (des milliers par jour)
        │
        ▼
┌────────────────────┐
│  Triage / Filtrage │  ← Analyste SOC L1
│   (SIEM, alertes)  │
└───────┬────────────┘
        │
        ▼
Alertes qualifiées (dizaines par jour)
        │
        ▼
┌────────────────────┐
│ Analyse approfondie│  ← Analyste SOC L2/L3
│  (investigation)   │
└───────┬────────────┘
        │
        ▼
Incidents confirmés (quelques-uns par semaine/mois)
        │
        ▼
┌────────────────────┐
│ Réponse à incident │  ← Équipe CSIRT
│   (containment,    │
│   eradication...)  │
└────────────────────┘
```

---

## Pourquoi la réponse aux incidents est critique

Une réponse aux incidents mal préparée ou inexistante expose l'organisation à des conséquences graves sur plusieurs plans.

### Impacts financiers

| Type de coût | Description | Ordre de grandeur |
|-------------|-------------|-------------------|
| **Coût direct** | Remédiation technique, restauration des systèmes, remplacement de matériel | Dizaines à centaines de milliers d'euros |
| **Rançon** | Paiement éventuel d'un ransomware (déconseillé) | De quelques milliers à plusieurs millions d'euros |
| **Perte d'exploitation** | Arrêt d'activité pendant la remédiation | Variable selon la durée (jours à semaines) |
| **Amendes réglementaires** | Sanctions RGPD (jusqu'à 4% du CA mondial), sanctions sectorielles | Jusqu'à plusieurs millions d'euros |
| **Coût moyen d'une data breach** | Selon le rapport IBM Cost of a Data Breach 2024 | ~4,45 millions USD en moyenne mondiale |

### Impacts réputationnels

La confiance des clients, partenaires et investisseurs peut être durablement atteinte. Selon une étude de Ponemon Institute, 65% des consommateurs perdent confiance dans une entreprise après une fuite de données. La couverture médiatique amplifie considérablement l'impact sur la marque.

### Impacts légaux

- **Responsabilité civile** : les victimes (clients, employés) peuvent engager des poursuites
- **Responsabilité pénale** : en cas de négligence avérée dans la protection des données
- **Obligations contractuelles** : les contrats avec les clients ou partenaires peuvent imposer des niveaux de sécurité et des délais de notification

### Impacts opérationnels

Un incident peut paralyser l'ensemble des opérations d'une organisation. Les systèmes critiques deviennent indisponibles, les employés ne peuvent plus travailler, et la chaîne d'approvisionnement peut être rompue. La restauration complète peut prendre des semaines, voire des mois.

---

## Les frameworks de référence

Deux frameworks majeurs structurent la réponse aux incidents dans le monde de la cybersécurité. Ils partagent des principes communs mais diffèrent dans leur découpage des phases.

### NIST SP 800-61 (4 phases)

Le **NIST** (National Institute of Standards and Technology) propose un cycle de réponse aux incidents en 4 phases dans sa publication spéciale 800-61 Rev. 2 (*Computer Security Incident Handling Guide*).

```
┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────────────┐    ┌───────────────────┐
│              │    │                  │    │                                  │    │                   │
│ 1.Préparation│───▶│ 2. Détection &   │───▶│ 3. Confinement, Éradication      │───▶│ 4. Activité       │
│              │    │    Analyse       │    │    & Récupération                │    │    post-incident  │
│              │    │                  │    │                                  │    │                   │
└──────────────┘    └──────────────────┘    └──────────────────────────────────┘    └───────┬───────────┘
       ▲                                                                                    │
       └────────────────────────────────────────────────────────────────────────────────────┘
                                    (boucle d'amélioration continue)
```

| Phase NIST | Description | Activités clés |
|-----------|-------------|----------------|
| **1. Préparation** | Mettre en place les moyens de réponse avant qu'un incident ne survienne | Politique IR, équipe CSIRT, outils (SIEM, EDR), playbooks, exercices de simulation, formation |
| **2. Détection & Analyse** | Identifier et valider qu'un incident s'est produit | Monitoring, analyse des alertes, triage, collecte de preuves initiales, détermination de la portée |
| **3. Confinement, Éradication & Récupération** | Limiter l'impact, éliminer la menace et restaurer les systèmes | Isolation réseau, suppression du malware, patch des vulnérabilités, restauration des backups, monitoring renforcé |
| **4. Activité post-incident** | Tirer les leçons de l'incident pour améliorer la posture de sécurité | Rapport post-incident, lessons learned, mise à jour des playbooks, amélioration des contrôles |

### SANS (6 étapes)

Le **SANS Institute** propose un modèle en 6 étapes, connu sous l'acronyme **PICERL** (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned).

| Étape SANS | Description | Activités clés |
|-----------|-------------|----------------|
| **1. Préparation** | Préparer l'organisation à gérer les incidents | Politiques, procédures, outils, formation, exercices |
| **2. Identification** | Détecter et confirmer l'incident | Surveillance, détection d'anomalies, analyse des alertes, validation |
| **3. Confinement** | Empêcher l'incident de se propager | Confinement court terme (isolation immédiate) et long terme (correctifs temporaires) |
| **4. Éradication** | Éliminer la cause racine de l'incident | Suppression malware, fermeture des accès non autorisés, correction des vulnérabilités |
| **5. Récupération** | Restaurer les systèmes à leur état normal | Restauration depuis les backups, remise en production progressive, monitoring renforcé |
| **6. Leçons apprises** | Documenter et améliorer | Post-mortem, rapport final, mise à jour des procédures, recommandations |

### Comparaison détaillée NIST vs SANS

| Critère | NIST SP 800-61 | SANS PICERL |
|---------|----------------|-------------|
| **Nombre de phases** | 4 | 6 |
| **Préparation** | Phase 1 : Préparation | Étape 1 : Préparation |
| **Détection** | Phase 2 : Détection & Analyse | Étape 2 : Identification |
| **Confinement** | Phase 3 (regroupée avec éradication et récupération) | Étape 3 : Confinement (phase dédiée) |
| **Éradication** | Phase 3 (regroupée) | Étape 4 : Éradication (phase dédiée) |
| **Récupération** | Phase 3 (regroupée) | Étape 5 : Récupération (phase dédiée) |
| **Retour d'expérience** | Phase 4 : Activité post-incident | Étape 6 : Leçons apprises |
| **Approche** | Itérative, met l'accent sur la boucle d'amélioration continue | Séquentielle et linéaire, étapes distinctes et ordonnées |
| **Granularité** | Moins granulaire sur le confinement/éradication/récupération | Plus granulaire, sépare clairement chaque phase opérationnelle |
| **Public cible** | Organisations gouvernementales et privées (référence aux USA) | Professionnels de la sécurité, praticiens IR |
| **Usage typique** | Cadre de gouvernance et politique IR | Guide opérationnel de terrain |
| **Point fort** | Vision holistique, boucle de feedback intégrée | Clarté opérationnelle, facilité d'implémentation pas-à-pas |

> **En pratique**, la plupart des équipes IR combinent les deux approches : elles utilisent la structure SANS pour les opérations quotidiennes et la philosophie NIST pour la gouvernance et l'amélioration continue.

---

## Les rôles dans une équipe CSIRT/CERT

Une équipe de réponse aux incidents ne se résume pas à quelques analystes. Elle repose sur des rôles complémentaires, chacun apportant une expertise spécifique.

### Qu'est-ce qu'un CSIRT / CERT ?

- **CSIRT** (Computer Security Incident Response Team) : équipe interne ou externe dédiée à la gestion des incidents de sécurité informatique.
- **CERT** (Computer Emergency Response Team) : historiquement le terme utilisé par le CERT/CC de Carnegie Mellon. Aujourd'hui, CERT est une marque déposée, et CSIRT est le terme générique recommandé.
- **SOC** (Security Operations Center) : centre de surveillance continue qui détecte et remonte les alertes. Le SOC alimente le CSIRT.

### Les rôles clés

| Rôle | Responsabilités | Compétences requises |
|------|----------------|---------------------|
| **Incident Manager** | Coordonne la réponse, prend les décisions critiques, communique avec la direction et les parties prenantes externes | Leadership, communication, gestion de crise, connaissance des processus IR |
| **Analyste SOC L1 (Triage)** | Première ligne : surveille les alertes SIEM, effectue le triage initial, escalade les alertes suspectes | Connaissance des outils SIEM, compréhension des logs, respect des procédures |
| **Analyste SOC L2 (Investigation)** | Analyse approfondie des alertes escaladées, corrélation d'événements, qualification des incidents | Analyse de logs avancée, threat intelligence, connaissance des TTPs (MITRE ATT&CK) |
| **Analyste SOC L3 (Expert)** | Gère les incidents complexes, développe des règles de détection, threat hunting proactif | Expertise technique pointue, reverse engineering, développement de signatures |
| **Forensic Analyst** | Collecte et analyse les preuves numériques dans le respect de la chaîne de custody | Forensics (disque, mémoire, réseau), outils spécialisés (Autopsy, Volatility, FTK), rigueur méthodologique |
| **Threat Hunter** | Recherche proactive de menaces non détectées par les outils automatisés | Threat intelligence, hypothèses d'attaque, analyse comportementale, connaissance avancée de MITRE ATT&CK |
| **Responsable communication** | Gère la communication interne et externe (médias, clients, régulateurs) | Communication de crise, connaissance réglementaire, rédaction |

### Organisation typique d'un SOC/CSIRT

```
                    ┌─────────────────┐
                    │  CISO / RSSI    │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │ Incident Manager│
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
  ┌───────┴───────┐  ┌──────┴──────┐  ┌────────┴────────┐
  │  SOC (L1/L2)  │  │ CSIRT (L3)  │  │ Forensics &     │
  │  Détection &  │  │ Réponse &   │  │ Threat Hunting  │
  │  Triage       │  │ Remédiation │  │                 │
  └───────────────┘  └─────────────┘  └─────────────────┘
```

---

## Classification des incidents

Classifier un incident permet de mobiliser les bonnes ressources et d'appliquer le bon playbook de réponse. Les incidents sont généralement catégorisés par type et par niveau de sévérité.

### Catégories d'incidents

| Catégorie | Description | Exemples | Vecteur typique |
|-----------|-------------|----------|-----------------|
| **Malware** | Logiciel malveillant exécuté sur un ou plusieurs systèmes | Trojan, worm, spyware, cryptominer | Pièce jointe email, téléchargement drive-by, clé USB |
| **Ransomware** | Malware qui chiffre les données et demande une rançon | LockBit, BlackCat/ALPHV, Cl0p | Phishing ciblé, exploitation de vulnérabilités, RDP exposé |
| **Phishing** | Tentative de vol d'identifiants ou d'installation de malware via ingénierie sociale | Spear-phishing, Business Email Compromise (BEC), smishing | Email frauduleux, SMS, appel téléphonique |
| **DDoS** | Attaque visant à rendre un service indisponible par saturation | DDoS volumétrique, applicatif (Layer 7), amplification DNS | Botnet, services DDoS-as-a-Service |
| **Data Breach** | Fuite ou exfiltration de données sensibles | Vol de base de données clients, exfiltration de propriété intellectuelle | Exploitation de vulnérabilité, accès non autorisé, erreur de configuration |
| **Insider Threat** | Menace interne provenant d'un employé, prestataire ou partenaire | Vol de données par un employé mécontent, négligence, espionnage industriel | Accès légitime détourné, abus de privilèges |
| **Compromission de compte** | Accès non autorisé à un compte utilisateur ou administrateur | Credential stuffing, brute force, vol de session | Identifiants volés, absence de MFA |
| **Exploitation de vulnérabilité** | Exploitation d'une faille technique dans un système ou une application | Zero-day, exploitation de CVE connue | Scan de vulnérabilités, exploit kit |

### Niveaux de sévérité

La classification par sévérité (souvent appelée "priorité") détermine la rapidité et l'intensité de la réponse. Voici un modèle en 4 niveaux couramment utilisé.

| Niveau | Nom | Critères | Délai de réponse | Exemples |
|--------|-----|----------|-------------------|----------|
| **P1** | Critique | Impact majeur sur l'activité, données sensibles compromises, systèmes critiques indisponibles, propagation active | Immédiat (< 15 min) | Ransomware actif sur le réseau, exfiltration de données en cours, compromission d'un DC Active Directory |
| **P2** | Élevé | Impact significatif mais limité, systèmes importants affectés, risque de propagation | < 1 heure | Malware détecté sur plusieurs postes, compromission d'un compte à privilèges, phishing réussi avec vol d'identifiants |
| **P3** | Modéré | Impact limité, systèmes non critiques affectés, pas de propagation observée | < 4 heures | Malware isolé sur un poste, tentative de phishing sans compromission, scan de ports suspect |
| **P4** | Faible | Impact minimal, événement suspect nécessitant une investigation | < 24 heures | Email de phishing bloqué par le filtre, alerte de politique de sécurité, comportement inhabituel d'un utilisateur |

> **Attention** : ces niveaux de sévérité doivent être adaptés au contexte de chaque organisation. Un incident P3 dans une entreprise peut être un P1 dans une autre selon la criticité des systèmes affectés.

---

## La chaîne de communication lors d'un incident

Une communication efficace est aussi importante que les actions techniques. Un incident mal communiqué peut aggraver la situation, créer de la panique ou exposer l'organisation à des risques juridiques.

### Matrice d'escalade

| Niveau de sévérité | Qui est notifié | Délai de notification | Canal |
|--------------------|-----------------|----------------------|-------|
| **P4 - Faible** | Analyste SOC L1/L2, team lead SOC | Notification dans le ticket | Outil de ticketing (JIRA, ServiceNow) |
| **P3 - Modéré** | Team lead SOC, Incident Manager | < 1 heure | Email + ticket |
| **P2 - Élevé** | Incident Manager, RSSI, responsables métier concernés | < 30 min | Appel téléphonique + email |
| **P1 - Critique** | RSSI, Direction Générale, juridique, communication, autorités si nécessaire | Immédiat | Appel téléphonique, cellule de crise activée |

### Principes de communication de crise

1. **Canal sécurisé** : ne communiquez pas sur les systèmes potentiellement compromis. Utilisez des canaux hors bande (téléphone personnel, messagerie externe).
2. **Need-to-know** : limitez les informations au strict nécessaire selon l'interlocuteur.
3. **Factuel** : communiquez uniquement les faits confirmés, pas les suppositions.
4. **Traçabilité** : documentez toutes les communications (qui, quand, quoi).
5. **Porte-parole unique** : désignez une seule personne pour la communication externe.

### Les parties prenantes

| Partie prenante | Rôle dans la communication | Quand notifier |
|----------------|---------------------------|----------------|
| **Direction Générale** | Décisions stratégiques, validation des communications externes | P1 et P2 |
| **Service juridique** | Conseil sur les obligations légales, gestion des litiges | P1, P2 et tout incident impliquant des données personnelles |
| **Communication / RP** | Communication externe (médias, clients) | P1 avec impact public |
| **DPO** | Évaluation RGPD, notification CNIL si nécessaire | Tout incident impliquant des données personnelles |
| **Métiers concernés** | Évaluation de l'impact business, continuité d'activité | Selon le périmètre de l'incident |
| **Autorités (ANSSI, CNIL)** | Notification réglementaire | Selon les obligations légales |

---

## Aspects légaux et réglementaires

En France et en Europe, la réponse aux incidents s'inscrit dans un cadre légal strict. Ne pas le respecter peut entraîner des sanctions lourdes, en plus des conséquences de l'incident lui-même.

### RGPD - Notification des violations de données

Le **Règlement Général sur la Protection des Données** (RGPD) impose des obligations précises en cas de violation de données personnelles.

| Obligation | Détail | Délai |
|-----------|--------|-------|
| **Notification à la CNIL** | Obligatoire sauf si la violation n'est pas susceptible d'engendrer un risque pour les droits et libertés des personnes | **72 heures** après avoir eu connaissance de la violation |
| **Notification aux personnes concernées** | Obligatoire si la violation est susceptible d'engendrer un risque élevé pour les droits et libertés | Dans les meilleurs délais |
| **Documentation** | Toute violation doit être documentée dans un registre interne | Permanente |
| **Sanctions** | Amende pouvant aller jusqu'à 20 millions d'euros ou 4% du CA mondial | En cas de non-conformité |

### Obligations ANSSI pour les OIV et OSE

| Statut | Signification | Obligation | Base légale |
|--------|--------------|------------|-------------|
| **OIV** | Opérateur d'Importance Vitale | Notification obligatoire à l'ANSSI des incidents de sécurité affectant leurs systèmes d'information d'importance vitale (SIIV) | Loi de Programmation Militaire (LPM) 2013 |
| **OSE** | Opérateur de Services Essentiels | Notification obligatoire à l'ANSSI des incidents ayant un impact significatif sur la continuité des services essentiels | Directive NIS / NIS2 |
| **Entités essentielles et importantes** | Catégories élargies par NIS2 | Obligations renforcées de notification (alerte précoce 24h, notification 72h, rapport final 1 mois) | Directive NIS2 (2024) |

### Autres cadres réglementaires

- **DORA** (Digital Operational Resilience Act) : pour le secteur financier, impose des obligations de gestion des incidents ICT.
- **HDS** (Hébergeur de Données de Santé) : obligations spécifiques pour les données de santé.
- **PCI-DSS** : standard pour les données de carte de paiement, impose une réponse aux incidents formalisée.

---

## KPIs de l'incident response

Mesurer l'efficacité de votre réponse aux incidents est indispensable pour s'améliorer. Trois indicateurs clés sont universellement utilisés.

| KPI | Signification | Définition | Objectif typique |
|-----|--------------|------------|-----------------|
| **MTTD** | Mean Time To Detect | Temps moyen entre le début de l'incident et sa détection | Le plus court possible (< 24h pour les incidents majeurs) |
| **MTTR** | Mean Time To Respond | Temps moyen entre la détection de l'incident et le début de la réponse | < 1h pour P1, < 4h pour P2 |
| **MTTC** | Mean Time To Contain | Temps moyen entre la détection et le confinement effectif de l'incident | < 4h pour P1, < 24h pour P2 |

### Autres métriques utiles

| Métrique | Description |
|---------|-------------|
| **Nombre d'incidents par catégorie** | Permet d'identifier les tendances et d'adapter les défenses |
| **Taux de faux positifs** | Pourcentage d'alertes qui ne sont pas de vrais incidents (à minimiser) |
| **Coût moyen par incident** | Permet de justifier les investissements en sécurité |
| **Taux de récurrence** | Pourcentage d'incidents similaires qui se reproduisent (mesure l'efficacité des leçons apprises) |
| **Temps de restauration complet** | Temps nécessaire pour revenir à un état opérationnel normal |

### Exemple de tableau de bord IR

```
┌─────────────────────────────────────────────────────────┐
│              TABLEAU DE BORD IR - Mars 2026              │
├──────────────────┬──────────────────────────────────────┤
│ Incidents P1     │  1  (MTTD: 2h, MTTC: 6h)            │
│ Incidents P2     │  4  (MTTD: 8h, MTTC: 18h)           │
│ Incidents P3     │ 12  (MTTD: 24h, MTTC: 48h)          │
│ Incidents P4     │ 34  (traités dans les SLA)           │
├──────────────────┼──────────────────────────────────────┤
│ Faux positifs    │ 23% (objectif: < 20%)                │
│ Taux récurrence  │  8% (objectif: < 5%)                 │
│ Playbooks exécutés│ 51                                  │
└──────────────────┴──────────────────────────────────────┘
```

---

## Mise en situation : déroulement d'un incident type

Pour illustrer l'ensemble des concepts de ce cours, voici le déroulement chronologique d'un incident de type ransomware dans une entreprise fictive.

| Heure | Événement | Phase (NIST) | Phase (SANS) |
|-------|-----------|-------------|-------------|
| 09:12 | Un employé clique sur un lien dans un email de phishing | - | - |
| 09:15 | Le malware s'installe et commence un mouvement latéral | - | - |
| 11:45 | Le SIEM génère une alerte sur un comportement réseau anormal | Détection & Analyse | Identification |
| 11:50 | L'analyste SOC L1 trie l'alerte et l'escalade au L2 | Détection & Analyse | Identification |
| 12:15 | L'analyste L2 confirme l'incident : ransomware actif, classé P1 | Détection & Analyse | Identification |
| 12:20 | L'Incident Manager est notifié, cellule de crise activée | Détection & Analyse | Identification |
| 12:30 | Les machines infectées sont isolées du réseau | Confinement, Érad. & Récup. | Confinement |
| 13:00 | Le segment réseau touché est segmenté | Confinement, Érad. & Récup. | Confinement |
| 14:00 | Le malware est identifié, les IOCs sont partagés | Confinement, Érad. & Récup. | Éradication |
| 15:00 | Les systèmes compromis sont nettoyés, les vulnérabilités patchées | Confinement, Érad. & Récup. | Éradication |
| 16:00 | Restauration depuis les backups, monitoring renforcé | Confinement, Érad. & Récup. | Récupération |
| J+2 | Vérification que tous les systèmes fonctionnent normalement | Confinement, Érad. & Récup. | Récupération |
| J+5 | Réunion post-incident, rapport final, mise à jour des playbooks | Activité post-incident | Leçons apprises |
| J+5 | Notification CNIL (dans les 72h, si données personnelles impactées) | Activité post-incident | Leçons apprises |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **IR** | Incident Response - Réponse aux incidents |
| **CSIRT** | Computer Security Incident Response Team - Équipe de réponse aux incidents de sécurité informatique |
| **CERT** | Computer Emergency Response Team - Équipe de réponse aux urgences informatiques (marque déposée CERT/CC) |
| **SOC** | Security Operations Center - Centre des opérations de sécurité |
| **SIEM** | Security Information and Event Management - Gestion des informations et événements de sécurité |
| **EDR** | Endpoint Detection and Response - Détection et réponse sur les endpoints |
| **NIST** | National Institute of Standards and Technology - Institut national des normes et de la technologie (USA) |
| **SANS** | SysAdmin, Audit, Network, and Security - Institut de formation en cybersécurité |
| **PICERL** | Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned - Mnémonique SANS |
| **MTTD** | Mean Time To Detect - Temps moyen de détection |
| **MTTR** | Mean Time To Respond - Temps moyen de réponse |
| **MTTC** | Mean Time To Contain - Temps moyen de confinement |
| **IOC** | Indicator of Compromise - Indicateur de compromission |
| **TTP** | Tactics, Techniques, and Procedures - Tactiques, techniques et procédures d'un attaquant |
| **RGPD** | Règlement Général sur la Protection des Données |
| **CNIL** | Commission Nationale de l'Informatique et des Libertés |
| **ANSSI** | Agence Nationale de la Sécurité des Systèmes d'Information |
| **OIV** | Opérateur d'Importance Vitale |
| **OSE** | Opérateur de Services Essentiels |
| **NIS2** | Network and Information Security Directive 2 - Directive européenne sur la sécurité des réseaux et de l'information |
| **DORA** | Digital Operational Resilience Act - Règlement sur la résilience opérationnelle numérique |
| **DPO** | Data Protection Officer - Délégué à la protection des données |
| **RSSI** | Responsable de la Sécurité des Systèmes d'Information |
| **BEC** | Business Email Compromise - Compromission de messagerie d'entreprise |
| **DDoS** | Distributed Denial of Service - Déni de service distribué |
| **MFA** | Multi-Factor Authentication - Authentification multifacteur |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Intro to IR and IM](https://tryhackme.com/room/dvintrotoimandcybir) | Introduction à la réponse aux incidents et à la gestion des incidents : concepts fondamentaux, rôles et processus |
| TryHackMe | [Incident Response Fundamentals](https://tryhackme.com/room/dvincidentresponsefundamentals) | Les fondamentaux de la réponse aux incidents : cycle de vie, détection, analyse et phases de réponse |
| HackTheBox | [Sherlock - Brutus](https://app.hackthebox.com/sherlocks/Brutus) | Exercice DFIR : analysez les traces d'une attaque par brute force pour reconstituer la chronologie de l'incident |

---

## Ressources

- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide : [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- SANS Incident Handler's Handbook : [sans.org](https://www.sans.org/white-papers/33901/)
- MITRE ATT&CK Framework : [attack.mitre.org](https://attack.mitre.org/)
- ANSSI - Guide de gestion de crise cyber : [cyber.gouv.fr](https://cyber.gouv.fr/publications/crise-dorigine-cyber-les-cles-dune-gestion-operationnelle-et-strategique)
- IBM Cost of a Data Breach Report 2024 : [ibm.com](https://www.ibm.com/reports/data-breach)
- RGPD - Notification de violations de données : [cnil.fr](https://www.cnil.fr/fr/les-violations-de-donnees-personnelles)
