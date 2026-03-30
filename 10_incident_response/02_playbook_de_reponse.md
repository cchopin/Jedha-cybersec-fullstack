# Playbook de réponse

**Durée : 40 min**

## Ce que vous allez apprendre dans ce cours

Savoir qu'il faut répondre à un incident ne suffit pas : il faut savoir **comment** répondre, étape par étape, sans improviser sous la pression. C'est exactement le rôle d'un playbook de réponse aux incidents. Dans cette leçon, vous apprendrez :

- ce qu'est un playbook de réponse et pourquoi il est indispensable,
- la différence entre playbook, runbook et procédure,
- comment structurer un playbook efficace,
- les playbooks adaptés à chaque type d'incident (ransomware, phishing, data breach, DDoS),
- les phases détaillées de confinement, éradication et récupération,
- la documentation et la chaîne de preuve (chain of custody),
- comment conduire une post-incident review,
- les principes d'automatisation avec SOAR.

---

## Qu'est-ce qu'un playbook de réponse aux incidents ?

Un **playbook de réponse aux incidents** est un document structuré qui décrit les étapes précises à suivre lorsqu'un type spécifique d'incident de sécurité est détecté. Il fournit un guide pas-à-pas pour chaque phase de la réponse, de la détection à la clôture.

### Pourquoi les playbooks sont indispensables

| Sans playbook | Avec playbook |
|--------------|---------------|
| Réponse improvisée, dépendante des individus présents | Réponse standardisée et reproductible |
| Risque d'oublier des étapes critiques sous la pression | Checklist complète, rien n'est oublié |
| Temps de réponse variable et souvent trop long | Temps de réponse optimisé et prévisible |
| Difficulté à former les nouveaux membres de l'équipe | Support de formation intégré |
| Pas de traçabilité des actions effectuées | Documentation systématique des actions |
| Pas d'amélioration continue possible | Base pour les retours d'expérience et l'optimisation |

> **Analogie** : un playbook IR est comparable aux protocoles d'urgence des services de secours. Quand les pompiers arrivent sur un incendie, ils ne se demandent pas "que fait-on ?" : ils appliquent un protocole rodé, adapté au type de sinistre.

---

## Playbook, runbook et procédure : les différences

Ces trois termes sont souvent confondus. Voici ce qui les distingue.

| Document | Définition | Niveau de détail | Public cible | Exemple |
|----------|------------|-------------------|-------------|---------|
| **Playbook** | Guide stratégique et tactique décrivant les étapes à suivre pour un type d'incident donné. Inclut les arbres de décision et les critères d'escalade. | Moyen à élevé | Incident Manager, analystes L2/L3 | "Playbook Ransomware" décrivant la stratégie globale de réponse |
| **Runbook** | Guide opérationnel détaillé, étape par étape, pour exécuter une tâche technique spécifique. Peut être automatisé. | Très élevé (step-by-step) | Analystes L1/L2, opérateurs | "Isoler un poste du réseau via l'EDR" avec les clics exacts à effectuer |
| **Procédure** | Document formel décrivant un processus organisationnel. Cadre les rôles, responsabilités et règles générales. | Faible à moyen | Management, toute l'organisation | "Procédure de gestion des incidents de sécurité" validée par la direction |

### Comment ils s'articulent

```
┌─────────────────────────────────────────────┐
│           PROCÉDURE (niveau politique)      │
│  "Tout incident doit être traité selon      │
│   le framework NIST SP 800-61"              │
└─────────────────────┬───────────────────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
┌────────┴────────┐     ┌─────────┴────────┐
│ PLAYBOOK        │     │ PLAYBOOK         │
│ Ransomware      │     │ Phishing         │
│ (stratégie IR)  │     │ (stratégie IR)   │
└────────┬────────┘     └─────────┬────────┘
         │                         │
    ┌────┴────┐              ┌────┴────┐
    │         │              │         │
┌───┴───┐ ┌───┴────┐    ┌────┴──┐ ┌────┴───┐
│RUNBOOK│ │RUNBOOK │    │RUNBOOK│ │RUNBOOK │
│Isoler │ │Collect.│    │Analyse│ │Reset   │
│poste  │ │preuves │    │header │ │MDP     │
└───────┘ └────────┘    └───────┘ └────────┘
```

---

## Structure d'un playbook type

Chaque playbook doit suivre une structure cohérente pour être facilement utilisable en situation de crise. Voici la structure recommandée.

### Les composants essentiels

| Section | Contenu | Obligatoire |
|---------|---------|-------------|
| **Métadonnées** | Nom, version, date de dernière mise à jour, auteur, approbateur | Oui |
| **Déclencheur (Trigger)** | Quel événement ou alerte déclenche l'exécution de ce playbook | Oui |
| **Conditions d'applicabilité** | Dans quelles conditions ce playbook s'applique (et ne s'applique pas) | Oui |
| **Prérequis** | Outils, accès et informations nécessaires pour exécuter le playbook | Oui |
| **Niveaux de sévérité** | Comment évaluer la sévérité de l'incident dans ce contexte spécifique | Oui |
| **Actions de réponse** | Étapes détaillées de la réponse, phase par phase | Oui |
| **Critères d'escalade** | Quand et à qui escalader | Oui |
| **Communication** | Qui informer, quand, et par quel canal | Oui |
| **Critères de clôture** | Conditions qui doivent être remplies pour considérer l'incident comme résolu | Oui |
| **Annexes** | IOCs connus, contacts, références techniques | Recommandé |

### Exemple de métadonnées

```
┌──────────────────────────────────────────────┐
│  PLAYBOOK: Réponse à un incident Ransomware  │
├──────────────────────────────────────────────┤
│  Version      : 2.3                          │
│  Date MAJ     : 2026-02-15                   │
│  Auteur       : Équipe CSIRT                 │
│  Approbateur  : RSSI                         │
│  Classification: Interne - Confidentiel      │
│  Prochaine revue: 2026-08-15                 │
└──────────────────────────────────────────────┘
```

---

## Playbooks par type d'incident

### Playbook Ransomware

Le ransomware est l'un des incidents les plus destructeurs. La réponse doit être rapide et méthodique. Voici les étapes clés.

| Phase | Actions | Points d'attention |
|-------|---------|-------------------|
| **Déclencheur** | Alerte EDR sur chiffrement massif de fichiers, demande de rançon affichée, extension de fichiers modifiée | Faux positif possible avec certains logiciels de compression/chiffrement légitimes |
| **Évaluation initiale** | Identifier le variant de ransomware, évaluer le périmètre touché, vérifier si l'exfiltration a précédé le chiffrement (double extorsion) | Utiliser ID Ransomware (id-ransomware.malwarehunterteam.com) |
| **Confinement immédiat** | Isoler les machines infectées du réseau (ne PAS les éteindre), bloquer les communications C2, désactiver les partages réseau | Préserver la mémoire vive pour l'analyse forensique |
| **Préservation des preuves** | Capturer la RAM, copier les logs, photographier les écrans de rançon | Respecter la chaîne de custody |
| **Éradication** | Identifier et supprimer le malware, patcher la vulnérabilité exploitée, réinitialiser tous les mots de passe compromis | Vérifier l'absence de persistence (tâches planifiées, services, clés de registre) |
| **Récupération** | Restaurer depuis des sauvegardes vérifiées (non chiffrées), réinstaller les systèmes si nécessaire | Tester les backups avant restauration, surveillance renforcée post-restauration |
| **Communication** | Notifier la direction, le juridique, les autorités (ANSSI, dépôt de plainte), CNIL si données personnelles | **Ne jamais communiquer publiquement que vous payez ou envisagez de payer** |

#### Règles fondamentales face à un ransomware

1. **Ne pas payer la rançon** : le paiement finance les criminels, ne garantit pas la récupération des données, et peut exposer à des sanctions (financement du terrorisme si le groupe est listé).
2. **Ne pas éteindre les machines** : la mémoire vive peut contenir la clé de chiffrement ou des preuves précieuses.
3. **Isoler, ne pas déconnecter brutalement** : débrancher le câble réseau ou désactiver le Wi-Fi, mais garder la machine allumée.
4. **Contacter les autorités** : ANSSI (via cert-fr@ssi.gouv.fr), dépôt de plainte auprès de la police/gendarmerie.
5. **Vérifier les sauvegardes avant de restaurer** : s'assurer qu'elles ne sont pas elles-mêmes compromises.

### Playbook Phishing

| Phase | Actions | Points d'attention |
|-------|---------|-------------------|
| **Déclencheur** | Signalement utilisateur, alerte de la passerelle email, détection par le SIEM d'une connexion suspecte | Encourager la culture du signalement (bouton "Report Phishing" dans le client mail) |
| **Analyse de l'email** | Examiner les en-têtes (SPF, DKIM, DMARC), analyser les URLs (sandbox, VirusTotal), vérifier les pièces jointes dans un environnement isolé | Ne jamais ouvrir les pièces jointes sur un poste de production |
| **Recherche d'IOCs** | Extraire les IOCs (URL, domaine, IP, hash), rechercher dans le SIEM si d'autres utilisateurs ont reçu le même email | Rechercher aussi les variantes du même email |
| **Évaluation de l'impact** | Identifier qui a cliqué, qui a saisi des identifiants, qui a ouvert la pièce jointe | Analyser les logs proxy et d'authentification |
| **Confinement** | Bloquer l'expéditeur et les URLs/domaines malveillants, isoler les postes compromis, supprimer l'email de toutes les boîtes de réception (purge) | Utiliser les outils d'administration Exchange/M365 pour la purge |
| **Éradication** | Réinitialiser les mots de passe des comptes compromis, révoquer les sessions actives, scanner les postes pour détecter un éventuel malware | Forcer le MFA si ce n'est pas déjà en place |
| **Récupération** | Restaurer les accès, surveiller les comptes compromis, vérifier l'absence d'activité suspecte | Surveillance renforcée pendant 30 jours |
| **Communication** | Informer les utilisateurs de la campagne de phishing, rappeler les bonnes pratiques | Transformer l'incident en opportunité de sensibilisation |

### Playbook Data Breach

| Phase | Actions | Points d'attention |
|-------|---------|-------------------|
| **Déclencheur** | Alerte DLP, découverte de données sur le dark web, notification d'un tiers, alerte SIEM sur exfiltration | Parfois découvert des semaines ou mois après la compromission |
| **Identification des données** | Déterminer quelles données sont exposées (personnelles, financières, médicales, propriété intellectuelle), volume, et sensibilité | Classification des données indispensable en amont |
| **Évaluation de l'impact** | Nombre de personnes affectées, type de données, risque pour les personnes concernées | Impliquer le DPO et le juridique immédiatement |
| **Confinement** | Bloquer la source de la fuite, révoquer les accès compromis, isoler les systèmes concernés | Préserver les preuves avant toute action corrective |
| **Notification RGPD** | Notifier la CNIL sous 72h si risque pour les personnes, notifier les personnes concernées si risque élevé | Documenter la chronologie et les décisions prises |
| **Forensics** | Analyser comment la fuite s'est produite, identifier la cause racine, déterminer la timeline | Faire appel à un prestataire forensique externe si nécessaire |
| **Récupération** | Corriger la vulnérabilité, renforcer les contrôles d'accès, améliorer le monitoring | Vérifier qu'il n'y a pas d'autres voies d'exfiltration |

### Playbook DDoS

| Phase | Actions | Points d'attention |
|-------|---------|-------------------|
| **Déclencheur** | Indisponibilité de service, alertes de monitoring (latence, taux d'erreurs), notification du FAI ou hébergeur | Distinguer DDoS d'une surcharge légitime (pic de trafic) |
| **Évaluation** | Identifier le type d'attaque (volumétrique, protocolaire, applicatif L7), mesurer le volume, identifier les sources | Un DDoS peut servir de diversion pour masquer une autre attaque |
| **Confinement immédiat** | Activer les protections WAF/CDN (mode "under attack"), activer le rate limiting, contacter le FAI pour filtrage en amont | Avoir des contacts FAI prédéfinis dans le playbook |
| **Mitigation** | Activer le service anti-DDoS (Cloudflare, Akamai, AWS Shield), appliquer des règles de filtrage géographique si pertinent, blackholer les IPs sources si identifiables | La mitigation doit être progressive pour ne pas bloquer le trafic légitime |
| **Récupération** | Désactiver progressivement les mesures de mitigation, surveiller le retour à la normale, vérifier qu'aucune autre attaque n'a eu lieu pendant le DDoS | Certains DDoS sont des attaques en plusieurs vagues |
| **Post-incident** | Analyser les logs, ajuster les seuils de détection, mettre à jour le plan de capacité | Envisager un service anti-DDoS permanent si pas encore en place |

---

## Les phases détaillées : Confinement, Éradication, Récupération

Ces trois phases sont le coeur opérationnel de la réponse à un incident. Chacune mérite une attention particulière.

### Confinement

Le confinement vise à empêcher l'incident de se propager davantage. Il se décompose en deux étapes.

| Type | Objectif | Actions typiques | Délai |
|------|----------|-----------------|-------|
| **Confinement court terme** | Stopper la propagation immédiate | Isoler le poste du réseau, bloquer le compte compromis, bloquer l'IP/domaine malveillant au firewall | Minutes |
| **Confinement long terme** | Stabiliser la situation pour permettre l'éradication | Segmenter le réseau, appliquer des règles firewall temporaires, rediriger le trafic, mettre en place un monitoring renforcé | Heures |

> **Attention** : le confinement doit être proportionné. Isoler un segment réseau entier pour un malware sur un seul poste peut causer plus de dommages que l'incident lui-même.

### Éradication

L'éradication consiste à supprimer complètement la menace de l'environnement.

| Action | Détail | Vérification |
|--------|--------|-------------|
| **Suppression du malware** | Utiliser l'EDR/antivirus pour supprimer le malware, ou réimager le poste si nécessaire | Scanner l'ensemble du parc avec les IOCs identifiés |
| **Patch des vulnérabilités** | Corriger la vulnérabilité exploitée par l'attaquant pour le compromission initiale | Vérifier que le patch est effectif et n'introduit pas de régression |
| **Reset des credentials** | Réinitialiser les mots de passe de tous les comptes potentiellement compromis | Forcer le changement au prochain login, révoquer les tokens/sessions |
| **Suppression des backdoors** | Rechercher et supprimer les mécanismes de persistence (tâches planifiées, services, clés de registre, webshells) | Audit complet des mécanismes de persistence connus |
| **Nettoyage des IOCs** | Supprimer les fichiers, clés de registre et artefacts laissés par l'attaquant | Comparer avec un état connu sain (baseline) |

### Récupération

La récupération est la phase de retour à la normale, effectuée avec précaution.

| Étape | Détail | Critère de validation |
|-------|--------|----------------------|
| **Restauration des systèmes** | Restaurer depuis des sauvegardes vérifiées ou réinstaller proprement | Les backups ont été testés et ne contiennent pas le malware |
| **Remise en production progressive** | Remettre les systèmes en service un par un, en commençant par les moins critiques | Chaque système restauré est validé avant de passer au suivant |
| **Monitoring renforcé** | Intensifier la surveillance pendant 30 à 90 jours après l'incident | Règles de détection spécifiques aux IOCs et TTPs observés |
| **Validation fonctionnelle** | Vérifier que les services fonctionnent correctement pour les utilisateurs | Tests de validation avec les équipes métier |
| **Retour à la normale** | Lever les mesures d'urgence (segmentation temporaire, restrictions d'accès) | Validation par l'Incident Manager et le RSSI |

---

## Documentation et chaîne de preuve (Chain of Custody)

La documentation est un élément crucial de la réponse aux incidents. Elle sert à la fois pour l'analyse technique, les obligations légales et l'amélioration continue.

### Principes de documentation

| Principe | Description |
|---------|-------------|
| **Exhaustivité** | Documenter toutes les actions effectuées, même celles qui semblent mineures |
| **Chronologie** | Horodater chaque action avec précision (timestamp UTC) |
| **Responsabilité** | Identifier qui a effectué chaque action |
| **Intégrité** | Protéger les documents contre la modification (hash, signature) |
| **Accessibilité** | Les documents doivent être facilement retrouvables et compréhensibles |

### Chaîne de custody (chaîne de preuve)

La chaîne de custody garantit que les preuves numériques collectées sont recevables devant un tribunal. Chaque transfert ou manipulation d'une preuve doit être documenté.

| Champ | Description | Exemple |
|-------|------------|---------|
| **Identifiant de la preuve** | Référence unique | EVD-2026-0042-001 |
| **Description** | Nature de la preuve | Image disque du poste PC-COMPTA-12 |
| **Date/heure de collecte** | Quand la preuve a été collectée | 2026-03-15 14:32 UTC |
| **Collectée par** | Nom et fonction de la personne | Jean Dupont, Forensic Analyst |
| **Méthode de collecte** | Outil et méthode utilisés | Image dd via write-blocker Tableau T35u |
| **Hash d'intégrité** | Empreinte cryptographique | SHA-256: a1b2c3d4e5... |
| **Lieu de stockage** | Où la preuve est conservée | Coffre-fort numérique, salle serveur B2 |
| **Transferts** | Historique de chaque transfert | 2026-03-15 16:00 : remis à Marie Martin pour analyse |

### Journal de bord de l'incident (Incident Log)

Pendant toute la durée de l'incident, un journal de bord doit être tenu en temps réel.

```
┌──────────────────────────────────────────────────────────────┐
│  JOURNAL DE BORD - Incident INC-2026-0042                    │
│  Type: Ransomware | Sévérité: P1 | Statut: En cours          │
├──────────┬────────────┬──────────────────────────────────────┤
│ Heure    │ Auteur     │ Action / Observation                 │
├──────────┼────────────┼──────────────────────────────────────┤
│ 11:45    │ SOC-L1     │ Alerte SIEM: chiffrement massif      │
│          │ (A. Leroy) │ fichiers sur PC-COMPTA-12            │
│ 11:50    │ SOC-L2     │ Escalade confirmée: ransomware       │
│          │ (B. Morel) │ LockBit identifié via extension .lb3 │
│ 11:55    │ SOC-L2     │ Isolation réseau de PC-COMPTA-12     │
│          │ (B. Morel) │ via console EDR CrowdStrike          │
│ 12:00    │ Inc. Mgr   │ Cellule de crise activée             │
│          │ (C. Petit) │ RSSI, juridique, comm. notifiés      │
│ 12:15    │ SOC-L3     │ Scan IOCs sur l'ensemble du parc:    │
│          │ (D. Grand) │ 3 autres postes identifiés, isolés   │
│ ...      │ ...        │ ...                                  │
└──────────┴────────────┴──────────────────────────────────────┘
```

---

## Post-incident review / Lessons learned

La réunion post-incident (aussi appelée "post-mortem" ou "retour d'expérience") est une étape souvent négligée mais essentielle. Elle doit avoir lieu dans les 5 à 10 jours suivant la clôture de l'incident.

### Objectifs

- Comprendre ce qui s'est passé (timeline factuelle)
- Identifier ce qui a bien fonctionné et ce qui doit être amélioré
- Proposer des actions correctives concrètes
- Mettre à jour les playbooks et les procédures
- Renforcer la posture de sécurité globale

### Template de rapport post-incident

| Section | Contenu |
|---------|---------|
| **Résumé exécutif** | Description en 3-5 lignes pour la direction : quoi, quand, impact, statut |
| **Chronologie** | Timeline détaillée de l'incident, de la compromission initiale à la clôture |
| **Cause racine** | Analyse de la cause profonde (root cause analysis) : vulnérabilité exploitée, vecteur d'attaque |
| **Impact** | Systèmes affectés, données compromises, durée d'indisponibilité, coût estimé |
| **Actions de réponse** | Détail des actions prises à chaque phase (détection, confinement, éradication, récupération) |
| **Ce qui a bien fonctionné** | Points positifs : détection rapide, playbook efficace, communication fluide |
| **Ce qui doit être amélioré** | Points à améliorer : détection tardive, playbook incomplet, manque de formation |
| **Actions correctives** | Liste d'actions avec responsable, priorité et date cible |
| **Indicateurs** | MTTD, MTTR, MTTC mesurés pour cet incident |
| **Annexes** | IOCs, logs pertinents, captures d'écran, communications |

### Règles pour une post-incident review efficace

1. **Blameless** : l'objectif est d'améliorer les processus, pas de désigner un coupable. Un environnement bienveillant encourage le signalement transparent.
2. **Factuel** : se baser sur les faits documentés, pas sur les souvenirs ou les impressions.
3. **Inclusif** : inviter toutes les personnes qui ont participé à la réponse.
4. **Orienté action** : chaque constat doit déboucher sur une action corrective assignée et suivie.
5. **Documenté** : le rapport final doit être archivé et accessible pour référence future.

---

## Automatisation avec SOAR

### Qu'est-ce que le SOAR ?

**SOAR** (Security Orchestration, Automation and Response) est une catégorie d'outils qui permet d'automatiser et d'orchestrer les processus de réponse aux incidents. Le SOAR exécute automatiquement les étapes des playbooks, réduisant le temps de réponse et la charge sur les analystes.

### Les trois piliers du SOAR

| Pilier | Description | Exemple |
|--------|------------|---------|
| **Orchestration** | Connecte et coordonne les différents outils de sécurité (SIEM, EDR, firewall, ticketing) via des API | Un incident créé dans le SIEM déclenche automatiquement un ticket dans ServiceNow |
| **Automatisation** | Exécute automatiquement des tâches répétitives sans intervention humaine | Enrichissement automatique des IOCs via VirusTotal et AbuseIPDB |
| **Réponse** | Prend des actions de réponse automatiques ou semi-automatiques | Isolation automatique d'un poste via l'EDR quand un malware est détecté |

### Exemples d'automatisation par playbook

| Playbook | Tâches automatisables | Tâches nécessitant un humain |
|----------|----------------------|----------------------------|
| **Phishing** | Extraction des IOCs de l'email, recherche dans le SIEM, blocage des URLs au proxy, purge de l'email dans les boîtes | Décision de réinitialiser les mots de passe, communication aux utilisateurs |
| **Ransomware** | Isolation réseau du poste via EDR, collecte automatique des logs et de la RAM, scan IOCs sur le parc | Décision de restauration, communication de crise, notification aux autorités |
| **Compromission de compte** | Désactivation du compte, révocation des sessions, enrichissement des IOCs de connexion | Évaluation de l'impact, décision sur le périmètre du reset de mots de passe |
| **DDoS** | Activation des règles WAF pré-configurées, notification au FAI, scaling automatique de l'infrastructure | Décision d'activer le service anti-DDoS payant, communication publique |

### Outils SOAR courants

| Outil | Type | Points forts |
|-------|------|-------------|
| **Splunk SOAR** (ex-Phantom) | Commercial | Intégration native avec Splunk SIEM, large bibliothèque de playbooks |
| **Palo Alto XSOAR** (ex-Demisto) | Commercial | Interface intuitive, marketplace de playbooks et d'intégrations |
| **IBM QRadar SOAR** (ex-Resilient) | Commercial | Gestion avancée des cas, conformité réglementaire intégrée |
| **Shuffle** | Open source | Gratuit, interface visuelle de création de workflows, API REST |
| **TheHive + Cortex** | Open source | Gestion de cas (TheHive) + analyse automatisée d'observables (Cortex) |

---

## Exemple concret : playbook ransomware en flowchart

Voici un playbook ransomware complet sous forme de diagramme de décision.

```
                    ┌───────────────────────────┐
                    │  ALERTE: Comportement de  │
                    │  chiffrement détecté (EDR)│
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │  Analyste L1: Vérifier    │
                    │  l'alerte (faux positif ?)│
                    └─────────────┬─────────────┘
                                  │
                         ┌────────┴────────┐
                         │                 │
                    Faux positif       Confirmé
                         │                 │
                         ▼                 ▼
                   ┌──────────┐   ┌────────────────────┐
                   │ Clôturer │   │ Escalade L2/L3     │
                   │ l'alerte │   │ Classer en P1      │
                   └──────────┘   └────────┬───────────┘
                                           │
                                           ▼
                                  ┌─────────────────────┐
                                  │ CONFINEMENT         │
                                  │ 1. Isoler le poste  │
                                  │    (NE PAS éteindre)│
                                  │ 2. Bloquer C2 au FW │
                                  │ 3. Désactiver les   │
                                  │    partages réseau  │
                                  └────────┬────────────┘
                                           │
                                           ▼
                                  ┌─────────────────────┐
                                  │ NOTIFICATION        │
                                  │ 1. Incident Manager │
                                  │ 2. RSSI             │
                                  │ 3. Direction        │
                                  │ 4. Juridique        │
                                  └────────┬────────────┘
                                           │
                                           ▼
                              ┌────────────┴────────────┐
                              │                         │
                     Données perso ?              Pas de données
                     impactées                    personnelles
                              │                         │
                              ▼                         │
                    ┌─────────────────┐                 │
                    │ Notifier CNIL   │                 │
                    │ sous 72h        │                 │
                    │ Préparer notif. │                 │
                    │ personnes       │                 │
                    └────────┬────────┘                 │
                             │                          │
                             └─────────────┬────────────┘
                                           │
                                           ▼
                                  ┌─────────────────────┐
                                  │ PRÉSERVATION PREUVES│
                                  │ 1. Capture RAM      │
                                  │ 2. Image disque     │
                                  │ 3. Copie des logs   │
                                  │ 4. Chain of custody │
                                  └────────┬────────────┘
                                           │
                                           ▼
                                  ┌─────────────────────┐
                                  │ ÉRADICATION         │
                                  │ 1. Identifier le    │
                                  │    variant          │
                                  │ 2. Supprimer malware│
                                  │ 3. Chercher         │
                                  │    persistence      │
                                  │ 4. Patcher la vuln. │
                                  │ 5. Reset credentials│
                                  └────────┬────────────┘
                                           │
                                           ▼
                              ┌────────────┴────────────┐
                              │                         │
                     Backups sains             Pas de backup
                     disponibles ?             ou corrompus
                              │                         │
                              ▼                         ▼
                    ┌─────────────────┐    ┌─────────────────┐
                    │ Restaurer depuis│    │ Réinstallation  │
                    │ les backups     │    │ complète        │
                    │ (après test)    │    │ Perte de données│
                    └────────┬────────┘    │ possible        │
                             │             └────────┬────────┘
                             │                      │
                             └──────────┬───────────┘
                                        │
                                        ▼
                                ┌─────────────────────┐
                                │ RÉCUPÉRATION        │
                                │ 1. Remise en prod   │
                                │    progressive      │
                                │ 2. Monitoring       │
                                │    renforcé (90j)   │
                                │ 3. Validation métier│
                                └────────┬────────────┘
                                         │
                                         ▼
                                ┌────────────────────┐
                                │ POST-INCIDENT      │
                                │ 1. Réunion retex   │
                                │ 2. Rapport final   │
                                │ 3. MAJ playbooks   │
                                │ 4. Actions correc. │
                                │ 5. Dépôt de plainte│
                                └────────────────────┘
```

---

## Bonnes pratiques pour la création de playbooks

| Bonne pratique | Détail |
|---------------|--------|
| **Tester régulièrement** | Exécuter des exercices de simulation (tabletop exercises) au moins 2 fois par an |
| **Maintenir à jour** | Revoir chaque playbook tous les 6 mois et après chaque incident majeur |
| **Garder la simplicité** | Un playbook trop complexe ne sera pas suivi en situation de crise |
| **Impliquer les parties prenantes** | Les playbooks doivent être validés par les équipes techniques, le management et le juridique |
| **Versionner** | Utiliser un système de gestion de versions pour suivre les modifications |
| **Rendre accessible** | Les playbooks doivent être accessibles hors ligne et hors des systèmes potentiellement compromis |
| **Adapter au contexte** | Un playbook générique doit être adapté aux spécificités de votre organisation |
| **Inclure des critères de décision** | Les arbres de décision évitent la paralysie en situation de stress |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Playbook** | Guide structuré décrivant les étapes de réponse à un type d'incident spécifique |
| **Runbook** | Guide opérationnel détaillé pour l'exécution d'une tâche technique spécifique |
| **SOAR** | Security Orchestration, Automation and Response - Orchestration, automatisation et réponse de sécurité |
| **Chain of Custody** | Chaîne de custody - Documentation traçant la possession et la manipulation des preuves numériques |
| **IOC** | Indicator of Compromise - Indicateur de compromission (hash, IP, domaine, URL malveillant) |
| **TTP** | Tactics, Techniques, and Procedures - Comportements et méthodes d'un attaquant (référencés dans MITRE ATT&CK) |
| **EDR** | Endpoint Detection and Response - Outil de détection et réponse sur les terminaux |
| **DLP** | Data Loss Prevention - Prévention de la perte de données |
| **WAF** | Web Application Firewall - Pare-feu applicatif web |
| **CDN** | Content Delivery Network - Réseau de diffusion de contenu |
| **FAI** | Fournisseur d'Accès Internet |
| **C2** | Command and Control - Serveur de commande et contrôle utilisé par un malware |
| **MFA** | Multi-Factor Authentication - Authentification multifacteur |
| **SPF** | Sender Policy Framework - Mécanisme d'authentification email |
| **DKIM** | DomainKeys Identified Mail - Signature cryptographique des emails |
| **DMARC** | Domain-based Message Authentication, Reporting and Conformance - Politique d'authentification email |
| **BEC** | Business Email Compromise - Fraude par compromission de messagerie d'entreprise |
| **Post-mortem** | Analyse rétrospective d'un incident pour en tirer les leçons |
| **Tabletop exercise** | Exercice de simulation sur table d'un scénario d'incident |
| **Root Cause Analysis** | Analyse de la cause racine d'un incident |
| **Blameless** | Approche "sans blâme" pour les retours d'expérience post-incident |

---

## Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Preparation](https://tryhackme.com/room/dvpreparationir) | Phase de préparation de la réponse aux incidents : construction des playbooks, outils, et équipes |
| TryHackMe | [DFIR: An Introduction](https://tryhackme.com/room/dvintroductiontodfir) | Introduction au Digital Forensics and Incident Response : méthodologie, outils et processus |
| HackTheBox | [Sherlock - Litter](https://app.hackthebox.com/sherlocks/Litter) | Exercice DFIR : analysez les traces réseau et systèmes d'un incident pour reconstituer l'attaque |

---

## Ressources

- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide : [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- SANS Incident Handler's Handbook : [sans.org](https://www.sans.org/white-papers/33901/)
- ANSSI - Guide de gestion de crise cyber : [cyber.gouv.fr](https://cyber.gouv.fr/publications/crise-dorigine-cyber-les-cles-dune-gestion-operationnelle-et-strategique)
- MITRE ATT&CK Framework : [attack.mitre.org](https://attack.mitre.org/)
- Incident Response Playbook - CISA : [cisa.gov](https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- TheHive Project (SOAR open source) : [thehive-project.org](https://thehive-project.org/)
- Shuffle Automation (SOAR open source) : [shuffler.io](https://shuffler.io/)
