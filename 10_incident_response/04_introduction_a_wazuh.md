# Introduction à Wazuh

**Durée : 40 min**

## Ce que vous allez apprendre dans ce cours

Wazuh est la plateforme open source de sécurité que nous utiliserons tout au long de ce module pour détecter, analyser et répondre aux incidents. Dans cette leçon, vous allez :

- comprendre ce qu'est Wazuh et son positionnement dans l'écosystème des SIEM,
- maîtriser l'architecture complète de Wazuh (server, indexer, dashboard, agents),
- découvrir les fonctionnalités principales : analyse de logs, FIM, détection de vulnérabilités, compliance,
- comprendre le moteur de règles et le système d'alertes (niveaux 0 à 15),
- comparer Wazuh aux autres solutions SIEM du marché.

---

## Qu'est-ce que Wazuh ?

Wazuh est une plateforme de sécurité open source et gratuite qui combine trois fonctions essentielles :

| Fonction | Description |
|----------|-------------|
| **SIEM** (Security Information and Event Management) | Collecte, agrégation, corrélation et analyse des logs de sécurité |
| **XDR** (Extended Detection and Response) | Détection des menaces et réponse automatisée sur les endpoints et au-delà |
| **HIDS** (Host-based Intrusion Detection System) | Surveillance de l'intégrité et détection d'intrusions au niveau des hôtes |

Wazuh est utilisé par des milliers d'organisations dans le monde, des petites entreprises aux grandes entreprises du Fortune 500. Sa nature open source le rend particulièrement attractif pour les organisations qui souhaitent une solution de sécurité complète sans les coûts de licence des solutions commerciales.

### Historique

Wazuh a une histoire intéressante qui explique sa maturité :

| Année | Événement |
|-------|-----------|
| **2004** | Création d'**OSSEC** (Open Source Security), un HIDS open source par Daniel Cid |
| **2015** | Fork d'OSSEC par l'équipe Wazuh pour moderniser et étendre le projet |
| **2016** | Première version stable de Wazuh avec intégration Elastic Stack |
| **2019** | Ajout de fonctionnalités XDR (Vulnerability Detection, SCA) |
| **2022** | Remplacement d'Elasticsearch par OpenSearch (Wazuh Indexer) |
| **2023-2024** | Évolution vers une plateforme unifiée de sécurité avec cloud security |
| **2025** | Version 4.x avec améliorations majeures du moteur de corrélation |

Le fork d'OSSEC a permis à Wazuh de bénéficier de plus de 20 ans de développement de règles de détection tout en modernisant l'architecture, l'interface et les fonctionnalités.

---

## Architecture de Wazuh

Wazuh suit une architecture client-serveur composée de quatre éléments principaux. Comprendre cette architecture est essentiel pour le déploiement et le troubleshooting.

### Les composants

| Composant | Rôle | Technologie |
|-----------|------|-------------|
| **Wazuh Server (Manager)** | Reçoit et analyse les données des agents, applique les règles de détection, génère les alertes | C, Python |
| **Wazuh Indexer** | Stocke et indexe les alertes et les événements pour la recherche rapide | Basé sur OpenSearch |
| **Wazuh Dashboard** | Interface web de visualisation, recherche et gestion | Basé sur OpenSearch Dashboards |
| **Wazuh Agent** | Collecte les données sur chaque endpoint et les envoie au manager | C, Python |

### Schéma d'architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENDPOINTS SURVEILLÉS                         │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  Linux   │  │ Windows  │  │  macOS   │  │  Cloud   │             │
│  │  Agent   │  │  Agent   │  │  Agent   │  │  Module  │             │
│  └────┬─────┘  └─────┬────┘  └──────┬───┘  └───────┬──┘             │
│       │              │              │              │                │
└───────┼──────────────┼──────────────┼──────────────┼────────────────┘
        │              │              │              │
        │    Port 1514 (chiffré, compressé)          │
        │              │              │              │
┌───────▼──────────────▼──────────────▼──────────────▼─────────────────┐
│                                                                      │
│                    WAZUH SERVER (MANAGER)                            │
│                                                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────────┐    │
│  │  Réception  │ │  Décodeurs  │ │   Règles    │ │   Active     │    │
│  │  des logs   │→│  (Parsing)  │→│ (Détection) │→│  Response    │    │
│  └─────────────┘ └─────────────┘ └──────┬──────┘ └──────────────┘    │ 
│                                         │                            │
│                                   Alertes générées                   │
│                                         │                            │
└─────────────────────────────────────────┼────────────────────────────┘
                                          │
                                    Port 9200
                                          │
┌─────────────────────────────────────────▼─────────────────────────────┐
│                                                                       │
│                      WAZUH INDEXER (OpenSearch)                       │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │  Index : wazuh-alerts-*  │  wazuh-archives-*  │  wazuh-stats-*  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────┬─────────────────────────────┘
                                          │
                                    Port 443
                                          │
┌─────────────────────────────────────────▼─────────────────────────────┐
│                                                                       │
│                     WAZUH DASHBOARD (Interface Web)                   │
│                                                                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐   │
│  │  Security  │  │  Agents    │  │  Threat    │  │  Compliance    │   │
│  │  Events    │  │  Overview  │  │  Intel     │  │  Dashboards    │   │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────┘   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Détail de chaque composant

#### Wazuh Server (Manager)

Le manager est le cerveau de l'architecture. Il reçoit les données des agents, les analyse et génère des alertes. Ses fonctions principales :

- **Réception des événements** : les agents envoient leurs données sur le port 1514 (protocole propriétaire, chiffré AES-256)
- **Décodage (parsing)** : les décodeurs extraient les champs structurés des logs bruts
- **Analyse par règles** : les règles de détection sont appliquées aux événements décodés
- **Génération d'alertes** : les événements correspondant à une règle produisent une alerte avec un niveau de sévérité
- **Active Response** : réponse automatique aux menaces (blocage IP, kill de processus)
- **Gestion des agents** : enregistrement, authentification et configuration des agents

#### Wazuh Indexer

L'indexer est basé sur **OpenSearch** (fork open source d'Elasticsearch). Il assure :

- le stockage persistant des alertes et des événements archivés,
- l'indexation full-text pour une recherche rapide,
- la rétention configurable des données,
- la haute disponibilité via le clustering.

#### Wazuh Dashboard

Le dashboard est basé sur **OpenSearch Dashboards** (fork de Kibana). Il fournit :

- une interface web accessible via HTTPS (port 443),
- des dashboards préconfigurés pour la sécurité,
- un moteur de recherche pour explorer les alertes,
- la gestion des agents et des règles,
- des visualisations de conformité réglementaire.

#### Wazuh Agent

L'agent est un logiciel léger déployé sur chaque endpoint à surveiller. Il :

- collecte les logs système et applicatifs,
- surveille l'intégrité des fichiers (FIM),
- exécute les scans de vulnérabilités et de configuration,
- envoie les données au manager de manière chiffrée et compressée,
- exécute les actions de réponse active ordonnées par le manager.

---

## Fonctionnalités principales

Wazuh offre un ensemble de fonctionnalités de sécurité couvrant la détection, la prévention et la conformité.

### Log Data Analysis

C'est la fonctionnalité fondamentale de Wazuh. Le système collecte et analyse les logs provenant de multiples sources :

- **Logs système** : syslog, journald, Windows Event Logs
- **Logs applicatifs** : Apache, Nginx, MySQL, PostgreSQL
- **Logs de sécurité** : auth.log, audit.log, PowerShell
- **Logs cloud** : AWS CloudTrail, Azure Activity, GCP Audit

Les décodeurs de Wazuh comprennent nativement des centaines de formats de logs différents.

### File Integrity Monitoring (FIM)

Le FIM surveille en temps réel les modifications apportées aux fichiers et répertoires critiques :

- Détection des modifications, créations et suppressions de fichiers
- Surveillance des permissions, propriétaires et attributs
- Calcul et comparaison des hashes (MD5, SHA1, SHA256)
- Surveillance de la base de registre Windows

Exemple de cas d'usage : un attaquant modifie `/etc/passwd` pour créer un backdoor. Le FIM génère immédiatement une alerte de niveau élevé.

### Vulnerability Detection

Wazuh scanne les logiciels installés sur chaque agent et les compare aux bases de données de vulnérabilités :

- **CVE** (Common Vulnerabilities and Exposures)
- Bases NVD (National Vulnerability Database), Red Hat, Debian, Ubuntu, Microsoft
- Priorisation par score CVSS
- Rapports de vulnérabilités par agent et par criticité

### Security Configuration Assessment (SCA)

Le SCA vérifie que la configuration des systèmes respecte les bonnes pratiques et les benchmarks de sécurité :

| Benchmark | Description |
|-----------|-------------|
| **CIS** (Center for Internet Security) | Benchmarks de configuration pour Linux, Windows, macOS, services |
| **STIG** (Security Technical Implementation Guide) | Standards de configuration du DoD américain |
| **PCI DSS** | Exigences de configuration pour le traitement des cartes bancaires |

### Intrusion Detection

La détection d'intrusions repose sur le moteur de règles de Wazuh. Les règles analysent les événements décodés et génèrent des alertes lorsqu'un comportement suspect est identifié :

- Détection de brute force (multiples échecs de connexion)
- Détection de rootkits (fichiers cachés, processus suspects)
- Détection d'escalade de privilèges
- Détection de mouvements latéraux
- Détection de reconnaissance réseau

### Incident Response (Active Response)

Wazuh peut réagir automatiquement aux menaces détectées :

| Action | Description | Exemple |
|--------|-------------|---------|
| **Blocage IP** | Ajoute une règle firewall pour bloquer l'IP source | Blocage après 5 échecs SSH |
| **Kill process** | Termine un processus malveillant | Kill d'un cryptominer détecté |
| **Quarantaine fichier** | Déplace un fichier suspect | Isolation d'un malware |
| **Script personnalisé** | Exécute un script défini par l'administrateur | Notification Slack, ticket JIRA |

### Regulatory Compliance

Wazuh fournit des dashboards et rapports préconfigurés pour les principales réglementations :

| Réglementation | Couverture Wazuh |
|----------------|-----------------|
| **PCI DSS** | Exigences 1, 2, 5, 6, 8, 10, 11 |
| **GDPR** | Articles 5, 25, 30, 32, 33, 35 |
| **HIPAA** | 164.312, 164.308, 164.310 |
| **NIST 800-53** | AC, AU, CM, IA, SI, SC |
| **TSC** (SOC 2) | CC6, CC7, CC8 |

### Cloud Security

Wazuh peut surveiller les environnements cloud :

| Cloud Provider | Sources surveillées |
|----------------|-------------------|
| **AWS** | CloudTrail, VPC Flow Logs, Config, GuardDuty |
| **Azure** | Activity Log, Azure AD, Blob Storage |
| **GCP** | Cloud Audit Logs, Pub/Sub |

---

## Comparaison Wazuh vs autres SIEM

Voici une comparaison objective de Wazuh avec les principales solutions SIEM du marché.

| Critère | Wazuh | Splunk | Elastic SIEM | QRadar (IBM) |
|---------|-------|--------|-------------|-------------|
| **Licence** | Open source (GPLv2) | Commercial | Open source + payant | Commercial |
| **Coût** | Gratuit | Très élevé (par volume de données ingérées) | Gratuit (basique) à élevé (Enterprise) | Élevé (par EPS) |
| **XDR intégré** | Oui (natif) | Non (add-on) | Partiel | Partiel |
| **HIDS intégré** | Oui (natif) | Non | Non | Non |
| **FIM** | Oui (natif) | Non (add-on) | Non (add-on) | Non |
| **Vulnerability Detection** | Oui (natif) | Non | Non | Partiellement (QVM) |
| **Compliance** | PCI DSS, GDPR, HIPAA, NIST | Via apps | Via règles | Oui |
| **Facilité d'installation** | Bonne (script all-in-one) | Moyenne | Moyenne | Complexe |
| **Scalabilité** | Bonne (clustering) | Excellente | Excellente | Bonne |
| **Communauté** | Large et active | Très large | Très large | Moyenne |
| **Support commercial** | Optionnel (Wazuh Inc.) | Inclus | Optionnel (Elastic) | Inclus (IBM) |
| **Langage de recherche** | OpenSearch Query DSL | SPL (Search Processing Language) | KQL / Lucene | AQL (Ariel Query Language) |
| **Cloud natif** | Wazuh Cloud (optionnel) | Splunk Cloud | Elastic Cloud | QRadar on Cloud |

**Pourquoi choisir Wazuh pour ce cours ?**

- Il est **gratuit** et open source, vous pouvez l'installer sans contrainte de licence
- Il offre la solution la plus **complète** en une seule plateforme (SIEM + XDR + HIDS + FIM + Compliance)
- Il est largement utilisé dans l'industrie, notamment par les PME et les SOC en croissance
- Sa **communauté active** fournit des règles de détection régulièrement mises à jour
- L'apprentissage de Wazuh est transférable aux autres SIEM (les concepts sont identiques)

---

## Le moteur de règles Wazuh

Le moteur de règles est le coeur de la détection dans Wazuh. Comprendre son fonctionnement est essentiel pour devenir un analyste SOC efficace.

### Pipeline de détection

Le traitement d'un événement suit trois étapes :

```
Événement brut → Décodeur → Règle → Alerte
```

#### 1. Les décodeurs (decoders)

Les décodeurs parsent les logs bruts pour en extraire des champs structurés. Wazuh inclut plus de 2500 décodeurs natifs.

Exemple : un log SSH brut :

```
Mar 15 14:22:01 webserver01 sshd[12345]: Failed password for root from 192.168.1.100 port 42156 ssh2
```

Le décodeur SSH extrait :

| Champ | Valeur |
|-------|--------|
| `program_name` | sshd |
| `srcip` | 192.168.1.100 |
| `srcport` | 42156 |
| `dstuser` | root |
| `status` | failed |

#### 2. Les règles (rules)

Les règles analysent les champs extraits par les décodeurs et déclenchent des alertes quand les conditions sont remplies. Wazuh inclut plus de 4000 règles de détection.

Exemple de règle de détection de brute force SSH :

```xml
<rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>
  <description>SSHD brute force trying to get access to the system.
    Authentication failed.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

Cette règle se déclenche lorsque la règle 5710 (échec SSH) est matchée 8 fois en 120 secondes. Elle génère une alerte de niveau 10.

#### 3. Les alertes

Chaque alerte reçoit un **niveau** (level) de 0 à 15 qui indique sa sévérité.

### Niveaux d'alerte Wazuh (0-15)

| Niveau | Catégorie | Description | Exemple |
|--------|-----------|-------------|---------|
| **0** | Ignoré | Aucune action, règle utilisée pour le pré-matching | Événement de base syslog |
| **1** | Aucun | Événement système de très bas niveau | Arrêt normal d'un programme |
| **2** | Notification système | Notification système de bas niveau | Changement de configuration mineur |
| **3** | Événement réussi | Événement de succès standard | Connexion réussie d'un utilisateur autorisé |
| **4** | Erreur système | Erreur liée à un mauvais état de configuration ou équipement | Espace disque bas |
| **5** | Erreur générée par l'utilisateur | Action utilisateur incorrecte (mauvais mot de passe, action refusée) | Échec d'authentification individuel |
| **6** | Attaque de faible pertinence | Attaque sans impact réel | Scan de port, worm connu |
| **7** | Événement "Bad word" | Détection de mots-clés suspects | "error", "bad", "failed" dans des contextes surveillés |
| **8** | Événement vu pour la première fois | Première occurrence d'un événement dans l'environnement | Première connexion d'un utilisateur, nouveau service |
| **9** | Erreur de source invalide | Événement provenant d'une source suspecte ou invalide | Tentative de connexion depuis un réseau non autorisé |
| **10** | Erreur multiple / attaque récurrente | Multiples échecs d'authentification ou patterns d'attaque répétés | Brute force SSH, multiples échecs de login |
| **11** | Alerte d'intégrité | Modification d'un fichier système critique | Modification de `/etc/passwd` ou d'un binaire système |
| **12** | Événement de haute importance | Événement nécessitant une attention immédiate | Modification de la configuration du firewall |
| **13** | Erreur inhabituelle (haute importance) | Pattern d'attaque avancé ou erreur anormale | Buffer overflow, exploitation de vulnérabilité |
| **14** | Événement de sécurité de haute priorité | Événement de sécurité critique | Corrélation de multiples alertes indiquant une compromission |
| **15** | Attaque sévère | Menace imminente ou attaque en cours confirmée | Rootkit détecté, modification de logs d'audit |

### En pratique : quels niveaux surveiller ?

| Action | Niveaux |
|--------|---------|
| **Ignorer** (bruit normal) | 0 à 3 |
| **Monitorer** (dashboard) | 4 à 7 |
| **Investiguer** (ticket SOC) | 8 à 11 |
| **Escalader** (alerte immédiate) | 12 à 15 |

Ces seuils sont des recommandations et doivent être adaptés à votre environnement. Un SOC mature affinera ces seuils en fonction du taux de faux positifs observé.

---

## Communication agent-serveur

La communication entre les agents Wazuh et le serveur suit un protocole spécifique :

| Caractéristique | Description |
|-----------------|-------------|
| **Port** | 1514 (TCP ou UDP, TCP recommandé) |
| **Chiffrement** | AES-256 avec clé pré-partagée |
| **Compression** | Les données sont compressées avant envoi |
| **Keep-alive** | Les agents envoient un signal de vie régulier |
| **Buffering** | Les agents stockent les événements localement en cas de perte de connexion |
| **Authentification** | Clé unique par agent, générée lors de l'enregistrement |

Ce mode de communication garantit que même en cas de coupure réseau temporaire, aucun événement n'est perdu.

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Wazuh** | Plateforme open source de sécurité combinant SIEM, XDR et HIDS |
| **OSSEC** | Open Source Security - HIDS open source dont Wazuh est un fork |
| **SIEM** | Security Information and Event Management |
| **XDR** | Extended Detection and Response - Détection et réponse étendue au-delà des endpoints |
| **HIDS** | Host-based Intrusion Detection System - Détection d'intrusion au niveau de l'hôte |
| **FIM** | File Integrity Monitoring - Surveillance de l'intégrité des fichiers |
| **SCA** | Security Configuration Assessment - Évaluation de la configuration de sécurité |
| **CIS** | Center for Internet Security - Organisation publiant des benchmarks de sécurité |
| **CVE** | Common Vulnerabilities and Exposures - Identifiant unique de vulnérabilité |
| **CVSS** | Common Vulnerability Scoring System - Score de gravité d'une vulnérabilité |
| **NVD** | National Vulnerability Database - Base nationale de vulnérabilités (NIST) |
| **OpenSearch** | Moteur de recherche et d'analyse open source, fork d'Elasticsearch |
| **Décodeur** | Composant Wazuh qui parse les logs bruts en champs structurés |
| **Rule** | Règle de détection Wazuh qui analyse les événements décodés |
| **Active Response** | Mécanisme de réponse automatique aux menaces dans Wazuh |
| **EPS** | Events Per Second - Nombre d'événements traités par seconde |
| **SPL** | Search Processing Language - Langage de requête de Splunk |
| **KQL** | Kibana Query Language - Langage de requête d'Elastic |
| **MITRE ATT&CK** | Framework de classification des tactiques et techniques d'attaque |
| **Manager** | Serveur central Wazuh qui reçoit et analyse les données des agents |

---

## Ressources

- Documentation officielle Wazuh : https://documentation.wazuh.com/
- Wazuh GitHub : https://github.com/wazuh/wazuh
- OSSEC documentation (historique) : https://www.ossec.net/docs/
- Wazuh Ruleset (règles et décodeurs) : https://github.com/wazuh/wazuh-ruleset
- MITRE ATT&CK Framework : https://attack.mitre.org/

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Wazuh](https://tryhackme.com/room/dvwazuhroom) | Découverte et prise en main de la plateforme Wazuh |
| TryHackMe | [Introduction to SIEM](https://tryhackme.com/room/dvintrotosiem) | Concepts fondamentaux des SIEM et mise en pratique |
