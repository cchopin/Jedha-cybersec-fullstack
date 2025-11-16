# Configuration des sources de données dans OpenCTI

## Table des matières

1. [Introduction](#introduction)
2. [Concepts de base](#concepts-de-base)
3. [Types de connecteurs](#types-de-connecteurs)
4. [Configuration des connecteurs externes](#configuration-des-connecteurs-externes)
5. [Connecteurs recommandés pour débuter](#connecteurs-recommandés-pour-débuter)
6. [Import manuel de données](#import-manuel-de-données)
7. [Configuration avancée](#configuration-avancée)
8. [Gestion et monitoring](#gestion-et-monitoring)
9. [Troubleshooting](#troubleshooting)
10. [Annexes](#annexes)

---

## Introduction

OpenCTI permet d'agréger des données de Cyber Threat Intelligence provenant de multiples sources. Cette documentation décrit comment configurer et gérer ces sources de données pour alimenter votre plateforme.

### Objectifs

- Comprendre les différents types de sources disponibles
- Configurer des connecteurs pour l'import automatique de données
- Importer manuellement des données au format STIX
- Surveiller et maintenir les sources de données

---

## Concepts de base

### Qu'est-ce qu'un connecteur ?

Un connecteur est un service Docker qui s'exécute de manière autonome et qui :
- Se connecte à une source de données externe
- Récupère les informations de threat intelligence
- Transforme les données au format STIX 2.1
- Injecte les données dans OpenCTI via l'API

### Format STIX 2.1

STIX (Structured Threat Information Expression) est le format standard pour l'échange de données de threat intelligence. OpenCTI utilise STIX 2.1 comme format natif.

**Objets STIX principaux :**
- **Indicator** : Indicateurs de compromission (IoC)
- **Malware** : Logiciels malveillants
- **Threat Actor** : Acteurs malveillants
- **Attack Pattern** : Techniques d'attaque (MITRE ATT&CK)
- **Vulnerability** : Vulnérabilités (CVE)
- **Campaign** : Campagnes d'attaque
- **Intrusion Set** : Ensembles d'intrusions
- **Tool** : Outils utilisés par les attaquants

### Architecture des connecteurs

```
┌─────────────────────┐
│  Source externe     │
│  (MITRE, CVE, etc.) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    Connecteur       │
│  (Container Docker) │
└──────────┬──────────┘
           │ API GraphQL
           ▼
┌─────────────────────┐
│     OpenCTI         │
│    (Platform)       │
└─────────────────────┘
```

---

## Types de connecteurs

### 1. EXTERNAL_IMPORT

Import de données depuis des sources externes vers OpenCTI.

**Exemples :**
- MITRE ATT&CK
- CVE
- AlienVault OTX
- URLhaus
- Abuse.ch

### 2. INTERNAL_IMPORT_FILE

Import de fichiers uploadés dans OpenCTI.

**Exemples :**
- Import File STIX
- Import Document (PDF, DOCX)

### 3. INTERNAL_EXPORT_FILE

Export de données depuis OpenCTI vers différents formats.

**Exemples :**
- Export File STIX
- Export File CSV
- Export File TXT

### 4. INTERNAL_ENRICHMENT

Enrichissement de données existantes dans OpenCTI.

**Exemples :**
- VirusTotal
- Shodan
- PassiveTotal

### 5. STREAM

Consommation de flux de données en temps réel.

**Exemples :**
- Elasticsearch
- Kafka
- Splunk

---

## Configuration des connecteurs externes

### Structure de base d'un connecteur

Chaque connecteur dans `docker-compose.yml` suit cette structure :

```yaml
services:
  connector-nom:
    image: opencti/connector-nom:version
    environment:
      # Configuration OpenCTI
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}

      # Configuration du connecteur
      - CONNECTOR_ID=UUID_UNIQUE
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=Nom du connecteur
      - CONNECTOR_SCOPE=scope1,scope2
      - CONNECTOR_CONFIDENCE_LEVEL=75
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info

      # Configuration spécifique au connecteur
      - PARAM_SPECIFIQUE=valeur

    restart: always
    depends_on:
      - opencti
```

### Paramètres communs

#### OPENCTI_URL
URL de l'instance OpenCTI.

```yaml
- OPENCTI_URL=http://opencti:8080
```

#### OPENCTI_TOKEN
Token d'authentification (doit correspondre à `OPENCTI_ADMIN_TOKEN` dans `.env`).

```yaml
- OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
```

#### CONNECTOR_ID
Identifiant unique du connecteur (UUID v4).

Génération :
```bash
uuidgen
```

```yaml
- CONNECTOR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

#### CONNECTOR_TYPE
Type de connecteur parmi :
- `EXTERNAL_IMPORT`
- `INTERNAL_IMPORT_FILE`
- `INTERNAL_EXPORT_FILE`
- `INTERNAL_ENRICHMENT`
- `STREAM`

```yaml
- CONNECTOR_TYPE=EXTERNAL_IMPORT
```

#### CONNECTOR_NAME
Nom affiché dans l'interface OpenCTI.

```yaml
- CONNECTOR_NAME=MITRE ATT&CK
```

#### CONNECTOR_SCOPE
Définit les types d'objets STIX que le connecteur peut traiter.

```yaml
- CONNECTOR_SCOPE=marking-definition,identity,attack-pattern
```

#### CONNECTOR_CONFIDENCE_LEVEL
Niveau de confiance des données importées (0-100).

```yaml
- CONNECTOR_CONFIDENCE_LEVEL=75
```

**Recommandations :**
- Sources officielles : 90-100
- Sources communautaires réputées : 70-80
- Sources communautaires : 50-60
- Sources non vérifiées : 30-40

#### CONNECTOR_UPDATE_EXISTING_DATA
Permet de mettre à jour des données existantes.

```yaml
- CONNECTOR_UPDATE_EXISTING_DATA=false  # Ne pas écraser les données
- CONNECTOR_UPDATE_EXISTING_DATA=true   # Mettre à jour les données
```

#### CONNECTOR_LOG_LEVEL
Niveau de verbosité des logs.

```yaml
- CONNECTOR_LOG_LEVEL=info  # debug, info, warning, error
```

---

## Connecteurs recommandés pour débuter

### 1. MITRE ATT&CK

Framework de techniques d'attaque et de tactiques.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-mitre:
    image: opencti/connector-mitre:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_MITRE_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MITRE ATT&CK
      - CONNECTOR_SCOPE=marking-definition,identity,attack-pattern,course-of-action,intrusion-set,campaign,malware,tool,report,external-reference-as-report
      - CONNECTOR_CONFIDENCE_LEVEL=90
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CONNECTOR_RUN_AND_TERMINATE=false
      - CONNECTOR_LOG_LEVEL=info
      - MITRE_ENTERPRISE_FILE_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
      - MITRE_MOBILE_ATTACK_FILE_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json
      - MITRE_ICS_ATTACK_FILE_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json
      - MITRE_INTERVAL=7
    restart: always
    depends_on:
      - opencti
```

**Paramètres spécifiques :**

| Paramètre | Description | Valeur par défaut |
|-----------|-------------|-------------------|
| MITRE_ENTERPRISE_FILE_URL | URL du fichier Enterprise ATT&CK | URL GitHub |
| MITRE_MOBILE_ATTACK_FILE_URL | URL du fichier Mobile ATT&CK | URL GitHub |
| MITRE_ICS_ATTACK_FILE_URL | URL du fichier ICS ATT&CK | URL GitHub |
| MITRE_INTERVAL | Intervalle de mise à jour (jours) | 7 |

**Configuration dans `.env` :**

```bash
CONNECTOR_MITRE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 2. CVE (Common Vulnerabilities and Exposures)

Base de données des vulnérabilités connues.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-cve:
    image: opencti/connector-cve:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CVE_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=Common Vulnerabilities and Exposures
      - CONNECTOR_SCOPE=identity,vulnerability
      - CONNECTOR_CONFIDENCE_LEVEL=75
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CONNECTOR_RUN_AND_TERMINATE=false
      - CONNECTOR_LOG_LEVEL=info
      - CVE_IMPORT_HISTORY=true
      - CVE_NVD_DATA_FEED=https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
      - CVE_HISTORY_DATA_FEED=https://nvd.nist.gov/feeds/json/cve/1.1/
      - CVE_INTERVAL=2
    restart: always
    depends_on:
      - opencti
```

**Paramètres spécifiques :**

| Paramètre | Description | Valeur par défaut |
|-----------|-------------|-------------------|
| CVE_IMPORT_HISTORY | Importer l'historique complet | true |
| CVE_NVD_DATA_FEED | URL du flux NVD récent | URL NVD |
| CVE_HISTORY_DATA_FEED | URL du flux historique NVD | URL NVD |
| CVE_INTERVAL | Intervalle de mise à jour (jours) | 2 |

**Configuration dans `.env` :**

```bash
CONNECTOR_CVE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**Note :** Le premier import peut prendre plusieurs heures car il importe l'historique complet des CVE.

### 3. AlienVault OTX

Plateforme communautaire de partage de threat intelligence.

**Prérequis :** Créer un compte gratuit sur https://otx.alienvault.com et récupérer une clé API.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-alienvault:
    image: opencti/connector-alienvault:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_ALIENVAULT_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=AlienVault OTX
      - CONNECTOR_SCOPE=alienvault
      - CONNECTOR_CONFIDENCE_LEVEL=60
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - ALIENVAULT_BASE_URL=https://otx.alienvault.com
      - ALIENVAULT_API_KEY=${ALIENVAULT_API_KEY}
      - ALIENVAULT_TLP=White
      - ALIENVAULT_CREATE_OBSERVABLES=true
      - ALIENVAULT_CREATE_INDICATORS=true
      - ALIENVAULT_PULSE_START_TIMESTAMP=2024-01-01T00:00:00
      - ALIENVAULT_REPORT_TYPE=threat-report
      - ALIENVAULT_REPORT_STATUS=New
      - ALIENVAULT_GUESS_MALWARE=false
      - ALIENVAULT_GUESS_CVE=false
      - ALIENVAULT_INTERVAL=10
    restart: always
    depends_on:
      - opencti
```

**Paramètres spécifiques :**

| Paramètre | Description | Valeur recommandée |
|-----------|-------------|-------------------|
| ALIENVAULT_API_KEY | Clé API OTX | Votre clé |
| ALIENVAULT_TLP | Niveau TLP par défaut | White, Green, Amber, Red |
| ALIENVAULT_CREATE_OBSERVABLES | Créer des observables | true |
| ALIENVAULT_CREATE_INDICATORS | Créer des indicateurs | true |
| ALIENVAULT_PULSE_START_TIMESTAMP | Date de début d'import | Date ISO |
| ALIENVAULT_INTERVAL | Intervalle de vérification (minutes) | 10 |

**Configuration dans `.env` :**

```bash
CONNECTOR_ALIENVAULT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ALIENVAULT_API_KEY=votre_cle_api_otx
```

### 4. CISA Known Exploited Vulnerabilities

Catalogue des vulnérabilités activement exploitées.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-cisa-kev:
    image: opencti/connector-cisa-known-exploited-vulnerabilities:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CISA_KEV_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=CISA Known Exploited Vulnerabilities
      - CONNECTOR_SCOPE=identity,vulnerability
      - CONNECTOR_CONFIDENCE_LEVEL=100
      - CONNECTOR_UPDATE_EXISTING_DATA=true
      - CONNECTOR_LOG_LEVEL=info
      - CISA_CATALOG_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      - CISA_CREATE_INFRASTRUCTURES=false
      - CISA_TLP=White
      - CISA_INTERVAL=1
    restart: always
    depends_on:
      - opencti
```

**Configuration dans `.env` :**

```bash
CONNECTOR_CISA_KEV_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 5. Abuse.ch URLhaus

Base de données d'URLs malveillantes.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-urlhaus:
    image: opencti/connector-urlhaus:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_URLHAUS_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=Abuse.ch URLhaus
      - CONNECTOR_SCOPE=urlhaus
      - CONNECTOR_CONFIDENCE_LEVEL=50
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - URLHAUS_CSV_URL=https://urlhaus.abuse.ch/downloads/csv_recent/
      - URLHAUS_IMPORT_OFFLINE=true
      - URLHAUS_CREATE_INDICATORS=true
      - URLHAUS_INTERVAL=3
    restart: always
    depends_on:
      - opencti
```

**Configuration dans `.env` :**

```bash
CONNECTOR_URLHAUS_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 6. Abuse.ch MalwareBazaar

Base de données d'échantillons de malware.

**Configuration dans `docker-compose.yml` :**

```yaml
  connector-malwarebazaar:
    image: opencti/connector-malwarebazaar-recent-additions:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_MALWAREBAZAAR_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MalwareBazaar Recent Additions
      - CONNECTOR_CONFIDENCE_LEVEL=50
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - MALWAREBAZAAR_RECENT_ADDITIONS_API_URL=https://mb-api.abuse.ch/api/v1/
      - MALWAREBAZAAR_RECENT_ADDITIONS_COOLDOWN_SECONDS=300
      - MALWAREBAZAAR_RECENT_ADDITIONS_INCLUDE_TAGS=exe,dll,docm,docx,doc,xls,xlsx,xlsm,js
      - MALWAREBAZAAR_RECENT_ADDITIONS_INCLUDE_REPORTERS=
      - MALWAREBAZAAR_RECENT_ADDITIONS_LABELS=malware-bazaar
      - MALWAREBAZAAR_RECENT_ADDITIONS_LABELS_COLOR=#54483b
    restart: always
    depends_on:
      - opencti
```

**Configuration dans `.env` :**

```bash
CONNECTOR_MALWAREBAZAAR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## Import manuel de données

### Import via l'interface web

#### 1. Fichiers STIX 2.1

**Étapes :**
1. Connectez-vous à OpenCTI
2. Menu **Data** → **Data import**
3. Cliquez sur **Upload file** ou glissez-déposez votre fichier
4. Sélectionnez le fichier STIX (.json)
5. Configurez les options d'import :
   - **Scope** : Validation automatique
   - **Update existing data** : Activer si vous voulez écraser les données existantes
6. Cliquez sur **Import**

**Formats supportés :**
- `.json` : Format STIX 2.1
- `.xml` : STIX 1.x (converti automatiquement)

#### 2. Documents (PDF, DOCX, TXT, HTML)

OpenCTI extrait automatiquement les indicateurs de compromission (IoC) des documents.

**Étapes :**
1. Menu **Data** → **Data import**
2. Upload du document
3. Le connecteur `Import Document` extrait automatiquement :
   - Adresses IP
   - Noms de domaine
   - URLs
   - Hashes (MD5, SHA-1, SHA-256)
   - Adresses email

**Formats supportés :**
- PDF
- DOCX, DOC
- TXT
- HTML

#### 3. Import CSV

Pour importer des indicateurs depuis un fichier CSV :

**Format CSV attendu :**
```csv
type,value,labels,description
ipv4-addr,192.0.2.1,malicious,C2 server
domain-name,evil.example.com,phishing,Phishing domain
file:hashes.MD5,d41d8cd98f00b204e9800998ecf8427e,malware,Malware hash
```

**Étapes :**
1. Préparez votre fichier CSV
2. Menu **Data** → **Data import**
3. Upload du fichier CSV
4. Mappez les colonnes si nécessaire

### Import via l'API

#### Prérequis

Installer le client Python OpenCTI :

```bash
pip install pycti --break-system-packages
```

#### Script Python d'import

```python
#!/usr/bin/env python3
from pycti import OpenCTIApiClient
from datetime import datetime

# Configuration
OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "votre_token_api"

# Connexion
api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

# Créer un indicateur IPv4
indicator = api.indicator.create(
    name="Malicious IP - C2 Server",
    description="IP address identified as C2 server in phishing campaign",
    pattern_type="stix",
    pattern="[ipv4-addr:value = '192.0.2.1']",
    x_opencti_main_observable_type="IPv4-Addr",
    validFrom=datetime.now().isoformat(),
    x_opencti_score=85,
    createdBy="Your Organization"
)

print(f"Indicateur créé : {indicator['id']}")

# Créer un domaine malveillant
domain = api.indicator.create(
    name="Phishing Domain",
    description="Domain used for credential harvesting",
    pattern_type="stix",
    pattern="[domain-name:value = 'evil.example.com']",
    x_opencti_main_observable_type="Domain-Name",
    validFrom=datetime.now().isoformat(),
    x_opencti_score=90
)

print(f"Domaine créé : {domain['id']}")

# Créer un hash de fichier
file_hash = api.indicator.create(
    name="Malware Sample",
    description="Zeus banking trojan variant",
    pattern_type="stix",
    pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
    x_opencti_main_observable_type="StixFile",
    validFrom=datetime.now().isoformat(),
    x_opencti_score=95
)

print(f"Hash créé : {file_hash['id']}")
```

#### Import en masse depuis CSV

```python
#!/usr/bin/env python3
import csv
from pycti import OpenCTIApiClient
from datetime import datetime

OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "votre_token_api"

api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

def import_indicators_from_csv(csv_file):
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)

        for row in reader:
            indicator_type = row['type']
            value = row['value']
            description = row.get('description', '')
            score = int(row.get('score', 50))

            # Construire le pattern STIX
            if indicator_type == 'ipv4-addr':
                pattern = f"[ipv4-addr:value = '{value}']"
                obs_type = "IPv4-Addr"
            elif indicator_type == 'domain-name':
                pattern = f"[domain-name:value = '{value}']"
                obs_type = "Domain-Name"
            elif indicator_type == 'url':
                pattern = f"[url:value = '{value}']"
                obs_type = "Url"
            elif indicator_type == 'file-md5':
                pattern = f"[file:hashes.MD5 = '{value}']"
                obs_type = "StixFile"
            else:
                print(f"Type non supporté : {indicator_type}")
                continue

            try:
                indicator = api.indicator.create(
                    name=f"{indicator_type}: {value}",
                    description=description,
                    pattern_type="stix",
                    pattern=pattern,
                    x_opencti_main_observable_type=obs_type,
                    validFrom=datetime.now().isoformat(),
                    x_opencti_score=score
                )
                print(f"Créé : {indicator['id']}")
            except Exception as e:
                print(f"Erreur pour {value}: {e}")

# Utilisation
import_indicators_from_csv('indicators.csv')
```

---

## Configuration avancée

### Gestion des duplicatas

OpenCTI détecte automatiquement les duplicatas basés sur les identifiants STIX. Comportement configurable par connecteur :

```yaml
- CONNECTOR_UPDATE_EXISTING_DATA=false  # Ignorer les duplicatas
- CONNECTOR_UPDATE_EXISTING_DATA=true   # Mettre à jour les duplicatas
```

### Niveaux de confiance (Confidence Level)

Le niveau de confiance affecte la fiabilité des données importées.

**Recommandations par type de source :**

| Source | Confidence Level | Justification |
|--------|------------------|---------------|
| MITRE ATT&CK | 90-100 | Source officielle, données vérifiées |
| CISA KEV | 100 | Vulnérabilités confirmées exploitées |
| CVE NVD | 75-85 | Base officielle mais peut contenir des faux positifs |
| AlienVault OTX | 50-70 | Source communautaire, qualité variable |
| URLhaus | 40-60 | Détections automatiques, taux de faux positifs |
| Données internes | 90-100 | Données vérifiées par votre équipe |

### Niveaux TLP (Traffic Light Protocol)

Contrôle la dissémination des informations.

**Niveaux disponibles :**

| Niveau | Description | Partage autorisé |
|--------|-------------|------------------|
| **TLP:RED** | Information strictement confidentielle | Destinataires spécifiques uniquement |
| **TLP:AMBER** | Information à diffusion limitée | Organisation et partenaires de confiance |
| **TLP:GREEN** | Information à diffusion communautaire | Communauté de sécurité |
| **TLP:WHITE** | Information publique | Aucune restriction |

**Configuration par connecteur :**

```yaml
- ALIENVAULT_TLP=White
- CONNECTOR_TLP=Green
```

### Scopes et filtrage

Le paramètre `CONNECTOR_SCOPE` définit les types d'objets STIX traités par le connecteur.

**Scopes courants :**

```yaml
# Tout importer
- CONNECTOR_SCOPE=all

# Types spécifiques
- CONNECTOR_SCOPE=indicator,malware,threat-actor

# MITRE ATT&CK complet
- CONNECTOR_SCOPE=marking-definition,identity,attack-pattern,course-of-action,intrusion-set,campaign,malware,tool,report

# Vulnérabilités uniquement
- CONNECTOR_SCOPE=vulnerability,identity

# Observables et indicateurs
- CONNECTOR_SCOPE=indicator,observable
```

### Intervalles de mise à jour

Configurez la fréquence de récupération des données selon vos besoins.

**Recommandations :**

| Type de données | Intervalle | Paramètre |
|----------------|-----------|-----------|
| Frameworks (MITRE) | 7 jours | `MITRE_INTERVAL=7` |
| Vulnérabilités (CVE) | 1-2 jours | `CVE_INTERVAL=2` |
| Threat Intel temps réel | 5-10 minutes | `ALIENVAULT_INTERVAL=10` |
| Listes d'URLs malveillantes | 2-3 heures | `URLHAUS_INTERVAL=3` |
| Malware samples | 1 heure | `MALWAREBAZAAR_COOLDOWN=3600` |

### Enrichissement automatique

Certains connecteurs peuvent enrichir automatiquement les données existantes.

**Exemple : VirusTotal Enrichment**

```yaml
  connector-virustotal:
    image: opencti/connector-virustotal:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_VIRUSTOTAL_ID}
      - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
      - CONNECTOR_NAME=VirusTotal
      - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url
      - CONNECTOR_AUTO=true
      - CONNECTOR_CONFIDENCE_LEVEL=50
      - CONNECTOR_LOG_LEVEL=info
      - VIRUSTOTAL_TOKEN=${VIRUSTOTAL_API_KEY}
      - VIRUSTOTAL_MAX_TLP=TLP:AMBER
    restart: always
    depends_on:
      - opencti
```

---

## Gestion et monitoring

### Vérifier l'état des connecteurs

#### Via l'interface web

1. Connectez-vous à OpenCTI
2. Menu **Data** → **Ingestion** → **Connectors**
3. Vérifiez :
   - **Status** : Active (vert) ou Error (rouge)
   - **Last run** : Date de dernière exécution
   - **Messages** : Nombre de messages traités

#### Via Docker

```bash
# Lister tous les conteneurs
docker compose ps

# Vérifier un connecteur spécifique
docker compose ps connector-mitre

# Statut détaillé
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"
```

### Consulter les logs

```bash
# Logs d'un connecteur en temps réel
docker compose logs -f connector-mitre

# Dernières 100 lignes
docker compose logs --tail=100 connector-mitre

# Logs de tous les connecteurs
docker compose logs | grep connector

# Rechercher les erreurs
docker compose logs connector-mitre | grep ERROR
docker compose logs connector-mitre | grep WARN
```

### Redémarrer un connecteur

```bash
# Redémarrer un connecteur spécifique
docker compose restart connector-mitre

# Redémarrer tous les connecteurs
docker compose restart $(docker compose ps --services | grep connector)

# Forcer la recréation
docker compose up -d --force-recreate connector-mitre
```

### Désactiver temporairement un connecteur

**Méthode 1 : Arrêter le conteneur**

```bash
docker compose stop connector-alienvault
```

**Méthode 2 : Commenter dans docker-compose.yml**

```yaml
# connector-alienvault:
#   image: opencti/connector-alienvault:latest
#   environment:
#     # ...
```

Puis :

```bash
docker compose up -d
```

### Statistiques d'import

#### Via l'interface web

1. Menu **Data** → **Ingestion** → **Connectors**
2. Cliquez sur un connecteur
3. Onglet **Activity**
4. Consultez :
   - Nombre d'entités importées
   - Graphiques d'activité
   - Historique des imports

#### Via l'API GraphQL

Accédez à http://localhost:8080/graphql

```graphql
query {
  connectors {
    edges {
      node {
        id
        name
        active
        connector_type
        updated_at
      }
    }
  }
}
```

### Alertes et notifications

Configurez des notifications pour être alerté en cas de problème.

**Via email (configuration SMTP dans .env) :**

```bash
SMTP_HOSTNAME=smtp.example.com
SMTP_PORT=587
SMTP_USE_SSL=true
SMTP_REJECT_UNAUTHORIZED=true
SMTP_FROM_EMAIL=opencti@example.com
SMTP_USERNAME=opencti
SMTP_PASSWORD=password
```

---

## Troubleshooting

### Problème : Le connecteur ne démarre pas

**Symptômes :**
- Le conteneur se termine immédiatement
- Status "Exited" dans `docker compose ps`

**Solutions :**

1. Vérifier les logs :
```bash
docker compose logs connector-mitre
```

2. Vérifier les variables d'environnement :
```bash
docker compose config | grep -A 20 connector-mitre
```

3. Vérifier que OpenCTI est démarré :
```bash
docker compose ps opencti
```

4. Vérifier le token d'authentification :
```bash
# Dans .env
echo $OPENCTI_ADMIN_TOKEN
```

### Problème : Connecteur en erreur "Cannot connect to OpenCTI"

**Causes possibles :**
- URL incorrecte
- Token invalide
- OpenCTI non accessible

**Solutions :**

1. Vérifier la connectivité réseau :
```bash
docker compose exec connector-mitre ping opencti
docker compose exec connector-mitre curl http://opencti:8080/health
```

2. Vérifier le token :
```bash
# Tester l'API avec curl
curl -X POST http://localhost:8080/graphql \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ me { name } }"}'
```

3. Recréer le connecteur :
```bash
docker compose rm -f connector-mitre
docker compose up -d connector-mitre
```

### Problème : Pas de données importées

**Symptômes :**
- Le connecteur fonctionne mais aucune donnée n'apparaît dans OpenCTI

**Solutions :**

1. Vérifier les logs du connecteur :
```bash
docker compose logs connector-mitre | grep -i import
```

2. Vérifier le scope :
```yaml
# Le scope doit correspondre aux types de données importées
- CONNECTOR_SCOPE=attack-pattern,malware,tool
```

3. Vérifier l'intervalle :
```bash
# Forcer une exécution immédiate en redémarrant
docker compose restart connector-mitre
```

4. Vérifier dans l'interface :
- Menu **Data** → **Entities**
- Filtrer par source du connecteur

### Problème : Erreur "Rate limit exceeded"

**Symptômes :**
- Logs indiquent "429 Too Many Requests"
- Import interrompu

**Solutions :**

1. Augmenter l'intervalle :
```yaml
# Exemple pour AlienVault
- ALIENVAULT_INTERVAL=30  # Passer de 10 à 30 minutes
```

2. Vérifier les limites de l'API source :
- AlienVault OTX : 10 requêtes/minute
- VirusTotal Free : 4 requêtes/minute

3. Utiliser une clé API premium si disponible

### Problème : Import très lent

**Causes :**
- Volume important de données
- Ressources insuffisantes
- Vérifications de duplicatas

**Solutions :**

1. Augmenter les ressources Docker :
```bash
# Docker Desktop → Preferences → Resources
# RAM : 16 GB minimum
# CPU : 8 cores recommandés
```

2. Augmenter le nombre de workers :
```yaml
# Dans docker-compose.yml
worker:
  deploy:
    replicas: 5  # Augmenter de 3 à 5
```

3. Optimiser Elasticsearch :
```bash
# Dans .env
ELASTIC_MEMORY_SIZE=6G  # Augmenter de 4G à 6G
```

4. Désactiver la mise à jour des données existantes :
```yaml
- CONNECTOR_UPDATE_EXISTING_DATA=false
```

### Problème : Connecteur avec erreur "Invalid STIX bundle"

**Symptômes :**
- Logs indiquent "Invalid STIX format"
- Import échoue

**Solutions :**

1. Activer la validation :
```yaml
- CONNECTOR_VALIDATE_BEFORE_IMPORT=true
```

2. Vérifier la version du connecteur :
```bash
docker compose pull connector-mitre
docker compose up -d connector-mitre
```

3. Vérifier la compatibilité STIX :
- OpenCTI utilise STIX 2.1
- Certaines sources fournissent STIX 1.x (conversion automatique)

---

## Annexes

### Annexe A : Liste complète des connecteurs officiels

#### Import externe

| Connecteur | Description | Confidence Level |
|------------|-------------|------------------|
| MITRE ATT&CK | Framework de techniques d'attaque | 90 |
| CVE | Vulnérabilités connues | 75 |
| CISA KEV | Vulnérabilités exploitées | 100 |
| AlienVault OTX | Threat intelligence communautaire | 60 |
| URLhaus | URLs malveillantes | 50 |
| MalwareBazaar | Échantillons de malware | 50 |
| Feodo Tracker | Botnet C2 tracking | 60 |
| ThreatFox | IoC de malware | 60 |
| MISP | Plateformes MISP | Variable |
| TheHive | Plateforme de réponse aux incidents | Variable |
| OpenCTI Datasets | Jeux de données OpenCTI | 75 |
| Cyber Campaign Collection | Campagnes APT documentées | 80 |
| Mandiant | Threat intelligence Mandiant | 85 |
| RecordedFuture | Threat intelligence RecordedFuture | 80 |
| CrowdStrike | Threat intelligence CrowdStrike | 85 |

#### Enrichissement

| Connecteur | Description | API Key Required |
|------------|-------------|------------------|
| VirusTotal | Analyse de fichiers et URLs | Oui |
| Shodan | Informations sur les IPs | Oui |
| PassiveTotal | Informations DNS et WHOIS | Oui |
| AbuseIPDB | Réputation d'IP | Oui |
| Hybrid Analysis | Sandbox de malware | Oui |
| Joe Sandbox | Sandbox de malware | Oui |
| GreyNoise | Contexte sur les IPs | Oui |
| IPInfo | Géolocalisation d'IP | Optionnel |
| Have I Been Pwned | Emails compromis | Oui |

#### Export

| Connecteur | Description | Format |
|------------|-------------|--------|
| Export File STIX | Export STIX 2.1 | JSON |
| Export File CSV | Export CSV | CSV |
| Export File TXT | Export texte | TXT |
| TAXII 2.1 Server | Serveur TAXII | TAXII |
| MISP Export | Export vers MISP | MISP |
| Splunk | Export vers Splunk | Splunk |
| Elasticsearch | Export vers Elasticsearch | JSON |

### Annexe B : Template de connecteur personnalisé

Structure minimale pour créer un connecteur custom :

**docker-compose.yml :**

```yaml
  connector-custom:
    image: opencti/connector-custom:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CUSTOM_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=My Custom Connector
      - CONNECTOR_SCOPE=indicator,observable
      - CONNECTOR_CONFIDENCE_LEVEL=70
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - CUSTOM_PARAM_1=value1
      - CUSTOM_PARAM_2=value2
      - CUSTOM_INTERVAL=60
    restart: always
    depends_on:
      - opencti
```

### Annexe C : Sources de données gratuites

#### Frameworks et méthodologies

- **MITRE ATT&CK** : https://attack.mitre.org/
- **MITRE D3FEND** : https://d3fend.mitre.org/
- **MITRE CAR** : https://car.mitre.org/

#### Vulnérabilités

- **NVD (CVE)** : https://nvd.nist.gov/
- **CISA KEV** : https://www.cisa.gov/known-exploited-vulnerabilities
- **VulnDB** : https://vulndb.cyberriskanalytics.com/

#### Indicateurs de compromission

- **AlienVault OTX** : https://otx.alienvault.com/
- **Abuse.ch URLhaus** : https://urlhaus.abuse.ch/
- **Abuse.ch MalwareBazaar** : https://bazaar.abuse.ch/
- **Abuse.ch Feodo Tracker** : https://feodotracker.abuse.ch/
- **Abuse.ch ThreatFox** : https://threatfox.abuse.ch/
- **PhishTank** : https://www.phishtank.com/
- **OpenPhish** : https://openphish.com/

#### Threat Intelligence

- **CIRCL** : https://www.circl.lu/services/misp-malware-information-sharing-platform/
- **Cyber Campaign Collection** : https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections

### Annexe D : Commandes utiles

#### Gestion des connecteurs

```bash
# Lister tous les connecteurs
docker compose ps | grep connector

# Démarrer tous les connecteurs
docker compose up -d $(docker compose config --services | grep connector)

# Arrêter tous les connecteurs
docker compose stop $(docker compose config --services | grep connector)

# Redémarrer tous les connecteurs
docker compose restart $(docker compose config --services | grep connector)

# Supprimer tous les connecteurs
docker compose rm -f $(docker compose config --services | grep connector)

# Logs de tous les connecteurs
docker compose logs $(docker compose config --services | grep connector)

# Mettre à jour tous les connecteurs
docker compose pull
docker compose up -d
```

#### Monitoring

```bash
# Utilisation des ressources par connecteur
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
  $(docker compose ps -q | grep connector)

# Nombre de messages traités
docker compose logs connector-mitre | grep "processed" | wc -l

# Dernière activité
docker compose ps --format "{{.Name}}\t{{.Status}}"
```

### Annexe E : Configuration du fichier .env complet

```bash
# === OPENCTI CORE ===
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMe
OPENCTI_ADMIN_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_HEALTHCHECK_ACCESS_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# === SERVICES ===
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=ChangeMe
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=ChangeMe
ELASTIC_MEMORY_SIZE=4G

# === SMTP (optionnel) ===
SMTP_HOSTNAME=
SMTP_PORT=25

# === CONNECTEURS EXPORT ===
CONNECTOR_EXPORT_FILE_STIX_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_EXPORT_FILE_CSV_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_EXPORT_FILE_TXT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# === CONNECTEURS IMPORT ===
CONNECTOR_IMPORT_FILE_STIX_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_IMPORT_DOCUMENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_ANALYSIS_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# === XTM COMPOSER ===
XTM_COMPOSER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# === CONNECTEURS EXTERNES ===
CONNECTOR_MITRE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_CVE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_CISA_KEV_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_ALIENVAULT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_URLHAUS_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONNECTOR_MALWAREBAZAAR_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# === CLÉS API EXTERNES ===
ALIENVAULT_API_KEY=votre_cle_api_otx
VIRUSTOTAL_API_KEY=votre_cle_api_virustotal
SHODAN_API_KEY=votre_cle_api_shodan
```

### Annexe F : Checklist de configuration

#### Configuration initiale

- [ ] OpenCTI démarré et accessible
- [ ] Mot de passe admin changé
- [ ] Token admin sécurisé
- [ ] Fichier .env sauvegardé en sécurité

#### Connecteurs de base

- [ ] MITRE ATT&CK configuré et actif
- [ ] CVE configuré et actif
- [ ] Premier import réussi
- [ ] Logs vérifiés

#### Connecteurs avancés

- [ ] AlienVault OTX avec clé API
- [ ] CISA KEV configuré
- [ ] URLhaus configuré
- [ ] Connecteurs d'enrichissement (optionnel)

#### Monitoring

- [ ] Vérification quotidienne des logs
- [ ] Notifications configurées
- [ ] Dashboard de monitoring créé
- [ ] Documentation mise à jour

---

## Conclusion

Cette documentation couvre la configuration complète des sources de données dans OpenCTI. Pour aller plus loin :

- Consultez la documentation officielle : https://docs.opencti.io
- Explorez l'écosystème de connecteurs : https://github.com/OpenCTI-Platform/connectors
- Rejoignez la communauté : https://community.filigran.io
