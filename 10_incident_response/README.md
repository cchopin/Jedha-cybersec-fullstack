# 10 - Incident Response

**Durée :** 4 jours
**Modules :** 4 chapitres | 12 cours

---

## Objectifs

Apprendre à détecter, analyser et répondre aux incidents de sécurité de manière efficace, depuis la mise en place d'un SIEM jusqu'à l'analyse de malware.

---

## Sommaire

### Chapitre 1 - Fondamentaux de la réponse aux incidents

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 01 | `01_reponse_aux_incidents_cyber.md` | Cours | Cycle de vie IR, frameworks NIST/SANS, rôles CSIRT, classification des incidents, KPIs |
| 02 | `02_playbook_de_reponse.md` | Cours | Playbooks par type d'incident, confinement, éradication, récupération, SOAR |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| TryHackMe | [Intro to IR and IM](https://tryhackme.com/room/dvintrotoimandcybir) | Easy | Introduction à la gestion des incidents |
| TryHackMe | [Incident Response Fundamentals](https://tryhackme.com/room/dvincidentresponsefundamentals) | Easy | Fondamentaux de la réponse aux incidents |
| TryHackMe | [Preparation](https://tryhackme.com/room/dvpreparationir) | Easy | Phase de préparation de l'IR |
| TryHackMe | [DFIR: An Introduction](https://tryhackme.com/room/dvintroductiontodfir) | Easy | Introduction au Digital Forensics and Incident Response |
| HackTheBox | [Brutus](https://app.hackthebox.com/sherlocks/Brutus) | Very Easy | Brute force SSH, analyse de logs d'authentification |
| HackTheBox | [Litter](https://app.hackthebox.com/sherlocks/Litter) | Easy | Tunneling DNS, exfiltration de données, analyse PCAP |

---

### Chapitre 2 - Logging, agrégation et SIEM (Wazuh)

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 03 | `03_logging_et_agregation.md` | Cours | Types de logs, syslog, Windows Event IDs, centralisation, pipeline SIEM |
| 04 | `04_introduction_a_wazuh.md` | Cours | Architecture Wazuh, fonctionnalités, moteur de règles, comparaison SIEM |
| 05 | `05_installation_serveur_wazuh.md` | Cours | Installation all-in-one et Docker, configuration, ports, sécurisation |
| 06 | `06_installation_wazuh_endpoints.md` | Cours | Déploiement agents Linux/Windows, enrollment, groupes, troubleshooting |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| TryHackMe | [Windows Event Logs](https://tryhackme.com/room/dvwindowseventlogs) | Medium | Analyse des journaux d'événements Windows |
| TryHackMe | [Intro to Logs](https://tryhackme.com/room/dvintrotologs) | Easy | Introduction aux logs et leur importance |
| TryHackMe | [Wazuh](https://tryhackme.com/room/dvwazuhroom) | Medium | Déploiement et utilisation de Wazuh |
| TryHackMe | [Introduction to SIEM](https://tryhackme.com/room/dvintrotosiem) | Easy | Concepts et fonctionnement d'un SIEM |
| HackTheBox | [Logjammer](https://app.hackthebox.com/sherlocks/Logjammer) | Easy | Analyse de 5 sources d'event logs Windows |

---

### Chapitre 3 - Détection et alertes personnalisées

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 07 | `07_collecte_de_logs_personnalisee.md` | Cours | Localfile, décodeurs personnalisés, Event Channel, syslog réseau |
| 08 | `08_ecriture_de_requetes.md` | Cours | Règles Wazuh, requêtes Lucene, MITRE ATT&CK, Active Response |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| TryHackMe | [Log Operations](https://tryhackme.com/room/dvlogoperations) | Medium | Opérations avancées sur les logs |
| TryHackMe | [Custom Alert Rules in Wazuh](https://tryhackme.com/room/dvwazuhcustomrules) | Medium | Création de règles d'alerte personnalisées |
| TryHackMe | [MITRE](https://tryhackme.com/room/dvmitre) | Easy | Framework MITRE ATT&CK |
| HackTheBox | [Unit42](https://app.hackthebox.com/sherlocks/Unit42) | Very Easy | Analyse de logs Sysmon, traçage de processus malveillants |
| HackTheBox | [Noted](https://app.hackthebox.com/sherlocks/Noted) | Easy | Investigation d'exfiltration de données |

---

### Chapitre 4 - Analyse de malware

| # | Fichier | Type | Sujet |
|---|---------|------|-------|
| 09 | `09_fondamentaux_analyse_malware.md` | Cours | Taxonomie des malwares, Cyber Kill Chain, MITRE ATT&CK, IOCs |
| 10 | `10_lab_environnement_analyse_malware.md` | Cours | FlareVM, REMnux, architecture lab isolé, bonnes pratiques |
| 11 | `11_analyse_statique.md` | Cours | Hashing, strings, PE headers, API suspectes, YARA, documents Office |
| 12 | `12_analyse_dynamique.md` | Cours | ProcMon, Wireshark, Volatility, évasion de sandbox, workflow complet |

**Rooms associées :**

| Plateforme | Room | Difficulté | Description |
|------------|------|------------|-------------|
| TryHackMe | [Intro to Malware Analysis](https://tryhackme.com/room/dvintromalwareanalysis) | Easy | Introduction à l'analyse de malware |
| TryHackMe | [History of Malware](https://tryhackme.com/room/dvhistoryofmalware) | Easy | Histoire et évolution des malwares |
| TryHackMe | [Basic Static Analysis](https://tryhackme.com/room/dvstaticanalysis1) | Medium | Techniques d'analyse statique |
| TryHackMe | [Dissecting PE Headers](https://tryhackme.com/room/dvdissectingpeheaders) | Medium | Structure des fichiers PE Windows |
| TryHackMe | [Basic Dynamic Analysis](https://tryhackme.com/room/dvdynamicanalysis1) | Medium | Techniques d'analyse dynamique |
| TryHackMe | [Volatility](https://tryhackme.com/room/dvbvolatility) | Medium | Forensique mémoire avec Volatility |
| TryHackMe | [MAL: Malware Introductory](https://tryhackme.com/room/dvmalmalintroductory) | Easy | Introduction pratique aux malwares |
| HackTheBox | [Recollection](https://app.hackthebox.com/sherlocks/Recollection) | Easy | Forensique mémoire avec Volatility |
| HackTheBox | [Tracer](https://app.hackthebox.com/sherlocks/Tracer) | Easy | Mouvement latéral, PSExec, services |
| HackTheBox | [Reminiscent](https://app.hackthebox.com/challenges/Reminiscent) | Medium | Analyse de dump mémoire, extraction de payloads PowerShell |
