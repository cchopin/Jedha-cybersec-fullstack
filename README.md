# Formation Cybersécurité Full Stack - Jedha

Ce repository contient l'ensemble des projets, exercices et documentations réalisés dans le cadre de ma formation en cybersécurité full stack avec Jedha.

## Progression

**4/16 modules complétés** • **Durée totale :** 61 jours

```
████████░░░░░░░░░░░░░░░░░░░░ 25%
```

## Vue d'ensemble des modules

| # | Module | Durée | Statut | Contenu principal |
|---|--------|-------|--------|-------------------|
| 01 | Prepare Your Training | 1 jour | ✅ | Scripting Bash, automatisation |
| 02 | Threat Intelligence | 2 jours | ✅ | APT, MITRE ATT&CK, OSINT, OpenCTI |
| 03 | Email Security | 1 jour | ✅ | Phishing, SPF/DKIM/DMARC, Gophish |
| 04 | Databases | 2 jours | ✅ | SQL/NoSQL, injections, sécurisation |
| 05 | Web Security | 6 jours | ⏳ | Python/Flask, XSS, SQLi, CSRF, Docker, CI/CD |
| 06 | Cloud Security | 3 jours | ⏳ | AWS, IAM, VPC, CloudWatch |
| 07 | Network Security | 6 jours | ⏳ | TCP/IP, VLANs, routing, firewalls, VPN, Wireshark |
| 08 | Linux System Security | 8 jours | ⏳ | Users, processes, kernel, SELinux, containers |
| 09 | Windows Security | 8 jours | ⏳ | Active Directory, GPO, Kerberos, exploitation |
| 10 | Incident Response | 4 jours | ⏳ | SIEM, Wazuh, playbooks, malware analysis |
| 11 | Digital Forensics | 3 jours | ⏳ | Disk/memory forensics, Autopsy, Volatility |
| 12 | Governance Risk & Compliance | 1 jour | ⏳ | NIST, GDPR, ISO 27001 |
| 13 | Penetration Testing | 3 jours | ⏳ | Metasploit, méthodologies, reporting |
| 14 | Career Coaching | 3 jours | ⏳ | CV, entretiens, networking |
| 15 | Final Project | 10 jours | ⏳ | Projet intégrateur |
| 16 | Cybersecurity Certification | - | ⏳ | Certification professionnelle |

## Structure du repository

```
jedha/
├── 01_prep_work/                    # ✅ Scripts Bash
│   └── bash_training/
├── 02_threat_intelligence/          # ✅ OpenCTI + Articles
│   └── opencti/
├── 03_email_security/               # ✅ Phishing, SPF/DKIM/DMARC
├── 04_databases/                    # ✅ SQL, sécurisation BDD
├── 05_web_security/                 # ⏳ Web app security (en cours)
│   └── python_blog/
├── 06_cloud_security/               # ⏳ AWS, IAM, monitoring
├── 07_network_security/             # ⏳ TCP/IP, firewalls, VPN
├── 08_linux_system_security/        # ⏳ Kernel, containers, hardening
├── 09_windows_security/             # ⏳ AD, Kerberos, exploitation
├── 10_incident_response/            # ⏳ SIEM, forensics, playbooks
├── 11_digital_forensics/            # ⏳ Disk/memory analysis
├── 12_governance_risk_compliance/   # ⏳ NIST, GDPR, compliance
├── 13_penetration_testing/          # ⏳ Metasploit, pentesting
├── 14_career_coaching/              # ⏳ Préparation professionnelle
├── 15_final_project/                # ⏳ Projet final
└── README.md                        # Ce fichier
```

> Chaque module possède son propre README avec les détails des projets, objectifs et compétences acquises.

## Modules complétés en détail

### 01 - Prepare Your Training ✅
**Projets :** Scripts Bash d'automatisation
- `search_with_bash.sh` - Recherche de fichiers/répertoires
- `lizard_toad_snake.sh` - Jeu interactif

### 02 - Threat Intelligence ✅
**Projets :** OpenCTI, analyse de menaces
- Configuration complète d'OpenCTI
- Analyse de groupes APT (DragonForce)
- Articles : [OpenCTI](https://tely.info/article.html?id=opencti) | [DragonForce](https://tely.info/article.html?id=opencti-dragonforce)

### 03 - Email Security ✅
**Compétences :** Analyse de phishing, SPF/DKIM/DMARC, Gophish
- Analyse d'headers d'emails
- Validation des mécanismes de sécurité
- Campagnes de simulation avec Gophish

### 04 - Databases ✅
**Compétences :** SQL/NoSQL, injections, sécurisation
- Requêtes SQL avancées
- Détection et prévention des SQL injections
- Gestion des accès et privilèges

## Modules en cours

### 05 - Web Security ⏳
**Technologies :** Python, Flask, Docker, Burp Suite
- Développement d'applications web sécurisées
- Vulnérabilités OWASP : XSS, SQLi, CSRF, SSTI
- Infrastructure sécurisée avec Nginx et Docker
- CI/CD avec GitHub Actions et Trivy
- Déploiement avec Docker Swarm

## Technologies et outils

**Langages :** Python, Bash, SQL, HTML/CSS, PowerShell

**Web :** Flask, Jinja2, Nginx, HTTPS/SSL

**Sécurité :** Burp Suite, Metasploit, Wireshark, Nmap, OpenCTI, Wazuh

**Infrastructure :** Docker, Docker Swarm, Ansible, Kubernetes

**Cloud :** AWS (EC2, S3, IAM, VPC, CloudWatch)

**Forensics :** Autopsy, Volatility, Wireshark

**OS :** Linux (SELinux, AppArmor), Windows (Active Directory)

**Autres :** Git, GitHub Actions, PostgreSQL, SQLite, LDAP

## Ressources externes

- **Articles techniques :** [tely.info](https://tely.info)
- **Formation :** [Jedha Bootcamp](https://www.jedha.co)

## Objectifs de la formation

- Maîtriser les techniques offensives et défensives
- Sécuriser les applications web, cloud et infrastructures
- Analyser et répondre aux incidents de sécurité
- Réaliser des tests d'intrusion professionnels
- Comprendre les frameworks de compliance (NIST, GDPR)

## Organisation

Ce repository est organisé par module de formation. Chaque répertoire numéroté (`01_`, `02_`, etc.) correspond à un module spécifique et contient :
- Un README détaillé du module
- Les projets et exercices associés
- La documentation et notes

## Licence

Projet éducatif - Formation Jedha Bootcamp
