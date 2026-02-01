# Certification TryHackMe - Junior Security Analyst

## Présentation

Examen pratique de cybersécurité basé sur l'attaque et la défense de systèmes réels (VMs).
Aucun QCM, uniquement du terminal et des outils techniques.

---

## Contenu détaillé par section

### Section 1 - Windows

**Tâches :**
- Requêtes PowerShell pour extraire des infos système
- Lecture du registre Windows
- Analyse des tâches planifiées et services
- Configuration réseau et firewall

**Prérequis :**
- Syntaxe PowerShell (`Get-Item`, `Get-ChildItem`, `Get-Service`, `Get-NetFirewallRule`)
- Structure du registre Windows (HKLM, HKCU)
- Fonctionnement des services Windows

---

### Section 2 - Linux

**Tâches :**
- Commandes bash : `grep`, `find`, `cat`, `chmod`, `ls`
- Gestion des utilisateurs et groupes
- Permissions fichiers
- Navigation système

**Prérequis :**
- Maîtrise du terminal Linux
- Arborescence Linux (`/etc`, `/home`, `/var`, `/root`)
- Lecture des fichiers système (`/etc/passwd`, `/etc/shadow`, `/etc/group`)

---

### Section 3 - Réseau

**Tâches :**
- Scan de ports sur une machine cible
- Identification des services (SSH, HTTP, MySQL...)
- Utilisation des scripts NSE
- Détection de versions et vulnérabilités

**Prérequis :**
- Modèle TCP/IP et ports courants (22, 80, 443, 3306...)
- Syntaxe Nmap (`-sV`, `-sC`, `-p-`, `--script`)
- Compréhension des bannières de services

---

### Section 4 - Web Pentesting

**Tâches :**
- **IDOR** : modification d'ID pour accéder aux données d'autres utilisateurs
- **XSS** : injection de JavaScript malveillant
- **Command Injection** : exécution de commandes système via un champ web
- **SQL Injection** : extraction de données via requêtes malformées
- **JWT Forgery** : modification de token en changeant l'algorithme à `none`

**Prérequis :**
- Fonctionnement HTTP (requêtes GET/POST, headers, cookies)
- Structure d'un JWT (`header.payload.signature`)
- Utilisation de Burp Suite ou curl
- Syntaxe SQL basique
- Encodage base64 et URL encoding

---

### Section 5 - Security Operations (Blue Team)

**Tâches :**
- Analyse d'alertes dans une console SIEM
- Création de règles firewall
- Interprétation de scans de vulnérabilités
- Triage d'incidents

**Prérequis :**
- Vocabulaire SOC (IOC, CVE, CVSS, faux positifs)
- Lecture de logs (format, timestamp, severity)
- Logique des règles firewall (source, destination, port, action)
- Connaissance des alertes courantes (bruteforce, scan, exfiltration)

---

### Section 6 - Kill Chain complète

**Tâches :**

Chaîne d'exploitation de A à Z :

1. Scan Nmap → identification des ports ouverts
2. Bruteforce du login admin sur une webapp
3. Découverte d'un endpoint sensible leakant un fichier ZIP
4. Cracking du mot de passe du ZIP
5. Extraction d'un fichier shadow
6. Cracking des hash SHA-512
7. Connexion SSH avec les credentials obtenus
8. Décodage base64 d'une note contenant un hash MD5
9. Cracking du hash MD5
10. Accès à une seconde application avec les nouveaux credentials
11. Récupération d'une clé SSH privée chiffrée
12. Cracking de la passphrase de la clé SSH
13. Connexion root et décodage d'un fichier chiffré en César

**Prérequis :**
- Nmap (scan et énumération)
- Outils de bruteforce web (Hydra, Burp Intruder, ffuf)
- John the Ripper et ses modules (`zip2john`, `ssh2john`)
- Hashcat et identification des formats de hash
- Formats de hash : MD5, SHA-256, SHA-512, bcrypt
- Utilisation de clés SSH et gestion des passphrases
- Chiffrements classiques (César, base64)

---

### Section 7 - Analyse de Malware

**Tâches :**
- Calcul de hash SHA-256
- Extraction des strings d'un exécutable
- Identification de l'architecture et de l'OS cible
- Décodage d'URLs obfusquées en base64
- Analyse du comportement (téléchargement de payload, exécution de commandes)

**Prérequis :**
- Format PE Windows (header MZ, sections `.text`, `.data`)
- Outils d'analyse statique (`strings`, `file`, PEStudio, CAPA)
- Compréhension des API Windows (`CreateProcess`, `URLDownloadToFile`)
- MBC (Malware Behaviour Catalogue) et objectifs courants
- Encodages courants (base64, XOR)

---

## Tableau récapitulatif des prérequis

| Section | Connaissances clés |
|---------|-------------------|
| Windows | PowerShell, registre, services Windows |
| Linux | Bash, arborescence système, permissions |
| Réseau | TCP/IP, Nmap, ports et services |
| Web Pentesting | HTTP, Burp Suite, OWASP Top 10, JWT |
| Security Ops | SIEM, logs, règles firewall, vocabulaire SOC |
| Kill Chain | John, Hashcat, formats de hash, SSH, encodages |
| Malware Analysis | Format PE, strings, API Windows, analyse statique |
