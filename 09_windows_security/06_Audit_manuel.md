# Audit Manuel - VAGRANT-2008R2 (10.10.3.41)

**Date :** 2026-02-14
**Identifiants de l'auditeur :** Jeremie / hunter22
**Nom de la machine :** VAGRANT-2008R2
**Connexion :** `ssh Jeremie@10.10.3.41`

---

## 1. Informations sur le système d'exploitation

### 1.1 Identification du système

La commande `systeminfo` (cf. cours *01 - Outils d'administration Windows*) fournit les informations les plus complètes sur la machine :

```powershell
PS> systeminfo
```

```
Host Name:                 VAGRANT-2008R2
OS Name:                   Microsoft Windows Server 2008 R2 Standard
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Organization:   Vagrant Inc.
Product ID:                00477-001-0000347-84780
Original Install Date:     8/6/2017, 7:16:02 PM
System Boot Time:          10/5/2022, 11:24:18 AM
System Manufacturer:       innotek GmbH
System Model:              VirtualBox
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 142 Stepping 12 GenuineIntel ~1992 Mhz
Total Physical Memory:     4,096 MB
Available Physical Memory: 1,856 MB
Domain:                    WORKGROUP
Logon Server:              \\VAGRANT-2008R2
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB3134760
                           [02]: KB976902
```

Commandes complémentaires :

```powershell
PS> ver
```

```
Microsoft Windows [Version 6.1.7601]
```

```powershell
PS> hostname
```

```
vagrant-2008R2
```

```powershell
PS> $PSVersionTable
```

```
Name                           Value
----                           -----
PSVersion                      7.2.6
PSEdition                      Core
OS                             Linux 6.17.8-orbstack-00308-g8f9c941121b1
Platform                       Unix
```

### 1.2 Tableau récapitulatif

| Propriété | Valeur |
|-----------|--------|
| Nom de la machine | VAGRANT-2008R2 |
| Système d'exploitation | Microsoft Windows Server 2008 R2 Standard |
| Version | 6.1.7601 Service Pack 1 Build 7601 |
| Architecture | x64 |
| Configuration | Standalone Server (WORKGROUP) |
| Fabricant système | innotek GmbH (VirtualBox) |
| Processeur | Intel64 ~1992 Mhz |
| RAM totale | 4 096 Mo |
| Disque C: | 52.93 Go utilisés / 648.24 Go libres |
| Version PowerShell | 7.2.6 (Core) |
| Correctifs installés | 2 (KB3134760, KB976902) |
| Date d'installation | 06/08/2017 |
| Dernier démarrage | 05/10/2022 |

### 1.3 Problèmes de sécurité identifiés

- **Windows Server 2008 R2 est en fin de vie (EOL depuis janvier 2020).** Il ne reçoit plus de correctifs de sécurité, ce qui le rend vulnérable à toutes les CVE découvertes depuis. Comme indiqué dans le cours (*01 - systeminfo permet de vérifier rapidement le niveau de correctifs*), un nombre faible de hotfixes est un signal d'alerte.
  - **Commande :** `systeminfo` → "OS Name", "Hotfix(s)"
- **Seulement 2 correctifs installés** (KB3134760 et KB976902) depuis l'installation en 2017. Cela signifie que le serveur n'a quasiment jamais été mis à jour.
  - **Commande :** `systeminfo` → "Hotfix(s): 2 Hotfix(s) Installed"
- **PowerShell 7.2.6 est obsolète** (la version stable actuelle est 7.5.4). Des vulnérabilités connues peuvent exister.
  - **Commande :** `$PSVersionTable` → champ `PSVersion`
- **La machine n'a pas été redémarrée depuis le 05/10/2022**, ce qui signifie que les mises à jour noyau ne sont pas appliquées (cf. cours : *une machine jamais rebootée n'applique pas ses mises à jour noyau*).
  - **Commande :** `systeminfo` → "System Boot Time"

---

## 2. Gestion des utilisateurs et groupes

*Référence : cours 02 - Gestion des utilisateurs et groupes sous Windows*

### 2.1 Énumération des utilisateurs

```powershell
PS> net user
```

```
User accounts for \\VAGRANT-2008R2
-------------------------------------------------------------------------------
Administrator            Jeremie               Guest
vagrant
```

### 2.2 Détails de chaque utilisateur

Les détails ont été obtenus avec `net user <nom>` (cf. cours *02 - section 3.1*) :

```powershell
PS> net user Jeremie
```

```
User name                    Jeremie
Full Name                    Jeremie A.
Comment                      Lab Creator
Account active               Yes
Account expires              Never
Password last set            8/6/2017 7:15:52 PM
Password expires             Never
Password required            Yes
Last logon                   10/6/2022 7:56:45 AM
Local Group Memberships      *Users
```

```powershell
PS> net user Administrator
```

```
User name                    Administrator
Comment                      Built-in account for administering the computer/domain
Account active               Yes
Account expires              Never
Password last set            8/6/2017 7:15:53 PM
Password expires             Never
Last logon                   11/20/2010 8:48:04 PM
Local Group Memberships      *Administrators
```

```powershell
PS> net user Guest
```

```
The user name could not be found.
```

```powershell
PS> net user vagrant
```

```
The user name could not be found.
```

| Utilisateur | Compte actif | Mot de passe expire | Dernière connexion | Groupes |
|-------------|-------------|---------------------|-------------------|---------|
| **Jeremie** | Oui | Jamais | 06/10/2022 | Users |
| **Administrator** | Oui | Jamais | 20/11/2010 | Administrators |
| **Guest** | Listé mais introuvable via `net user` | - | - | - |
| **vagrant** | Listé mais introuvable via `net user` | - | - | - |

### 2.3 Énumération des groupes

```powershell
PS> net localgroup
```

```
Aliases for \\VAGRANT-2008R2
------------------------------------------
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*Remote Desktop Users
*Replicator
*Users
*WinRMRemoteWMIUsers__
```

### 2.4 Membres du groupe Administrators

```powershell
PS> net localgroup Administrators
```

```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
sshd_server
```

### 2.5 Politique de mots de passe

La commande `net accounts` (cf. cours *02 - section 3.2*) affiche la politique globale :

```powershell
PS> net accounts
```

```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                 None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
```

### 2.6 Problèmes de sécurité identifiés

En comparant avec les bonnes pratiques du cours (*02 - section 2.3*) :

- **`sshd_server` fait partie du groupe Administrators.** C'est un compte de service qui ne devrait PAS avoir de privilèges administrateur (cf. cours : *principe du moindre privilège*). Si un attaquant compromet le service SSH ou exécute des commandes en tant que `sshd_server`, il obtient un accès administrateur complet. Il s'agit d'un **vecteur d'escalade de privilèges**.
  - **Commande :** `net localgroup Administrators`

- **Le compte Administrator est actif et non renommé.** Le cours indique : *le compte Administrator intégré est la première cible des attaques par force brute. Il convient de le renommer, de le désactiver ou d'appliquer des restrictions via GPO.* Ici, il est actif avec une dernière connexion en 2010 — le mot de passe est potentiellement faible ou par défaut.
  - **Commande :** `net user Administrator`

- **La politique de mots de passe est inexistante.** Le cours recommande une longueur minimale de 12 caractères (recommandation ANSSI), un historique de mots de passe, et une déconnexion automatique. Ici :
  - Longueur minimale : **0** (aucun minimum !)
  - Âge minimum : **0 jours**
  - Âge maximum : **Illimité** (les mots de passe n'expirent jamais)
  - Historique : **Aucun** (réutilisation possible)
  - Seuil de verrouillage : **Jamais** (aucune protection contre le brute-force !)
  - Déconnexion forcée : **Jamais**
  - **Commande :** `net accounts`

- **Le groupe Backup Operators existe.** Le cours prévient : *ce groupe permet de contourner les permissions de fichiers, ce qui représente un risque important. Son utilisation doit être surveillée.*
  - **Commande :** `net localgroup`

---

## 3. Services et exécutables en cours d'exécution

*Référence : cours 01 - section 2.2 (Processus et services)*

### 3.1 Services actifs

La commande `net start` (cf. cours *01 - section 2.2*) liste tous les services en cours :

```powershell
PS> net start
```

```
ManageEngine Desktop Central Server
MEDC Server Component - Apache
MEDC Server Component - Notification Server
Network Connections
Network List Service
Network Location Awareness
Network Store Interface Service
OpenSSH Server
Plug and Play
Power
Print Spooler
Remote Desktop Configuration
Remote Desktop Services
Remote Desktop Services UserMode Port Redirector
Remote Procedure Call (RPC)
Remote Registry
RPC Endpoint Mapper
Security Accounts Manager
Server
Shell Hardware Detection
Software Protection
System Event Notification Service
Task Scheduler
TCP/IP NetBIOS Helper
User Profile Service
VirtualBox Guest Additions Service
wampapache
wampmysqld
Windows Event Log
Windows Firewall
Windows Font Cache Service
Windows Licensing Monitoring Service
Windows Management Instrumentation
Windows Remote Management (WS-Management)
Windows Update
Workstation
```

### 3.2 Processus en cours

La commande `Get-Process` (cf. cours *01 - section 2.2*) affiche les processus actifs :

```powershell
PS> Get-Process | Format-Table -AutoSize Id, ProcessName, Path
```

```
 Id ProcessName Path
 -- ----------- ----
 42 pwsh        /mnt/rv/[rosetta]
684 pwsh        /opt/microsoft/powershell/7/pwsh
 41 sh          /mnt/rv/[rosetta]
683 sh          /mnt/rv/[rosetta]
  1 sshd
 38 sshd
 40 sshd
680 sshd
682 sshd
```

### 3.3 Tâches planifiées

*Référence : cours 04 - Planification de tâches sous Windows*

Comme indiqué dans le cours, les tâches planifiées sont un vecteur de **persistance** très répandu (technique **T1053.005** du framework MITRE ATT&CK). Plusieurs commandes ont été tentées pour les énumérer :

```powershell
PS> schtasks /query
PS> schtasks /query /fo LIST
PS> schtasks /query /fo TABLE /v
PS> Get-ScheduledTask
```

Aucune de ces commandes n'a retourné de résultats. Les clés de registre associées ont aussi été vérifiées :

```powershell
PS> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Schedule\TaskCache\Tasks
PS> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Schedule\TaskCache\Tree
```

```
ERROR: The system was unable to find the specified registry key or value.
```

Le dossier `C:\Windows\System32\Tasks` est vide. Cependant, le log du Task Scheduler a été retrouvé :

```powershell
PS> Get-ChildItem C:/Windows/Tasks -Force
```

```
Name         Length LastWriteTime
----         ------ -------------
SCHEDLGU.txt   3330 08/28/2024 15:05:29
```

```powershell
PS> Get-Content C:/Windows/Tasks/SCHEDLGU.txt
```

```
"Task Scheduler Service"
6.1.7600.16385 (win7_rtm.090713-1255)
  Started at 4/22/2018 11:55:23 AM
  ...
  Started at 10/6/2022 8:59:19 AM
[ ***** Most recent entry is above this line ***** ]
```

La version du Task Scheduler (**6.1.7600.16385** = build RTM) confirme que le système n'a jamais été mis à jour.

Les dossiers de démarrage automatique et les clés de registre d'auto-démarrage ont aussi été vérifiés :

```powershell
PS> dir "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"
PS> dir "C:/Users/Jeremie/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
PS> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
PS> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
PS> reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Tous vides ou introuvables. **Aucune tâche planifiée personnalisée ni programme de démarrage automatique n'a été identifié.**

### 3.4 Problèmes de sécurité identifiés

- **ManageEngine Desktop Central** est en cours d'exécution — ce logiciel a de nombreuses CVE critiques connues (ex : CVE-2020-10189 pour du RCE, CVE-2021-44515 pour un contournement d'authentification). Sur un serveur 2008 R2 non mis à jour, il est très probablement vulnérable.
  - **Commande :** `net start` → "ManageEngine Desktop Central Server", "MEDC Server Component - Apache", "MEDC Server Component - Notification Server"

- **Le service Remote Registry est actif** — il permet l'accès distant au registre Windows. Cela peut être utilisé pour de la collecte d'informations et potentiellement de l'escalade de privilèges.
  - **Commande :** `net start` → "Remote Registry"

- **Remote Desktop Services (RDP) est actif** sur le port 3389 — combiné avec la politique de mots de passe faible, c'est une cible pour le brute-force. Le cours (*02 - section 2.3*) recommande de restreindre le groupe `Remote Desktop Users` et de combiner avec du MFA et de la segmentation réseau.
  - **Commande :** `net start` → "Remote Desktop Services" + `netstat -ano` → port 3389

- **wampapache et wampmysqld sont actifs** — pile WAMP (Apache + MySQL). MySQL sur le port 3306 pourrait avoir des identifiants par défaut.
  - **Commande :** `net start` → "wampapache", "wampmysqld" + `netstat -ano` → port 3306

- **Windows Remote Management (WinRM)** est actif sur le port 5985 — peut être utilisé pour l'exécution de commandes à distance si des identifiants sont obtenus.
  - **Commande :** `net start` → "Windows Remote Management (WS-Management)" + `netstat -ano` → port 5985

- **VirtualBox Guest Additions** — indique que c'est une VM, possibilité de chemins d'escalade spécifiques à VBox.
  - **Commande :** `net start` → "VirtualBox Guest Additions Service"

- **Print Spooler est actif** — historiquement vulnérable à PrintNightmare (CVE-2021-34527) et d'autres exploits du spooler.
  - **Commande :** `net start` → "Print Spooler"

- **Le Task Scheduler est à la version RTM (6.1.7600.16385)**, jamais patché, cohérent avec le constat général d'un système non maintenu.
  - **Commande :** `Get-Content C:/Windows/Tasks/SCHEDLGU.txt`

---

## 4. Configuration réseau

*Référence : cours 01 - section 2.3 (Configuration et surveillance réseau)*

### 4.1 Configuration IP

```powershell
PS> ipconfig /all
```

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : vagrant-2008R2
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Local network wireless card* 2:
   Connection specific DNS suffix. . : jedha-cs-fullstack.org
   IPv6 Address. . . . . . . . . . . : fe80::fd3b:c93c:4ba8:834d%5
   IPv4 Address. . . . . . . . . . . : 10.10.7.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter Local Area Connection* 9:
   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
```

### 4.2 Partages réseau

Comme indiqué dans le cours (*01 - section 2.3*), les partages administratifs (`C$`, `ADMIN$`, `IPC$`) sont actifs par défaut. En contexte de durcissement, il est important d'évaluer s'ils doivent rester ouverts.

```powershell
PS> net share
```

```
Share name   Resource                        Remark
-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
```

### 4.3 Ports en écoute

La commande `netstat -ano` (cf. cours *01 - section 2.3*) affiche les connexions actives et ports en écoute. Le cours recommande de *croiser la sortie de `netstat -ano` avec `Get-Process` pour identifier quel programme est responsable de chaque connexion*.

```powershell
PS> netstat -ano | Select-String LISTENING
```

| Port | Protocole | PID | Service (déduit) |
|------|-----------|-----|------------------|
| 22 | TCP | 4100 | OpenSSH |
| 135 | TCP | 704 | RPC |
| 445 | TCP | 4 | SMB |
| 1617 | TCP | 1788 | ManageEngine |
| 3000 | TCP | 1988 | Serveur Rails |
| 3306 | TCP | 1196 | MySQL (WAMP) |
| 3389 | TCP | 5024 | Bureau à distance (RDP) |
| 3700 | TCP | 1836 | GlassFish |
| 4848 | TCP | 1836 | GlassFish Admin |
| 5985 | TCP | 4 | WinRM |
| 7676 | TCP | 1836 | GlassFish |
| 8005 | TCP | 2424 | Tomcat Shutdown (localhost uniquement) |
| 8009 | TCP | 2424 | Apache AJP |
| 8019-8032 | TCP | 1400/1724 | ManageEngine Desktop Central |
| 8080 | TCP | 1836 | GlassFish HTTP |
| 8181 | TCP | 1836 | GlassFish HTTPS |
| 8282 | TCP | 2424 | Apache Struts |
| 8383 | TCP | 1724 | ManageEngine Desktop Central |
| 8443-8444 | TCP | 1400 | ManageEngine HTTPS |
| 8484 | TCP | 2112 | Jenkins |
| 8585 | TCP | 3644 | WordPress / phpMyAdmin |
| 8686 | TCP | 1836 | GlassFish |
| 9200 | TCP | 1272 | ElasticSearch HTTP |
| 9300 | TCP | 1272 | ElasticSearch Transport |
| 32000 | TCP | 1088 | Inconnu (localhost uniquement) |
| 47001 | TCP | 4 | Écouteur WinRM |
| 161 | UDP | - | SNMP |

### 4.4 Configuration du pare-feu

```powershell
PS> netsh firewall show state
PS> netsh firewall show config
```

**Profil standard : mode opérationnel = DÉSACTIVÉ**

Le pare-feu est effectivement **désactivé** sur le profil standard. Des règles existent mais ne sont pas appliquées :

```
Standard profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Disable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable

Port configuration for Standard profile:
Port   Protocol  Mode     Traffic direction  Name
-------------------------------------------------------------------
3306   TCP       Disable  Inbound            Closed Port 3306 for MySQL
3389   TCP       Disable  Inbound            Closed Port 3389 for Remote Desktop
135    TCP       Disable  Inbound            Closed port 135 for NetBIOS
139    TCP       Disable  Inbound            Closed port 139 for NetBIOS
445    TCP       Disable  Inbound            Closed port 445 for SMB
161    UDP       Enable   Inbound            Open Port 161 for SNMP
9200   TCP       Enable   Inbound            Open Port 9200 for ElasticSearch
8022   TCP       Enable   Inbound            Open Port 8022 for ManageEngine Desktop Central
8383   TCP       Enable   Inbound            Open Port 8383 for ManageEngine Desktop Central
8020   TCP       Enable   Inbound            Open Port 8020 for ManageEngine Desktop Central
3000   TCP       Enable   Inbound            Open Port 3000 for Rails Server
8585   TCP       Enable   Inbound            Open Port 8585 for Wordpress and phpMyAdmin
8080   TCP       Enable   Inbound            Open Port 8080 for GlassFish
4848   TCP       Enable   Inbound            Open Port 4848 for GlassFish
80     TCP       Enable   Inbound            Open Port 80 for IIS
8282   TCP       Enable   Inbound            Open Port 8282 for Apache Struts
8484   TCP       Enable   Inbound            Open Port 8484 for Jenkins
3389   TCP       Enable   Inbound            Open Port 3389
22     TCP       Enable   Inbound            ssh
2222   TCP       Enable   Inbound            OpenSSH
```

### 4.5 Problèmes de sécurité identifiés

- **Le pare-feu est DÉSACTIVÉ** — tous les ports sont exposés sur le réseau, indépendamment des règles configurées. C'est une mauvaise configuration critique.
  - **Commande :** `netsh firewall show config` → "Operational mode = Disable"

- **Les partages administratifs sont actifs** (C$, ADMIN$, IPC$) — avec des identifiants admin, un attaquant pourrait accéder à l'intégralité du disque C: à distance.
  - **Commande :** `net share`

- **Surface d'attaque massive** — plus de 30 ports en écoute avec de multiples applications web :
  - **ElasticSearch (9200)** — souvent sans authentification par défaut, permet l'exfiltration de données
  - **Jenkins (8484)** — s'il n'est pas correctement sécurisé, permet l'exécution de code à distance via la console de scripts
  - **phpMyAdmin (8585)** — interface web de gestion MySQL, vulnérable au brute-force
  - **GlassFish Admin (4848)** — console d'administration du serveur d'applications, identifiants par défaut possibles
  - **Apache Struts (8282)** — historiquement vulnérable à des RCE critiques (ex : CVE-2017-5638)
  - **Serveur Rails (3000)** — vulnérabilités potentielles de l'application web
  - **ManageEngine (8020/8383)** — vulnérabilités critiques connues
  - **SNMP (UDP 161)** — si la communauté par défaut "public" est utilisée, fuite d'informations système
  - **Commandes :** `netstat -ano | Select-String LISTENING` + `netsh firewall show config`

---

## 5. Résumé des découvertes critiques

| # | Découverte | Sévérité | Catégorie | Commande(s) utilisée(s) |
|---|-----------|----------|-----------|------------------------|
| 1 | Windows Server 2008 R2 (fin de vie depuis 01/2020) | **CRITIQUE** | OS | `systeminfo`, `ver` |
| 2 | Seulement 2 correctifs installés depuis 2017 | **CRITIQUE** | OS | `systeminfo` → "Hotfix(s)" |
| 3 | Le pare-feu est DÉSACTIVÉ | **CRITIQUE** | Réseau | `netsh firewall show config` |
| 4 | `sshd_server` dans le groupe Administrators (escalade de privilèges) | **ÉLEVÉ** | Utilisateurs | `net localgroup Administrators` |
| 5 | Aucune politique de mots de passe (longueur=0, pas de verrouillage, pas d'expiration) | **ÉLEVÉ** | Utilisateurs | `net accounts` |
| 6 | ManageEngine Desktop Central (CVE critiques connues) | **ÉLEVÉ** | Services | `net start`, `netstat -ano` |
| 7 | Jenkins exposé (RCE potentiel via console de scripts) | **ÉLEVÉ** | Services | `netstat -ano` (port 8484) |
| 8 | ElasticSearch exposé (probablement sans authentification) | **ÉLEVÉ** | Services | `netstat -ano` (port 9200) |
| 9 | Apache Struts exposé (RCE critiques connus) | **ÉLEVÉ** | Services | `netstat -ano` (port 8282) |
| 10 | Print Spooler actif (potentiel PrintNightmare CVE-2021-34527) | **ÉLEVÉ** | Services | `net start` |
| 11 | Console d'administration GlassFish exposée (port 4848) | **MOYEN** | Services | `netstat -ano` (port 4848) |
| 12 | phpMyAdmin / WordPress exposés | **MOYEN** | Services | `netstat -ano` (port 8585) |
| 13 | MySQL (3306) exposé sur le réseau | **MOYEN** | Services | `netstat -ano` (port 3306) |
| 14 | Bureau à distance (3389) + mots de passe faibles | **MOYEN** | Réseau | `net start`, `netstat -ano`, `net accounts` |
| 15 | Remote Registry actif | **MOYEN** | Services | `net start` |
| 16 | Partages administratifs (C$, ADMIN$) actifs | **MOYEN** | Réseau | `net share` |
| 17 | WinRM (5985) exposé | **MOYEN** | Réseau | `net start`, `netstat -ano` (port 5985) |
| 18 | Compte Administrator actif, non renommé, dernière connexion en 2010 | **MOYEN** | Utilisateurs | `net user Administrator` |
| 19 | Machine non redémarrée depuis le 05/10/2022 | **MOYEN** | OS | `systeminfo` → "System Boot Time" |
| 20 | SNMP (UDP 161) ouvert — fuite d'informations possible | **FAIBLE** | Réseau | `netstat -ano`, `netsh firewall show config` |

---

## 6. Récapitulatif des commandes d'audit utilisées

| Commande | Usage | Référence cours |
|----------|-------|-----------------|
| `systeminfo` | Informations système complètes (OS, correctifs, RAM, etc.) | 01 - section 2.1 |
| `ver` | Version de Windows | 01 - section 2.1 |
| `hostname` | Nom de la machine | 01 - section 2.1 |
| `$PSVersionTable` | Version de PowerShell | - |
| `net user` / `net user <nom>` | Lister et détailler les utilisateurs | 02 - section 3.1 |
| `net localgroup` / `net localgroup <groupe>` | Lister les groupes et leurs membres | 02 - section 3.3 |
| `net accounts` | Politique de mots de passe | 02 - section 3.2 |
| `net start` | Services en cours d'exécution | 01 - section 2.2 |
| `Get-Process` | Processus actifs avec PID et chemin | 01 - section 2.2 |
| `schtasks /query` | Tâches planifiées (cmd) | 04 - section 3.7 |
| `Get-ScheduledTask` | Tâches planifiées (PowerShell) | 04 - section 3.7 |
| `ipconfig /all` | Configuration réseau complète | 01 - section 2.3 |
| `netstat -ano` | Ports en écoute et connexions actives | 01 - section 2.3 |
| `net share` | Partages réseau | 01 - section 2.3 |
| `netsh firewall show config` | Configuration du pare-feu | - |
