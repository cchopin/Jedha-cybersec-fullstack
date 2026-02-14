# Surveillance et detection dans Active Directory

**Module** : outils et techniques de monitoring pour la securite AD

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Connaitre les Event IDs critiques pour la securite AD dans l'Event Viewer
- Maitriser les cmdlets PowerShell de consultation des journaux d'evenements
- Comprendre le role et la configuration de Sysmon pour le monitoring avance
- Identifier des sequences d'evenements suspects plutot que des evenements isoles
- Utiliser PingCastle pour l'audit automatise de la configuration AD
- Utiliser BloodHound pour l'enumeration et l'analyse des chemins d'attaque

---

## 1. Windows Event Viewer

### 1.1 Principe

L'**Event Viewer** (Observateur d'evenements) est l'outil natif Windows pour consulter les journaux d'evenements. Les evenements lies a la securite AD sont enregistres dans le journal **Security** des Domain Controllers.

Chaque evenement possede un **Event ID** unique qui identifie le type d'action enregistree.

### 1.2 Event IDs critiques pour Kerberos

| Event ID | Description | Interet securite |
|---|---|---|
| **4768** | A Kerberos Authentication Ticket (TGT) was requested | Tentatives d'authentification, AS-REP Roasting |
| **4769** | A Kerberos Service Ticket (TGS) was requested | Kerberoasting (demandes TGS massives pour des SPN) |
| **4770** | A Kerberos Service Ticket was renewed | Renouvellement de tickets, potentiel abus de tickets |
| **4771** | Kerberos Pre-Authentication failed | Tentatives de brute-force, AS-REP Roasting |
| **4776** | The domain controller attempted to validate the credentials for an account | Validation NTLM, attaques pass-the-hash |

### 1.3 Event IDs pour la gestion des comptes

| Event ID | Description | Interet securite |
|---|---|---|
| **4720** | A user account was created | Creation de comptes suspects (backdoor) |
| **4722** | A user account was enabled | Reactivation de comptes desactives |
| **4724** | An attempt was made to reset an account's password | Reinitialisation de mot de passe non autorisee |
| **4725** | A user account was disabled | Desactivation de comptes legitimes (sabotage) |
| **4726** | A user account was deleted | Suppression de comptes (destruction de preuves) |
| **4728** | A member was added to a security-enabled global group | Ajout a un groupe global (ex. Domain Admins) |
| **4732** | A member was added to a security-enabled local group | Ajout a un groupe local (ex. Administrators) |
| **4756** | A member was added to a security-enabled universal group | Ajout a un groupe universel (ex. Enterprise Admins) |

### 1.4 Event IDs pour les modifications d'objets AD

| Event ID | Description | Interet securite |
|---|---|---|
| **5136** | A directory service object was modified | Modification d'attributs AD (ACL, SPN, delegation) |
| **5137** | A directory service object was created | Creation d'objets dans l'annuaire |
| **5141** | A directory service object was deleted | Suppression d'objets dans l'annuaire |
| **4662** | An operation was performed on an object | Operation DCSync (droits de replication) |

> **Bonne pratique** : activer l'audit avance sur les Domain Controllers via la GPO `Advanced Audit Policy Configuration`. En particulier, activer les sous-categories `Directory Service Changes` et `Kerberos Authentication Service`.

---

## 2. PowerShell pour la consultation des journaux

### 2.1 Get-EventLog (cmdlet classique)

La cmdlet `Get-EventLog` est l'ancienne methode pour consulter les journaux d'evenements classiques (Application, System, Security).

```powershell
# Lister les 20 derniers evenements de securite
Get-EventLog -LogName Security -Newest 20

# Filtrer par Event ID (ex. creation de compte utilisateur)
Get-EventLog -LogName Security -InstanceId 4720 -Newest 10

# Filtrer par plage de dates
Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) -InstanceId 4720

# Rechercher des evenements lies a un utilisateur specifique
Get-EventLog -LogName Security -Newest 100 |
    Where-Object { $_.Message -match "jarjar" }
```

> **A noter** : `Get-EventLog` ne fonctionne qu'avec les journaux classiques et ne supporte pas les journaux ETW (Event Tracing for Windows). Il est considere comme obsolete et remplace par `Get-WinEvent`.

### 2.2 Get-WinEvent (cmdlet moderne)

La cmdlet `Get-WinEvent` est la methode recommandee. Elle supporte tous les types de journaux, y compris les journaux ETW et les fichiers `.evtx`.

```powershell
# Lister les 20 derniers evenements de securite
Get-WinEvent -LogName Security -MaxEvents 20

# Filtrer par Event ID avec FilterHashtable (plus performant)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
} -MaxEvents 50

# Filtrer par Event ID et plage de dates
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4768, 4769, 4771
    StartTime = (Get-Date).AddDays(-1)
} | Format-Table TimeCreated, Id, Message -Wrap

# Rechercher les demandes TGS massives (indicateur de Kerberoasting)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = (Get-Date).AddHours(-1)
} | Group-Object { $_.Properties[0].Value } |
    Where-Object { $_.Count -gt 10 } |
    Select-Object Count, Name

# Lire un fichier .evtx exporte
Get-WinEvent -Path "C:\Logs\Security_backup.evtx" -MaxEvents 100
```

### 2.3 Exemples de requetes de detection

```powershell
# Detecter les ajouts aux groupes privilegies (Domain Admins, Enterprise Admins)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4728, 4732, 4756
    StartTime = (Get-Date).AddDays(-7)
} | ForEach-Object {
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        EventID  = $_.Id
        Group    = $_.Properties[2].Value
        Member   = $_.Properties[0].Value
        ChangedBy = $_.Properties[6].Value
    }
}

# Detecter les reinitialisations de mot de passe
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4724
    StartTime = (Get-Date).AddDays(-1)
} | ForEach-Object {
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        Target    = $_.Properties[0].Value
        ResetBy   = $_.Properties[4].Value
    }
}
```

---

## 3. Sysmon (System Monitor)

### 3.1 Presentation

**Sysmon** (System Monitor) est un outil de la suite **Sysinternals** de Microsoft. Il s'installe comme un service et un pilote de peripherique pour monitorer et enregistrer l'activite du systeme dans le journal d'evenements Windows.

Sysmon va bien au-dela des journaux natifs en capturant des informations detaillees sur la creation de processus, les connexions reseau, la creation de fichiers et les modifications du registre.

### 3.2 Installation avec configuration SwiftOnSecurity

La configuration recommandee pour un deploiement en production est celle maintenue par **SwiftOnSecurity** qui filtre les evenements bruyants et se concentre sur les indicateurs de compromission.

```powershell
# Telecharger Sysmon depuis Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Telecharger la configuration SwiftOnSecurity
# https://github.com/SwiftOnSecurity/sysmon-config

# Installer Sysmon avec la configuration
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml

# Mettre a jour la configuration
.\Sysmon64.exe -c sysmonconfig-export.xml

# Verifier l'installation
Get-Service Sysmon64
```

### 3.3 Event IDs Sysmon importants

| Event ID | Nom | Description | Interet securite |
|---|---|---|---|
| **1** | Process Create | Creation d'un processus avec ligne de commande complete | Detection d'execution d'outils offensifs (Mimikatz, SharpHound, etc.) |
| **3** | Network Connection | Connexion reseau initiee par un processus | Detection de beaconing C2, lateral movement |
| **7** | Image Loaded | Chargement d'une DLL par un processus | Detection de DLL injection, DLL sideloading |
| **8** | CreateRemoteThread | Creation d'un thread dans un autre processus | Detection d'injection de code |
| **10** | Process Access | Acces a un processus par un autre processus | Detection de dump de LSASS |
| **11** | File Create | Creation de fichier | Detection de drop de payloads, fichiers suspects |
| **12** | Registry Value Set | Modification d'une valeur de registre | Detection de persistence (Run keys, services) |
| **13** | Registry Value Set | Modification de valeur de registre | Detection de modifications de configuration |
| **15** | File Create Stream Hash | Creation d'un Alternate Data Stream | Detection de dissimulation de donnees |
| **22** | DNS Query | Requete DNS effectuee par un processus | Detection de DNS tunneling, domaines C2 |
| **25** | Process Tampering | Modification d'image de processus | Detection de process hollowing |

### 3.4 Consultation des journaux Sysmon

```powershell
# Lister les derniers evenements Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20

# Filtrer les creations de processus (Event ID 1)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap

# Detecter les acces a LSASS (Event ID 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 10
} | Where-Object { $_.Message -match "lsass.exe" }

# Detecter les connexions reseau suspectes (Event ID 3)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3
} -MaxEvents 100 | Where-Object {
    $_.Message -match "DestinationPort: (4444|5555|8080|8443)"
}
```

---

## 4. Detection par sequences d'evenements

### 4.1 Principe

La detection d'attaques ne repose pas sur des evenements isoles mais sur des **sequences d'evenements** qui, prises ensemble, indiquent un comportement suspect. Un evenement 4769 (demande TGS) est normal ; 50 evenements 4769 en 2 minutes pour des SPN differents par le meme utilisateur est un indicateur de Kerberoasting.

### 4.2 Exemples de sequences suspectes

| Sequence | Attaque probable |
|---|---|
| Multiple 4769 (TGS requests) depuis le meme compte en peu de temps | Kerberoasting |
| 4768 (TGT request) avec un type de chiffrement faible (RC4) | AS-REP Roasting ou attaque downgrade |
| 4720 (creation compte) suivi de 4728 (ajout a un groupe) sur Domain Admins | Creation de backdoor |
| 5136 (modification AD) sur l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` | Configuration de RBCD malveillante |
| 4662 (operation sur objet) avec des GUID de replication depuis une machine non-DC | Attaque DCSync |
| Sysmon 1 (process create) pour `mimikatz.exe` suivi de Sysmon 10 (process access) sur `lsass.exe` | Extraction de credentials |

### 4.3 Correlation manuelle avec PowerShell

```powershell
# Detecter un potentiel Kerberoasting : plus de 10 demandes TGS
# depuis le meme compte en moins d'une heure
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = (Get-Date).AddHours(-1)
}

$events | Group-Object { $_.Properties[0].Value } |
    Where-Object { $_.Count -gt 10 } |
    ForEach-Object {
        Write-Warning "Potentiel Kerberoasting : $($_.Name) - $($_.Count) demandes TGS"
    }
```

---

## 5. SIEM (Security Information and Event Management)

Un **SIEM** centralise les evenements provenant de multiples sources (Domain Controllers, serveurs membres, postes de travail, equipements reseau) et applique des regles de correlation automatisees.

La mise en place d'un SIEM sera couverte dans un module ulterieur du programme. Les principaux SIEM du marche sont :

| SIEM | Type | Remarque |
|---|---|---|
| **Splunk** | Commercial | Leader du marche, puissant mais couteux |
| **Microsoft Sentinel** | Cloud (Azure) | Integration native avec les environnements Microsoft |
| **Elastic SIEM** | Open source | Base sur la stack Elastic (Elasticsearch, Kibana) |
| **Wazuh** | Open source | Alternative open source complete |

> **A noter** : meme sans SIEM, la centralisation des journaux via **Windows Event Forwarding** (WEF) vers un serveur collecteur est une premiere etape essentielle.

---

## 6. PingCastle : audit automatise AD

### 6.1 Presentation

**PingCastle** est un outil d'audit automatise pour Active Directory developpe par Vincent Le Toux. Il analyse la configuration du domaine et genere un **dashboard de securite** avec un score global et des recommandations detaillees.

### 6.2 Categories d'evaluation

PingCastle evalue la securite du domaine selon quatre axes :

| Categorie | Description |
|---|---|
| **Stale Objects** | Comptes inactifs, machines obsoletes, comptes jamais utilises |
| **Privileged Accounts** | Nombre de comptes privilegies, comptes de service dans Domain Admins |
| **Trust** | Relations d'approbation entre domaines, delegation |
| **Anomalies** | Misconfigurations detectees (ACL, GPO, delegation, etc.) |

### 6.3 Utilisation

```cmd
# Lancer un audit du domaine courant
PingCastle.exe --healthcheck

# Lancer un audit d'un domaine specifique
PingCastle.exe --healthcheck --server corp.local

# Generer un rapport consolide pour plusieurs domaines
PingCastle.exe --healthcheck --server corp.local --level Full
```

Le rapport HTML genere contient :

- Un **score global** (de 0 a 100, 0 etant le meilleur)
- Un detail par categorie avec les points de deduction
- Des **recommandations priorisees** avec les actions correctives
- Une cartographie des relations d'approbation

> **Bonne pratique** : executer PingCastle au minimum une fois par trimestre et suivre l'evolution du score dans le temps. Prioriser les corrections par niveau de risque (critique, eleve, modere).

---

## 7. BloodHound : enumeration et analyse des chemins d'attaque

### 7.1 Presentation

**BloodHound** est un outil d'enumeration et d'analyse graphique pour Active Directory. Il permet de visualiser les **chemins d'attaque** possibles dans un domaine en cartographiant les relations entre utilisateurs, groupes, machines, ACL, sessions et delegations.

BloodHound se compose de deux elements :

| Composant | Role | Technologie |
|---|---|---|
| **BloodHound** (interface web) | Visualisation et analyse des donnees collectees | Application web (Neo4j / PostgreSQL) |
| **SharpHound** | Collecteur de donnees (ingestor) | Executable .NET ou script PowerShell |

### 7.2 Installation sur Kali Linux

L'installation recommandee utilise **bloodhound-cli** via pip :

```bash
# Installer bloodhound-cli
pip install bloodhound

# Ou installer via apt sur Kali
sudo apt install bloodhound

# Demarrer BloodHound (interface web sur le port 8080)
sudo bloodhound-ce start

# Acceder a l'interface web
# Ouvrir un navigateur sur http://localhost:8080
```

Lors du premier demarrage, BloodHound affiche les credentials d'administration initiales dans le terminal. Les noter pour se connecter a l'interface web.

### 7.3 Collecte de donnees avec SharpHound

**SharpHound** est le collecteur officiel de BloodHound. Il enumere les objets AD, les sessions, les ACL et les relations de confiance, puis exporte les donnees dans un fichier ZIP.

```cmd
# Collecte complete depuis une machine jointe au domaine
SharpHound.exe -c All

# Collecte avec un domaine specifique
SharpHound.exe -c All -d corp.local

# Collecte silencieuse (moins de bruit)
SharpHound.exe -c DCOnly
```

> **A noter** : l'execution de SharpHound declenche des alertes de securite sur les systemes correctement configures (EDR, antivirus). La collecte genere un volume important de requetes LDAP et des connexions vers chaque machine du domaine pour enumerer les sessions.

### 7.4 Alternative : collecte a distance avec Python

Pour les situations ou l'execution de SharpHound sur une machine du domaine n'est pas possible (ou trop risquee), des collecteurs Python permettent une collecte a distance :

```bash
# Collecte a distance avec bloodhound-python
bloodhound-python -u 'utilisateur' -p 'motdepasse' -d corp.local -ns 10.0.0.1 -c All

# Le resultat est un ensemble de fichiers JSON
ls *.json
# computers.json  domains.json  groups.json  users.json
```

### 7.5 Import des donnees

Une fois la collecte terminee, le fichier ZIP (le **loot**) doit etre transfere vers la machine Kali pour import dans BloodHound.

```bash
# Transferer le loot depuis la machine Windows vers Kali via scp
scp utilisateur@machine-windows:C:\Users\utilisateur\*.zip /tmp/loot/

# Importer via l'interface web de BloodHound
# 1. Se connecter a http://localhost:8080
# 2. Aller dans la section "File Ingest"
# 3. Uploader le fichier ZIP
```

### 7.6 Requetes utiles dans BloodHound

Une fois les donnees importees, BloodHound propose des requetes pre-construites et permet d'en creer des personnalisees :

| Requete | Description |
|---|---|
| **Find Shortest Paths to Domain Admins** | Chemins d'attaque les plus courts vers Domain Admins |
| **Find Principals with DCSync Rights** | Comptes avec droits de replication (potentiel DCSync) |
| **Find Computers with Unconstrained Delegation** | Machines en delegation non contrainte |
| **Find All Kerberoastable Users** | Comptes utilisateurs avec SPN (cibles de Kerberoasting) |
| **Find Shortest Paths to High Value Targets** | Chemins vers tous les objets critiques |
| **List All Owned Principals** | Visualiser les comptes deja compromis et les chemins restants |

> **Bonne pratique** : utiliser BloodHound en mode defensif (Blue Team) pour identifier et corriger les chemins d'attaque avant qu'un attaquant ne les exploite. Executer une collecte reguliere et comparer les resultats dans le temps.

---

## Pour aller plus loin

- [Microsoft -- Advanced Security Audit Policies](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Microsoft -- Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity -- Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [PingCastle -- Site officiel](https://www.pingcastle.com/)
- [BloodHound -- Documentation officielle](https://bloodhound.readthedocs.io/)
- [SANS -- Windows Event ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft -- Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
