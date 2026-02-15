# Surveillance et détection dans Active Directory

**Module** : outils et techniques de monitoring pour la sécurité AD

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Connaître les Event IDs critiques pour la sécurité AD dans l'Event Viewer
- Maîtriser les cmdlets PowerShell de consultation des journaux d'événements
- Comprendre le rôle et la configuration de Sysmon pour le monitoring avancé
- Identifier des séquences d'événements suspects plutôt que des événements isolés
- Utiliser PingCastle pour l'audit automatisé de la configuration AD
- Utiliser BloodHound pour l'énumération et l'analyse des chemins d'attaque

---

## 1. Windows Event Viewer

### 1.1 Principe

L'**Event Viewer** (Observateur d'événements) est l'outil natif Windows pour consulter les journaux d'événements. Les événements liés à la sécurité AD sont enregistrés dans le journal **Security** des Domain Controllers.

Chaque événement possède un **Event ID** unique qui identifie le type d'action enregistrée.

### 1.2 Event IDs critiques pour Kerberos

| Event ID | Description | Intérêt sécurité |
|---|---|---|
| **4768** | A Kerberos Authentication Ticket (TGT) was requested | Tentatives d'authentification, AS-REP Roasting |
| **4769** | A Kerberos Service Ticket (TGS) was requested | Kerberoasting (demandes TGS massives pour des SPN) |
| **4770** | A Kerberos Service Ticket was renewed | Renouvellement de tickets, potentiel abus de tickets |
| **4771** | Kerberos Pre-Authentication failed | Tentatives de brute-force, AS-REP Roasting |
| **4776** | The domain controller attempted to validate the credentials for an account | Validation NTLM, attaques pass-the-hash |

### 1.3 Event IDs pour la gestion des comptes

| Event ID | Description | Intérêt sécurité |
|---|---|---|
| **4720** | A user account was created | Création de comptes suspects (backdoor) |
| **4722** | A user account was enabled | Réactivation de comptes désactivés |
| **4724** | An attempt was made to reset an account's password | Réinitialisation de mot de passe non autorisée |
| **4725** | A user account was disabled | Désactivation de comptes légitimes (sabotage) |
| **4726** | A user account was deleted | Suppression de comptes (destruction de preuves) |
| **4728** | A member was added to a security-enabled global group | Ajout à un groupe global (ex. Domain Admins) |
| **4732** | A member was added to a security-enabled local group | Ajout à un groupe local (ex. Administrators) |
| **4756** | A member was added to a security-enabled universal group | Ajout à un groupe universel (ex. Enterprise Admins) |

### 1.4 Event IDs pour les modifications d'objets AD

| Event ID | Description | Intérêt sécurité |
|---|---|---|
| **5136** | A directory service object was modified | Modification d'attributs AD (ACL, SPN, délégation) |
| **5137** | A directory service object was created | Création d'objets dans l'annuaire |
| **5141** | A directory service object was deleted | Suppression d'objets dans l'annuaire |
| **4662** | An operation was performed on an object | Opération DCSync (droits de réplication) |

> **Bonne pratique** : activer l'audit avancé sur les Domain Controllers via la GPO `Advanced Audit Policy Configuration`. En particulier, activer les sous-catégories `Directory Service Changes` et `Kerberos Authentication Service`.

---

## 2. PowerShell pour la consultation des journaux

### 2.1 Get-EventLog (cmdlet classique)

La cmdlet `Get-EventLog` est l'ancienne méthode pour consulter les journaux d'événements classiques (Application, System, Security).

```powershell
# Lister les 20 derniers événements de sécurité
Get-EventLog -LogName Security -Newest 20

# Filtrer par Event ID (ex. création de compte utilisateur)
Get-EventLog -LogName Security -InstanceId 4720 -Newest 10

# Filtrer par plage de dates
Get-EventLog -LogName Security -After (Get-Date).AddDays(-7) -InstanceId 4720

# Rechercher des événements liés à un utilisateur spécifique
Get-EventLog -LogName Security -Newest 100 |
    Where-Object { $_.Message -match "jarjar" }
```

> **À noter** : `Get-EventLog` ne fonctionne qu'avec les journaux classiques et ne supporte pas les journaux ETW (Event Tracing for Windows). Il est considéré comme obsolète et remplacé par `Get-WinEvent`.

### 2.2 Get-WinEvent (cmdlet moderne)

La cmdlet `Get-WinEvent` est la méthode recommandée. Elle supporte tous les types de journaux, y compris les journaux ETW et les fichiers `.evtx`.

```powershell
# Lister les 20 derniers événements de sécurité
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

# Lire un fichier .evtx exporté
Get-WinEvent -Path "C:\Logs\Security_backup.evtx" -MaxEvents 100
```

### 2.3 Exemples de requêtes de détection

```powershell
# Détecter les ajouts aux groupes privilégiés (Domain Admins, Enterprise Admins)
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

# Détecter les réinitialisations de mot de passe
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

### 3.1 Présentation

**Sysmon** (System Monitor) est un outil de la suite **Sysinternals** de Microsoft. Il s'installe comme un service et un pilote de périphérique pour monitorer et enregistrer l'activité du système dans le journal d'événements Windows.

Sysmon va bien au-delà des journaux natifs en capturant des informations détaillées sur la création de processus, les connexions réseau, la création de fichiers et les modifications du registre.

### 3.2 Installation avec configuration SwiftOnSecurity

La configuration recommandée pour un déploiement en production est celle maintenue par **SwiftOnSecurity** qui filtre les événements bruyants et se concentre sur les indicateurs de compromission.

```powershell
# Télécharger Sysmon depuis Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Télécharger la configuration SwiftOnSecurity
# https://github.com/SwiftOnSecurity/sysmon-config

# Installer Sysmon avec la configuration
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml

# Mettre à jour la configuration
.\Sysmon64.exe -c sysmonconfig-export.xml

# Vérifier l'installation
Get-Service Sysmon64
```

### 3.3 Event IDs Sysmon importants

| Event ID | Nom | Description | Intérêt sécurité |
|---|---|---|---|
| **1** | Process Create | Création d'un processus avec ligne de commande complète | Détection d'exécution d'outils offensifs (Mimikatz, SharpHound, etc.) |
| **3** | Network Connection | Connexion réseau initiée par un processus | Détection de beaconing C2, lateral movement |
| **7** | Image Loaded | Chargement d'une DLL par un processus | Détection de DLL injection, DLL sideloading |
| **8** | CreateRemoteThread | Création d'un thread dans un autre processus | Détection d'injection de code |
| **10** | Process Access | Accès à un processus par un autre processus | Détection de dump de LSASS |
| **11** | File Create | Création de fichier | Détection de drop de payloads, fichiers suspects |
| **12** | Registry Value Set | Modification d'une valeur de registre | Détection de persistence (Run keys, services) |
| **13** | Registry Value Set | Modification de valeur de registre | Détection de modifications de configuration |
| **15** | File Create Stream Hash | Création d'un Alternate Data Stream | Détection de dissimulation de données |
| **22** | DNS Query | Requête DNS effectuée par un processus | Détection de DNS tunneling, domaines C2 |
| **25** | Process Tampering | Modification d'image de processus | Détection de process hollowing |

### 3.4 Consultation des journaux Sysmon

```powershell
# Lister les derniers événements Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20

# Filtrer les créations de processus (Event ID 1)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap

# Détecter les accès à LSASS (Event ID 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 10
} | Where-Object { $_.Message -match "lsass.exe" }

# Détecter les connexions réseau suspectes (Event ID 3)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3
} -MaxEvents 100 | Where-Object {
    $_.Message -match "DestinationPort: (4444|5555|8080|8443)"
}
```

---

## 4. Détection par séquences d'événements

### 4.1 Principe

La détection d'attaques ne repose pas sur des événements isolés mais sur des **séquences d'événements** qui, prises ensemble, indiquent un comportement suspect. Un événement 4769 (demande TGS) est normal ; 50 événements 4769 en 2 minutes pour des SPN différents par le même utilisateur est un indicateur de Kerberoasting.

### 4.2 Exemples de séquences suspectes

| Séquence | Attaque probable |
|---|---|
| Multiple 4769 (TGS requests) depuis le même compte en peu de temps | Kerberoasting |
| 4768 (TGT request) avec un type de chiffrement faible (RC4) | AS-REP Roasting ou attaque downgrade |
| 4720 (création compte) suivi de 4728 (ajout à un groupe) sur Domain Admins | Création de backdoor |
| 5136 (modification AD) sur l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` | Configuration de RBCD malveillante |
| 4662 (opération sur objet) avec des GUID de réplication depuis une machine non-DC | Attaque DCSync |
| Sysmon 1 (process create) pour `mimikatz.exe` suivi de Sysmon 10 (process access) sur `lsass.exe` | Extraction de credentials |

### 4.3 Corrélation manuelle avec PowerShell

```powershell
# Détecter un potentiel Kerberoasting : plus de 10 demandes TGS
# depuis le même compte en moins d'une heure
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

Un **SIEM** centralise les événements provenant de multiples sources (Domain Controllers, serveurs membres, postes de travail, équipements réseau) et applique des règles de corrélation automatisées.

La mise en place d'un SIEM sera couverte dans un module ultérieur du programme. Les principaux SIEM du marché sont :

| SIEM | Type | Remarque |
|---|---|---|
| **Splunk** | Commercial | Leader du marché, puissant mais coûteux |
| **Microsoft Sentinel** | Cloud (Azure) | Intégration native avec les environnements Microsoft |
| **Elastic SIEM** | Open source | Basé sur la stack Elastic (Elasticsearch, Kibana) |
| **Wazuh** | Open source | Alternative open source complète |

> **À noter** : même sans SIEM, la centralisation des journaux via **Windows Event Forwarding** (WEF) vers un serveur collecteur est une première étape essentielle.

---

## 6. PingCastle : audit automatisé AD

### 6.1 Présentation

**PingCastle** est un outil d'audit automatisé pour Active Directory développé par Vincent Le Toux. Il analyse la configuration du domaine et génère un **dashboard de sécurité** avec un score global et des recommandations détaillées.

### 6.2 Catégories d'évaluation

PingCastle évalue la sécurité du domaine selon quatre axes :

| Catégorie | Description |
|---|---|
| **Stale Objects** | Comptes inactifs, machines obsolètes, comptes jamais utilisés |
| **Privileged Accounts** | Nombre de comptes privilégiés, comptes de service dans Domain Admins |
| **Trust** | Relations d'approbation entre domaines, délégation |
| **Anomalies** | Misconfigurations détectées (ACL, GPO, délégation, etc.) |

### 6.3 Utilisation

```cmd
# Lancer un audit du domaine courant
PingCastle.exe --healthcheck

# Lancer un audit d'un domaine spécifique
PingCastle.exe --healthcheck --server corp.local

# Générer un rapport consolidé pour plusieurs domaines
PingCastle.exe --healthcheck --server corp.local --level Full
```

Le rapport HTML généré contient :

- Un **score global** (de 0 à 100, 0 étant le meilleur)
- Un détail par catégorie avec les points de déduction
- Des **recommandations priorisées** avec les actions correctives
- Une cartographie des relations d'approbation

> **Bonne pratique** : exécuter PingCastle au minimum une fois par trimestre et suivre l'évolution du score dans le temps. Prioriser les corrections par niveau de risque (critique, élevé, modéré).

---

## 7. BloodHound : énumération et analyse des chemins d'attaque

### 7.1 Présentation

**BloodHound** est un outil d'énumération et d'analyse graphique pour Active Directory. Il permet de visualiser les **chemins d'attaque** possibles dans un domaine en cartographiant les relations entre utilisateurs, groupes, machines, ACL, sessions et délégations.

BloodHound se compose de deux éléments :

| Composant | Rôle | Technologie |
|---|---|---|
| **BloodHound** (interface web) | Visualisation et analyse des données collectées | Application web (Neo4j / PostgreSQL) |
| **SharpHound** | Collecteur de données (ingestor) | Exécutable .NET ou script PowerShell |

### 7.2 Installation sur Kali Linux

L'installation recommandée utilise **bloodhound-cli** via pip :

```bash
# Installer bloodhound-cli
pip install bloodhound

# Ou installer via apt sur Kali
sudo apt install bloodhound

# Démarrer BloodHound (interface web sur le port 8080)
sudo bloodhound-ce start

# Accéder à l'interface web
# Ouvrir un navigateur sur http://localhost:8080
```

Lors du premier démarrage, BloodHound affiche les credentials d'administration initiales dans le terminal. Les noter pour se connecter à l'interface web.

### 7.3 Collecte de données avec SharpHound

**SharpHound** est le collecteur officiel de BloodHound. Il énumère les objets AD, les sessions, les ACL et les relations de confiance, puis exporte les données dans un fichier ZIP.

```cmd
# Collecte complète depuis une machine jointe au domaine
SharpHound.exe -c All

# Collecte avec un domaine spécifique
SharpHound.exe -c All -d corp.local

# Collecte silencieuse (moins de bruit)
SharpHound.exe -c DCOnly
```

> **À noter** : l'exécution de SharpHound déclenche des alertes de sécurité sur les systèmes correctement configurés (EDR, antivirus). La collecte génère un volume important de requêtes LDAP et des connexions vers chaque machine du domaine pour énumérer les sessions.

### 7.4 Alternative : collecte à distance avec Python

Pour les situations où l'exécution de SharpHound sur une machine du domaine n'est pas possible (ou trop risquée), des collecteurs Python permettent une collecte à distance :

```bash
# Collecte à distance avec bloodhound-python
bloodhound-python -u 'utilisateur' -p 'motdepasse' -d corp.local -ns 10.0.0.1 -c All

# Le résultat est un ensemble de fichiers JSON
ls *.json
# computers.json  domains.json  groups.json  users.json
```

### 7.5 Import des données

Une fois la collecte terminée, le fichier ZIP (le **loot**) doit être transféré vers la machine Kali pour import dans BloodHound.

```bash
# Transférer le loot depuis la machine Windows vers Kali via scp
scp utilisateur@machine-windows:C:\Users\utilisateur\*.zip /tmp/loot/

# Importer via l'interface web de BloodHound
# 1. Se connecter à http://localhost:8080
# 2. Aller dans la section "File Ingest"
# 3. Uploader le fichier ZIP
```

### 7.6 Requêtes utiles dans BloodHound

Une fois les données importées, BloodHound propose des requêtes pré-construites et permet d'en créer des personnalisées :

| Requête | Description |
|---|---|
| **Find Shortest Paths to Domain Admins** | Chemins d'attaque les plus courts vers Domain Admins |
| **Find Principals with DCSync Rights** | Comptes avec droits de réplication (potentiel DCSync) |
| **Find Computers with Unconstrained Delegation** | Machines en délégation non contrainte |
| **Find All Kerberoastable Users** | Comptes utilisateurs avec SPN (cibles de Kerberoasting) |
| **Find Shortest Paths to High Value Targets** | Chemins vers tous les objets critiques |
| **List All Owned Principals** | Visualiser les comptes déjà compromis et les chemins restants |

> **Bonne pratique** : utiliser BloodHound en mode défensif (Blue Team) pour identifier et corriger les chemins d'attaque avant qu'un attaquant ne les exploite. Exécuter une collecte régulière et comparer les résultats dans le temps.

---

## Pour aller plus loin

- [Microsoft -- Advanced Security Audit Policies](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Microsoft -- Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity -- Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [PingCastle -- Site officiel](https://www.pingcastle.com/)
- [BloodHound -- Documentation officielle](https://bloodhound.readthedocs.io/)
- [SANS -- Windows Event ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft -- Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)
