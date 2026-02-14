# Prise en main de la sécurité Windows

**Module** : outils d'administration Windows

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Naviguer dans l'arborescence Windows et identifier les dossiers critiques pour la sécurité
- Utiliser les commandes système essentielles pour auditer une machine
- Connaitre les outils d'administration et savoir quand les utiliser

---

## Pourquoi maîtriser Windows en cybersécurité ?

Avec plus de 70 % de parts de marché mondial, Windows est de loin le système d'exploitation le plus déployé en entreprise. C'est donc aussi la cible principale des attaquants. Toute démarché d'administration ou de sécurisation d'un SI passe inévitablement par une maîtrise solide de cet environnement.

Ce module pose les basés : système de fichiers, commandes d'audit, outils d'administration. Ces connaissances seront mobilisées dans tous les modules suivants du programme.

---

## 1. Le système de fichiers Windows (NTFS)

### 1.1 Vue d'ensemble de l'arborescence

Windows utilisé le système de fichiers **NTFS** (New Technology File System). L'arborescence racine est accèssible via PowerShell :

```powershell
cd /
dir
```

Résultat typique :

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/1/2024   9:26 AM                PerfLogs
d-r---         4/2/2025   1:40 AM                Program Files
d-r---         4/1/2024  10:31 AM                Program Files (x86)
d-r---         4/1/2025   5:25 PM                Users
d-----         4/1/2025  11:55 PM                Windows
d-----         4/2/2025   2:39 AM                Windows.old
```

### 1.2 Role de chaque dossier racine

| Dossier | Role |
|---|---|
| `PerfLogs` | Journaux de performance système (utilisés par l'Analyseur de performances) |
| `Program Files` | Applications **64 bits** installées (Excel, Firefox, etc.) |
| `Program Files (x86)` | Applications **32 bits** sur un Windows 64 bits |
| `Users` | Profils utilisateurs et donnees personnelles (Bureau, Documents...). Un utilisateur standard ne peut pas accéder au profil d'un autre |
| `Windows` | Répertoire d'installation du système d'exploitation |
| `Windows.old` | Sauvegarde de l'installation précédente, utilisée pour un éventuel retour en arrière apres mise à jour |

> **Bonne pratique** : prendre le temps d'explorer ces dossiers pour se familiariser avec la structure. En revanche, ne jamais supprimer de fichiers dans `C:\Windows` sous peine de corrompre le système.

### 1.3 Le dossier `C:\Windows` en détail

C'est le dossier le moins intuitif, mais aussi le plus important à connaître en cybersécurité. Voici les sous-dossiers essentiels, regroupés par usage :

**Coeur du système**

| Dossier | Contenu | Intérêt sécurité |
|---|---|---|
| `System32` | Exécutables (.exe), bibliothèques (.dll), pilotes (.sys), services. On y trouve `cmd.exe`, `taskmgr.exe`, `powershell.exe` | Analyse de malwares, escalade de privilèges |
| `WinSxS` | Stockage "Side-by-Side" de toutes les versions de composants Windows | Gestion des correctifs, comprehension du DLL hijacking |
| `assembly` | Global Assembly Cache (GAC) : bibliothèques .NET | Analyse de malwares .NET, attaques LOLBAS |

**Journalisation et diagnostic**

| Dossier | Contenu | Intérêt sécurité |
|---|---|---|
| `Logs` | Journaux générés par l'OS (`CBS.log`, `WindowsUpdate.log`...) | Diagnostic, investigation forensique |
| `Prefetch` | Métadonnées d'execution des applications (optimisation de lancement) | Forensique : retracer l'historique d'execution des programmes |
| `Temp` / `%TEMP%` | Fichiers temporaires d'installation et d'execution | Souvent utilisé par les malwares pour déposer leurs charges utiles |

**Configuration et persistence**

| Dossier | Contenu | Intérêt sécurité |
|---|---|---|
| `Tasks` / `System32\Tasks` | Définitions des tâches planifiées | Détournement fréquent pour la persistence (lancement de malwares au démarrage) |
| `INF` | Fichiers `.inf` de configuration des pilotes | Détection de malwares basés sur les pilotes |
| `PolicyDéfinitions` | Templates ADMX pour les stratégies de groupe (GPO) | Gestion des GPO et politique de sécurité |

**Autres**

| Dossier | Contenu | Intérêt sécurité |
|---|---|---|
| `SystemApps` | Applications modernes intégrées (Paramètres, Cortana...) | Debloating, comprehension de l'architecture UWP |
| `Fonts` | Polices système (.ttf, .otf) | DLL hijacking via polices (rare) |
| `Resources` | Themes, sons, fonds d'ecran | Rarement cible, utile pour le durcissement |

> **À noter** : beaucoup de ces dossiers sont masqués ou protégés par défaut. Leur exploration nécessite des droits administrateur ou des outils spécialisés comme FTK Imager ou la suite Sysinternals (Autoruns, Procmon). La cmdlet `Get-Acl` permet également d'inspecter les permissions.

### 1.4 Extensions de fichiers à connaître

La connaissance des extensions Windows est indispensable pour l'analyse de sécurité. Elles se répartissent en plusieurs catégories :

**Exécutables et bibliothèques**

| Extension | Description | Risque sécurité |
|---|---|---|
| `.exe` | Programme exécutable | Vecteur principal de malwares |
| `.dll` | Dynamic Link Library (bibliothèque partagée) | DLL hijacking |
| `.sys` | Pilote système (mode noyau) | Rootkits |

**Scripts et automatisation**

| Extension | Description | Risque sécurité |
|---|---|---|
| `.ps1` | Script PowerShell | Très utilisé par les attaquants pour l'automatisation |
| `.bat` / `.cmd` | Scripts batch | Automatisation simple, parfois malveillante |
| `.vbs` | VBScript | Moteur legacy, encore utilisé dans certains malwares |

**Configuration et système**

| Extension | Description | Risque sécurité |
|---|---|---|
| `.msc` | Snap-in MMC (`eventvwr.msc`, `gpedit.msc`...) | Accès aux outils d'administration |
| `.reg` | Fichier de registre (import/export) | Persistence via modification du registre |
| `.inf` | Script d'installation de pilote | Persistence |
| `.lnk` | Raccourci | Peut être armé pour lancer des charges utiles |

**Conteneurs et journaux**

| Extension | Description | Risque sécurité |
|---|---|---|
| `.iso` | Image disque | Peut contenir des scripts ou outils malveillants |
| `.cab` | Archive Cabinet (fichiers d'installation) | Malwares "fileless" |
| `.log` | Fichier journal | Source d'information en forensique |

Chacune de ces extensions sera approfondie au fil du programme.

### 1.5 Focus : le DLL hijacking

Le **DLL hijacking** est une technique d'attaque qui consiste à faire charger par une application légitime une DLL malveillante à la place de la vraie.

**Exemple concret** : dans le répertoire d'Internet Explorer (`C:\Program Files\Internet Explorer\`), on trouve entre autres :

```
-a----    9/6/2024   6:02 AM     73728  hmmapi.dll
-a----    4/1/2025   5:09 PM    434176  IEShims.dll
-a----    4/1/2025   5:09 PM    845392  iexplore.exe
```

`IEShims.dll` et `hmmapi.dll` sont des dépendances d'Internet Explorer. Si un attaquant parvient à remplacer le contenu de `IEShims.dll` par du code malveillant, celui-ci sera exécuté à chaque lancement de l'application.

**Mesures de protection** :

- Signature et validation du code des DLL
- Utilisation de chemins absolus pour le chargement des DLL
- Activation du mode **DLL SafeSearch** (fonctionnalité Windows native)
- Surveillance des chargements de DLL avec **Sysmon** ou **ProcMon**

Ces protections seront détaillées dans un module ultérieur.

---

## 2. Commandes système essentielles

Cette section couvre les commandes indispensables pour auditer une machine Windows. Elles se répartissent en trois catégories : informations système, processus et services, réseau.

### 2.1 Informations système

Lors de la gestion ou de l'audit d'un système Windows, la première étape consiste toujours à collecter des informations de base sur la machine.

#### `systeminfo`

C'est la commande la plus complète. Elle fournit entre autres :

- Nom et version de l'OS
- Architecture système (32 ou 64 bits)
- Informations processeur et mémoire
- Configuration réseau
- Correctifs installés
- Heure de dernier démarrage

Exemple de sortie (extrait) :

```
Host Name:                 DESKTOP-ABC123
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22621 N/A Build 22621
System Type:               x64-based PC
Total Physical Memory:     16,384 MB
Hotfix(s):                 12 Hotfix(s) Installed.
```

> **Intérêt pour l'audit** : `systeminfo` permet de vérifier rapidement le niveau de correctifs (un nombre faible est un signal d'alerte), la version de l'OS (toujours supportée ?), et le dernier redémarrage (une machine jamais rebootée n'applique pas ses mises à jour noyau).

#### `ver`

Pour obtenir uniquement la version de Windows, sans le reste :

```
Microsoft Windows [Version 10.0.22621.2715]
```

#### `hostname`

Affiche le nom de la machine. Indispensable lorsqu'on travaille sur plusieurs serveurs en parallele pour confirmer sur lequel on se trouve.

### 2.2 Processus et services

Comprendre ce qui tourne sur un système est fondamental, autant pour l'administration que pour la détection d'anomalies.

#### Processus vs services : quelle différence ?

Avant de voir les commandes, il est important de distinguer ces deux notions :

| | Processus | Service |
|---|---|---|
| **Définition** | Tout programme en cours d'execution | Type particulier de processus tournant en arrière-plan |
| **Démarrage** | Lancé par un utilisateur ou le système | Démarré généralement automatiquement au boot |
| **Interaction** | Peut avoir une interface graphique | Pas d'interaction utilisateur directe |
| **Privileges** | Variables | Souvent élevés (compte SYSTEM) |
| **Exemple** | `chrome.exe` | Pare-feu Windows |

#### `Get-Process`

Affiche tous les processus en cours d'execution :

```
NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
------    -----      -----     ------      --  -- -----------
    24    15.23      25.67       2.45    1234   1 chrome
    15     8.45      12.34       0.89    5678   1 explorer
    10     5.67       8.90       0.12    9012   0 svchost
```

Lecture des colonnes :

| Colonne | Signification |
|---|---|
| `NPM(K)` | Mémoire non paginée (en Ko) |
| `PM(M)` | Mémoire privée (en Mo) |
| `WS(M)` | Working Set : mémoire physique utilisée (en Mo) |
| `CPU(s)` | Temps CPU consommé (en secondes) |
| `Id` | PID (identifiant unique du processus) |
| `SI` | Identifiant de session |
| `ProcessName` | Nom du processus |

Quelques variantes utiles en PowerShell :

```powershell
# Trier par consommation CPU (décroissant)
Get-Process | Sort-Object CPU -Descending

# Trier par consommation mémoire
Get-Process | Sort-Object WS -Descending

# Rechercher un processus spécifique
Get-Process | Where-Object {$_.ProcessName -like "*chrome*"}
```

#### `net start`

Liste tous les services en cours d'execution :

```
These Windows services are started:

   Application Information
   Background Intelligent Transfer Service
   Base Filtering Engine
   DNS Client
   Windows Defender Antivirus Service
   Windows Firewall
   Windows Update
```

### 2.3 Configuration et surveillance réseau

#### `ipconfig /all`

Affiche la configuration réseau complète :

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC123
   Node Type . . . . . . . . . . . . : Hybrid

Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8
                                        8.8.4.4
```

Informations clés à relever :

| Champ | Signification |
|---|---|
| `IPv4 Address` | Adresse IP de la machine sur le réseau |
| `Subnet Mask` | Définit la plage du réseau |
| `Default Gateway` | Adresse IP du routeur |
| `DNS Servers` | Serveurs DNS utilisés pour la resolution de noms |

> **Variante** : `ipconfig` (sans `/all`) affiche une version simplifiée, suffisante pour une vérification rapide.

#### `netstat -ano`

Affiche toutes les connexions réseau actives et les ports en écoute :

```
Proto  Local Address          Foreign Address        State           PID
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       704
TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1024
TCP    192.168.1.100:49234    142.250.185.46:443     ESTABLISHED     5678
```

Lecture des colonnes :

| Colonne | Signification |
|---|---|
| `Proto` | Protocole (TCP ou UDP) |
| `Local Address` | IP et port de la machine locale |
| `Foreign Address` | IP et port de la machine distante |
| `State` | État de la connexion |
| `PID` | Identifiant du processus responsable |

États de connexion les plus courants :

| État | Signification |
|---|---|
| `LISTENING` | Port ouvert, en attente de connexions entrantes |
| `ESTABLISHED` | Connexion active avec une machine distante |
| `TIME_WAIT` | Connexion recemment fermée, en attente de nettoyage |

> **Réflexe sécurité** : croiser la sortie de `netstat -ano` avec `Get-Process` permet d'identifier quel programme est responsable de chaque connexion. Un processus inconnu avec une connexion `ESTABLISHED` vers une IP externe mérite investigation.

#### `net share`

Affiche les dossiers et ressources partagés sur la machine :

```
Share name   Resource                        Remark
-----------  --------                        ------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
SharedDocs   C:\Users\Public\Documents       Public documents
```

Partagés par défaut de Windows :

| Partage | Role |
|---|---|
| `C$`, `D$`, etc. | Partagés administratifs pour chaque lecteur (accèssibles uniquement par les administrateurs) |
| `ADMIN$` | Pointe vers le répertoire Windows |
| `IPC$` | Inter-Process Communication, utilisé pour l'administration à distance |

> **Point de vigilance** : ces partagés administratifs sont actifs par défaut. En contexte de durcissement, il est important d'évaluer s'ils doivent rester ouverts selon le niveau de risque du système.

---

## 3. La boîte à outils d'administration Windows

Contrairement à Linux ou macOS, Windows repose historiquement sur l'interface graphique. L'écosystème d'outils d'administration est donc vaste et peut paraître déroutant au premier abord.

Le tableau ci-dessous synthétise les outils par domaine fonctionnel :

| Domaine | Objectif | Outils principaux |
|---|---|---|
| **Gestion des utilisateurs** | Créer, modifier, supprimer des comptes et groupes | `lusrmgr.msc` (MMC) |
| **Stockage** | Gérer l'espace disque, les volumes, les partitions | Explorateur de fichiers, Gestion des disques |
| **Automatisation** | Planifier des tâches récurrentes (équivalent de Cron sous Linux) | Planificateur de tâches (Task Scheduler) |
| **Surveillance** | Vérifier l'utilisation CPU/RAM, consulter les journaux système | Gestionnaire des taches, Observateur d'événements (`eventvwr.msc`), Console de services |
| **Configuration** | Personnaliser les paramètres système | Application Paramètres, Panneau de configuration, Registre (`regedit`) |

### Les deux outils transversaux

Deux outils se démarquent par leur capacité à centraliser plusieurs fonctionnalités :

**Gestion de l'ordinateur (`compmgmt.msc`)**

Console graphique qui regroupe en un seul endroit : la gestion des utilisateurs et groupes locaux, le planificateur de tâches, les services, la gestion des disques et l'observateur d'événements. C'est l'outil de référence pour l'administration ponctuelle d'une machine.

**PowerShell**

Interface en ligne de commande capable de reproduire (et dépasser) tout ce que font les outils graphiques ci-dessus. Son principal avantage est l'automatisation : tout ce qui se fait manuellement dans une console graphique peut être scripté en PowerShell pour être reproduit sur des dizaines de machines. L'apprentissage demande un investissement initial, mais le gain en efficacité est considérable.

> **À propos de cmd** : l'invite de commandes classique (`cmd.exe`) reste présente sur toutes les versions de Windows, mais elle est aujourd'hui considérée comme un outil legacy. PowerShell la remplace avantageusement dans la quasi-totalité des cas. Il est néanmoins courant de trouver des commandes `cmd` dans la documentation ou les forums en ligne.

> **Où se trouvent ces outils ?** Tous les exécutables mentionnés dans cette section sont situés dans `C:\Windows` ou `C:\Windows\System32\`. C'est un bon exercice de les localiser manuellement pour se familiariser avec l'arborescence.

---

## Récapitulatif : les commandes essentielles

| Commande | Usage | Catégorie |
|---|---|---|
| `systeminfo` | Informations système complètes | Audit |
| `ver` | Version de Windows | Audit |
| `hostname` | Nom de la machine | Audit |
| `Get-Process` | Lister les processus en cours | Surveillance |
| `net start` | Lister les services actifs | Surveillance |
| `ipconfig /all` | Configuration réseau complète | Réseau |
| `netstat -ano` | Connexions actives et ports en écoute | Réseau |
| `net share` | Ressources partagées | Réseau |

---

## Pour aller plus loin

- [Operating System Market Share Worldwide (StatCounter)](https://gs.statcounter.com/os-market-share)
- [Windows Fundamentals 1 (TryHackMe)](https://tryhackme.com/room/windowsfundamentals1xbx)
- [Windows Fundamentals 2 (TryHackMe)](https://tryhackme.com/room/windowsfundamentals2x0x)
- [Explore the Windows client (Microsoft Learn)](https://learn.microsoft.com/en-us/training/modules/explore-windows-client/)
- [Windows Through the Ages (LinkedIn / Amr Elharony)](https://www.linkedin.com/pulse/windows-through-ages-evolution-os-giant-amr-elharony-tzv2f)
