# Processus, threads et services Windows

**Module** : comprendre les processus, les threads, les DLL et les services

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre ce qu'est un processus Windows et les ressources qu'il encapsule
- Distinguer les processus des threads et comprendre leur relation
- Maitriser le concept de relation parent/enfant entre processus
- Comprendre le role des DLL (Dynamic Link Libraries) et leur fonctionnement
- Connaitre les services Windows, le Service Control Manager et svchost.exe
- Identifier les risques de securite lies aux services

---

## 1. Les processus Windows

### 1.1 Definition

Un **processus** est un conteneur logique cree par le systeme d'exploitation lorsqu'un programme est execute. Il ne s'agit pas du programme lui-meme (qui est un fichier `.exe` stocke sur le disque), mais de l'instance en cours d'execution de ce programme.

Chaque processus encapsule plusieurs ressources :

| Ressource | Description |
|---|---|
| **Code executable** | Le code source compile du programme, charge en memoire |
| **Espace d'adressage virtuel** | Zone de memoire privee allouee par le systeme d'exploitation |
| **DLL chargees** | Bibliotheques dynamiques necessaires au fonctionnement du programme |
| **Handles** | References vers les objets du noyau utilises (fichiers, cles de registre, etc.) |
| **Token d'acces** | Identifiant de securite qui determine les privileges du processus |
| **PID** | Process Identifier, un identifiant numerique unique attribue par le systeme |

> **A noter** : le token d'acces est un element central de la securite Windows. Il contient l'identite de l'utilisateur qui a lance le processus (son SID), ses groupes d'appartenance et ses privileges. C'est ce token que le noyau consulte pour autoriser ou refuser chaque operation.

### 1.2 Examiner les processus

Plusieurs outils permettent de lister et d'examiner les processus :

```powershell
# Lister tous les processus en cours
Get-Process

# Voir le chemin complet de l'executable de chaque processus
Get-Process | Format-Table Id, ProcessName, Path -AutoSize

# Filtrer un processus specifique
Get-Process -Name "explorer"

# Obtenir des informations detaillees sur un processus
Get-Process -Id 1234 | Format-List *
```

L'outil **Task Manager** (`taskmgr.exe`) offre une vue graphique des processus. L'onglet "Details" affiche le PID, l'utilisateur, la consommation CPU et memoire de chaque processus.

Pour une analyse approfondie, l'outil **Process Explorer** de la suite Sysinternals est recommande. Il affiche l'arborescence parent/enfant, les DLL chargees, les handles ouverts et les informations de securite de chaque processus.

---

## 2. Les threads

### 2.1 Definition

Un **thread** (fil d'execution) est la plus petite unite de calcul pouvant etre planifiee et executee par le processeur. Un processus contient au moins un thread (le thread principal), mais peut en creer plusieurs pour effectuer des taches en parallele.

La relation entre processus et threads peut se resumer ainsi :

| Concept | Analogie | Role |
|---|---|---|
| **Processus** | Usine | Fournit les ressources (memoire, DLL, handles) |
| **Thread** | Ouvrier dans l'usine | Execute le code, utilise les ressources du processus |

### 2.2 Fonctionnement

Les threads sont definis par les developpeurs dans le code source de l'application. Le systeme d'exploitation se charge ensuite de les planifier sur les coeurs du processeur.

Exemple concret avec un navigateur web :

- **Thread 1** : gere l'interface graphique (affichage des onglets, boutons)
- **Thread 2** : effectue le rendu HTML/CSS de la page web
- **Thread 3** : execute le code JavaScript
- **Thread 4** : gere les connexions reseau et le telechargement des ressources

Tous ces threads partagent la memoire et les ressources du meme processus navigateur, ce qui permet une communication rapide entre eux.

> **A noter** : c'est le thread (et non le processus) qui execute reellement le code sur le processeur. Le processeur ne "voit" que des threads. Le processus n'est qu'un conteneur organisationnel.

### 2.3 Examiner les threads

```powershell
# Compter le nombre de threads d'un processus
(Get-Process -Name "explorer").Threads.Count

# Lister les threads d'un processus avec leur etat
(Get-Process -Name "explorer").Threads | Format-Table Id, ThreadState, WaitReason -AutoSize
```

---

## 3. Relation parent/enfant des processus

### 3.1 Principe

Sous Windows, tout processus est cree par un autre processus, a l'exception du processus initial du systeme (`System`, PID 4). Le processus qui en cree un autre est appele **processus parent** (parent process), et le nouveau processus est appele **processus enfant** (child process).

Cette hierarchie forme un arbre de processus. Chaque processus conserve le **PID de son parent** (PPID, Parent Process ID).

### 3.2 Exemple : Microsoft Edge

Lorsqu'un utilisateur lance Microsoft Edge, voici l'arbre typique de processus qui en resulte :

```
explorer.exe (PID 1200)          <- Shell Windows (Bureau)
  └── msedge.exe (PID 3400)      <- Processus principal du navigateur
        ├── msedge.exe (PID 3412) <- Processus GPU
        ├── msedge.exe (PID 3428) <- Processus reseau
        ├── msedge.exe (PID 3440) <- Onglet 1
        ├── msedge.exe (PID 3456) <- Onglet 2
        └── msedge.exe (PID 3472) <- Extension
```

Chaque onglet et chaque extension tourne dans un processus separe (architecture multi-processus). Ce modele de securite s'appelle le **sandboxing** : si un onglet plante ou est compromis, les autres continuent de fonctionner de maniere isolee.

### 3.3 Interet pour la securite

L'analyse de la relation parent/enfant est fondamentale pour la detection d'anomalies :

| Situation normale | Situation suspecte |
|---|---|
| `explorer.exe` lance `chrome.exe` | `cmd.exe` lance `powershell.exe` qui lance `whoami.exe` |
| `svchost.exe` lance un service systeme | `winword.exe` lance `cmd.exe` ou `powershell.exe` |
| `services.exe` lance `svchost.exe` | `svchost.exe` lance depuis un dossier inhabituel |

> **Bonne pratique** : un document Office (`winword.exe`, `excel.exe`) qui lance un interpreteur de commandes (`cmd.exe`, `powershell.exe`) est un indicateur classique d'attaque par macro malveillante. Les solutions EDR (Endpoint Detection and Response) surveillent en permanence ces relations parent/enfant.

---

## 4. Les DLL (Dynamic Link Libraries)

### 4.1 Definition

Les **DLL** (Dynamic Link Libraries, ou bibliotheques de liens dynamiques) sont des fichiers contenant du code compile reutilisable. Elles portent l'extension `.dll` et sont stockees principalement dans `C:\Windows\System32\`.

Le principe est simple : plutot que de dupliquer le meme code dans chaque programme, les developpeurs placent les fonctions partagees dans des DLL. Chaque programme charge ensuite les DLL dont il a besoin.

### 4.2 Fonctionnement du chargement

Les DLL peuvent etre chargees de deux manieres :

| Mode | Description | Exemple |
|---|---|---|
| **Chargement statique** | La DLL est chargee automatiquement au demarrage du processus, car elle est declaree dans les dependances de l'executable | `kernel32.dll`, `user32.dll` |
| **Chargement dynamique** | La DLL est chargee a la demande pendant l'execution, par un appel a `LoadLibrary()` | Plugins, extensions |

### 4.3 DLL essentielles du systeme

| DLL | Chemin | Role |
|---|---|---|
| `kernel32.dll` | `C:\Windows\System32\` | Operations fondamentales : gestion de la memoire, des fichiers, des processus |
| `user32.dll` | `C:\Windows\System32\` | Interface graphique : fenetres, messages, entrees clavier/souris |
| `advapi32.dll` | `C:\Windows\System32\` | Securite et registre : gestion des tokens, des services, des cles de registre |
| `ntdll.dll` | `C:\Windows\System32\` | Interface vers le noyau : contient les fonctions de transition user mode/kernel mode (syscalls) |
| `gdi32.dll` | `C:\Windows\System32\` | Graphismes : dessin, polices, operations graphiques de bas niveau |

### 4.4 ntdll.dll : la passerelle vers le noyau

La DLL `ntdll.dll` occupe une place particuliere dans l'architecture Windows. C'est elle qui contient les **fonctions syscall** (appels systeme), c'est-a-dire les instructions qui permettent a un programme en mode utilisateur de demander un service au noyau.

Lorsqu'un programme appelle une fonction comme `CreateFile()` (via `kernel32.dll`), la chaine d'appel est la suivante :

```
Application → kernel32.dll → ntdll.dll → syscall → Noyau Windows
```

`ntdll.dll` est donc la derniere etape avant le passage en mode noyau. Elle sera etudiee en detail dans le module suivant.

### 4.5 Examiner les DLL chargees

```powershell
# Lister les DLL (modules) chargees par un processus
Get-Process -Name "explorer" | Select-Object -ExpandProperty Modules

# Avec plus de details
Get-Process -Name "explorer" | Select-Object -ExpandProperty Modules |
    Format-Table ModuleName, FileName, Size -AutoSize
```

L'outil **Process Explorer** (Sysinternals) permet egalement de visualiser les DLL chargees par chaque processus en cliquant sur le processus puis en consultant le panneau inferieur (View > Lower Pane View > DLLs).

> **A noter** : le DLL hijacking (etudie dans le module 01) exploite l'ordre de recherche des DLL par Windows. Si un attaquant place une DLL malveillante dans un dossier prioritaire dans l'ordre de recherche, elle sera chargee a la place de la DLL legitime.

---

## 5. Les services Windows

### 5.1 Definition

Un **service Windows** est un type particulier de processus qui s'execute en arriere-plan, independamment de toute session utilisateur. Contrairement a un programme classique, un service :

- Demarre automatiquement au demarrage de la machine (avant meme qu'un utilisateur ne se connecte)
- Ne possede pas d'interface graphique
- Continue de fonctionner meme apres la deconnexion de l'utilisateur
- S'execute generalement avec des privileges eleves (compte `SYSTEM` ou `LOCAL SERVICE`)

### 5.2 Le Service Control Manager (SCM)

Le **Service Control Manager** (SCM, gestionnaire de controle des services) est un composant du noyau Windows responsable de la gestion du cycle de vie des services. Il est implemente dans le processus `services.exe`.

Le SCM assure les fonctions suivantes :

| Fonction | Description |
|---|---|
| **Demarrage** | Charge et demarre les services au boot selon leur type de demarrage |
| **Arret** | Arrete proprement les services a la demande ou lors de l'arret du systeme |
| **Pause/reprise** | Permet de suspendre temporairement un service |
| **Configuration** | Stocke les parametres de chaque service dans le registre |
| **Surveillance** | Detecte les echecs et peut relancer automatiquement un service |

Les informations de configuration des services sont stockees dans le registre, sous la cle :

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\
```

### 5.3 Types de demarrage des services

| Type | Description |
|---|---|
| **Automatic** | Le service demarre automatiquement au boot |
| **Automatic (Delayed Start)** | Le service demarre automatiquement, mais apres un delai pour ne pas ralentir le boot |
| **Manual** | Le service ne demarre que lorsqu'il est explicitement lance |
| **Disabled** | Le service est desactive et ne peut pas etre demarre |

### 5.4 Gestion des services en PowerShell

```powershell
# Lister tous les services
Get-Service

# Lister les services en cours d'execution
Get-Service | Where-Object {$_.Status -eq "Running"}

# Obtenir des details sur un service specifique
Get-Service -Name "wuauserv" | Format-List *

# Demarrer / Arreter / Redemarrer un service
Start-Service -Name "wuauserv"
Stop-Service -Name "wuauserv"
Restart-Service -Name "wuauserv"

# Modifier le type de demarrage
Set-Service -Name "wuauserv" -StartupType Automatic
```

Avec la commande `sc` (Service Control) en ligne de commande classique :

```cmd
sc query wuauserv
sc start wuauserv
sc stop wuauserv
sc config wuauserv start= auto
```

### 5.5 svchost.exe : l'hote de services generique

**svchost.exe** (Service Host) est un processus generique dont le role est d'heberger un ou plusieurs services Windows. Il est situe dans `C:\Windows\System32\svchost.exe`.

Pourquoi ce mecanisme existe-t-il ? De nombreux services Windows sont implementes sous forme de DLL (et non d'executables autonomes). Or une DLL ne peut pas s'executer seule : elle a besoin d'un processus hote. C'est le role de `svchost.exe`.

Sur un systeme Windows typique, on observe plusieurs instances de `svchost.exe` en cours d'execution, chacune hebergeant un ou plusieurs services :

```powershell
# Voir les services heberges par chaque instance de svchost.exe
Get-WmiObject Win32_Service | Where-Object {$_.PathName -like "*svchost*"} |
    Format-Table Name, DisplayName, State -AutoSize
```

On peut aussi utiliser la commande :

```cmd
tasklist /svc /fi "imagename eq svchost.exe"
```

Resultat typique (extrait) :

```
Image Name    PID Services
============= === ============================================
svchost.exe   704 RpcSs
svchost.exe   832 DcomLaunch
svchost.exe   928 lsm
svchost.exe  1024 Dhcp, EventLog, lmhosts, Wcmsvc
svchost.exe  1100 AudioSrv, BFE, MpsSvc, WdiServiceHost
```

### 5.6 Risques de securite lies aux services

Les services Windows constituent une surface d'attaque importante pour plusieurs raisons :

| Risque | Description |
|---|---|
| **Privileges eleves** | Les services s'executent souvent avec le compte `SYSTEM`, qui dispose de tous les privileges sur la machine |
| **Persistance** | Un attaquant peut creer un service malveillant pour maintenir un acces permanent |
| **Escalade de privileges** | Un service mal configure (permissions trop larges sur l'executable ou la cle de registre) peut etre detourne |
| **Mouvement lateral** | Certains services (SMB, WinRM, RDP) peuvent etre exploites pour se propager sur le reseau |

**Risque specifique a svchost.exe** : lorsque plusieurs services partagent la meme instance de `svchost.exe`, une vulnerabilite dans l'un d'entre eux peut potentiellement permettre a un attaquant d'acceder aux autres services heberges dans le meme processus. C'est pourquoi les versions recentes de Windows tendent a isoler davantage les services dans des instances separees de `svchost.exe`.

> **Bonne pratique** : lors d'un audit, toujours verifier les services en cours d'execution (`Get-Service`), les permissions sur les executables des services (`icacls`), et les comptes sous lesquels ils s'executent. Un service s'executant sous le compte `SYSTEM` avec un executable modifiable par un utilisateur standard est un vecteur d'escalade de privileges classique.

---

## Recapitulatif

| Concept | Definition | Outil d'examen |
|---|---|---|
| **Processus** | Conteneur contenant le code, la memoire, les DLL et le token d'acces | `Get-Process`, Task Manager, Process Explorer |
| **Thread** | Plus petite unite d'execution planifiee par le CPU | `(Get-Process).Threads`, Process Explorer |
| **DLL** | Bibliotheque de code reutilisable, chargee par les processus | `Get-Process -Name X \| Select -Expand Modules` |
| **Service** | Processus en arriere-plan, gere par le SCM | `Get-Service`, `sc query`, `services.msc` |
| **svchost.exe** | Processus hote pour les services implementes en DLL | `tasklist /svc`, Process Explorer |

---

## Pour aller plus loin

- [Windows Internals, Part 1 (Microsoft Press)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Process Explorer (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [Understanding svchost.exe (Microsoft)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/svchost-exe-high-cpu-usage)
- [MITRE ATT&CK - Create or Modify System Process: Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)
- [DLL Hijacking (OWASP)](https://owasp.org/www-community/vulnerabilities/DLL_Hijacking)
