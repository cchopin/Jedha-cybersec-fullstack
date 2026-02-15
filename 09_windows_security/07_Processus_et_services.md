# Processus, threads et services Windows

**Module** : comprendre les processus, les threads, les DLL et les services

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre ce qu'est un processus Windows et les ressources qu'il encapsule
- Distinguer les processus des threads et comprendre leur relation
- Maîtriser le concept de relation parent/enfant entre processus
- Comprendre le rôle des DLL (Dynamic Link Libraries) et leur fonctionnement
- Connaître les services Windows, le Service Control Manager et svchost.exe
- Identifier les risques de sécurité liés aux services

---

## 1. Les processus Windows

### 1.1 Définition

Un **processus** est un conteneur logique créé par le système d'exploitation lorsqu'un programme est exécuté. Il ne s'agit pas du programme lui-même (qui est un fichier `.exe` stocké sur le disque), mais de l'instance en cours d'exécution de ce programme.

Chaque processus encapsule plusieurs ressources :

| Ressource | Description |
|---|---|
| **Code exécutable** | Le code source compilé du programme, chargé en mémoire |
| **Espace d'adressage virtuel** | Zone de mémoire privée allouée par le système d'exploitation |
| **DLL chargées** | Bibliothèques dynamiques nécessaires au fonctionnement du programme |
| **Handles** | Références vers les objets du noyau utilisés (fichiers, clés de registre, etc.) |
| **Token d'accès** | Identifiant de sécurité qui détermine les privilèges du processus |
| **PID** | Process Identifier, un identifiant numérique unique attribué par le système |

> **À noter** : le token d'accès est un élément central de la sécurité Windows. Il contient l'identité de l'utilisateur qui a lancé le processus (son SID), ses groupes d'appartenance et ses privilèges. C'est ce token que le noyau consulte pour autoriser ou refuser chaque opération.

### 1.2 Examiner les processus

Plusieurs outils permettent de lister et d'examiner les processus :

```powershell
# Lister tous les processus en cours
Get-Process

# Voir le chemin complet de l'exécutable de chaque processus
Get-Process | Format-Table Id, ProcessName, Path -AutoSize

# Filtrer un processus spécifique
Get-Process -Name "explorer"

# Obtenir des informations détaillées sur un processus
Get-Process -Id 1234 | Format-List *
```

L'outil **Task Manager** (`taskmgr.exe`) offre une vue graphique des processus. L'onglet "Details" affiche le PID, l'utilisateur, la consommation CPU et mémoire de chaque processus.

Pour une analyse approfondie, l'outil **Process Explorer** de la suite Sysinternals est recommandé. Il affiche l'arborescence parent/enfant, les DLL chargées, les handles ouverts et les informations de sécurité de chaque processus.

---

## 2. Les threads

### 2.1 Définition

Un **thread** (fil d'exécution) est la plus petite unité de calcul pouvant être planifiée et exécutée par le processeur. Un processus contient au moins un thread (le thread principal), mais peut en créer plusieurs pour effectuer des tâches en parallèle.

La relation entre processus et threads peut se résumer ainsi :

| Concept | Analogie | Rôle |
|---|---|---|
| **Processus** | Usine | Fournit les ressources (mémoire, DLL, handles) |
| **Thread** | Ouvrier dans l'usine | Exécute le code, utilise les ressources du processus |

### 2.2 Fonctionnement

Les threads sont définis par les développeurs dans le code source de l'application. Le système d'exploitation se charge ensuite de les planifier sur les cœurs du processeur.

Exemple concret avec un navigateur web :

- **Thread 1** : gère l'interface graphique (affichage des onglets, boutons)
- **Thread 2** : effectue le rendu HTML/CSS de la page web
- **Thread 3** : exécute le code JavaScript
- **Thread 4** : gère les connexions réseau et le téléchargement des ressources

Tous ces threads partagent la mémoire et les ressources du même processus navigateur, ce qui permet une communication rapide entre eux.

> **À noter** : c'est le thread (et non le processus) qui exécute réellement le code sur le processeur. Le processeur ne "voit" que des threads. Le processus n'est qu'un conteneur organisationnel.

### 2.3 Examiner les threads

```powershell
# Compter le nombre de threads d'un processus
(Get-Process -Name "explorer").Threads.Count

# Lister les threads d'un processus avec leur état
(Get-Process -Name "explorer").Threads | Format-Table Id, ThreadState, WaitReason -AutoSize
```

---

## 3. Relation parent/enfant des processus

### 3.1 Principe

Sous Windows, tout processus est créé par un autre processus, à l'exception du processus initial du système (`System`, PID 4). Le processus qui en crée un autre est appelé **processus parent** (parent process), et le nouveau processus est appelé **processus enfant** (child process).

Cette hiérarchie forme un arbre de processus. Chaque processus conserve le **PID de son parent** (PPID, Parent Process ID).

### 3.2 Exemple : Microsoft Edge

Lorsqu'un utilisateur lance Microsoft Edge, voici l'arbre typique de processus qui en résulte :

```
explorer.exe (PID 1200)          <- Shell Windows (Bureau)
  └── msedge.exe (PID 3400)      <- Processus principal du navigateur
        ├── msedge.exe (PID 3412) <- Processus GPU
        ├── msedge.exe (PID 3428) <- Processus réseau
        ├── msedge.exe (PID 3440) <- Onglet 1
        ├── msedge.exe (PID 3456) <- Onglet 2
        └── msedge.exe (PID 3472) <- Extension
```

Chaque onglet et chaque extension tourne dans un processus séparé (architecture multi-processus). Ce modèle de sécurité s'appelle le **sandboxing** : si un onglet plante ou est compromis, les autres continuent de fonctionner de manière isolée.

### 3.3 Intérêt pour la sécurité

L'analyse de la relation parent/enfant est fondamentale pour la détection d'anomalies :

| Situation normale | Situation suspecte |
|---|---|
| `explorer.exe` lance `chrome.exe` | `cmd.exe` lance `powershell.exe` qui lance `whoami.exe` |
| `svchost.exe` lance un service système | `winword.exe` lance `cmd.exe` ou `powershell.exe` |
| `services.exe` lance `svchost.exe` | `svchost.exe` lancé depuis un dossier inhabituel |

> **Bonne pratique** : un document Office (`winword.exe`, `excel.exe`) qui lance un interpréteur de commandes (`cmd.exe`, `powershell.exe`) est un indicateur classique d'attaque par macro malveillante. Les solutions EDR (Endpoint Detection and Response) surveillent en permanence ces relations parent/enfant.

---

## 4. Les DLL (Dynamic Link Libraries)

### 4.1 Définition

Les **DLL** (Dynamic Link Libraries, ou bibliothèques de liens dynamiques) sont des fichiers contenant du code compilé réutilisable. Elles portent l'extension `.dll` et sont stockées principalement dans `C:\Windows\System32\`.

Le principe est simple : plutôt que de dupliquer le même code dans chaque programme, les développeurs placent les fonctions partagées dans des DLL. Chaque programme charge ensuite les DLL dont il a besoin.

### 4.2 Fonctionnement du chargement

Les DLL peuvent être chargées de deux manières :

| Mode | Description | Exemple |
|---|---|---|
| **Chargement statique** | La DLL est chargée automatiquement au démarrage du processus, car elle est déclarée dans les dépendances de l'exécutable | `kernel32.dll`, `user32.dll` |
| **Chargement dynamique** | La DLL est chargée à la demande pendant l'exécution, par un appel à `LoadLibrary()` | Plugins, extensions |

### 4.3 DLL essentielles du système

| DLL | Chemin | Rôle |
|---|---|---|
| `kernel32.dll` | `C:\Windows\System32\` | Opérations fondamentales : gestion de la mémoire, des fichiers, des processus |
| `user32.dll` | `C:\Windows\System32\` | Interface graphique : fenêtres, messages, entrées clavier/souris |
| `advapi32.dll` | `C:\Windows\System32\` | Sécurité et registre : gestion des tokens, des services, des clés de registre |
| `ntdll.dll` | `C:\Windows\System32\` | Interface vers le noyau : contient les fonctions de transition user mode/kernel mode (syscalls) |
| `gdi32.dll` | `C:\Windows\System32\` | Graphismes : dessin, polices, opérations graphiques de bas niveau |

### 4.4 ntdll.dll : la passerelle vers le noyau

La DLL `ntdll.dll` occupe une place particulière dans l'architecture Windows. C'est elle qui contient les **fonctions syscall** (appels système), c'est-à-dire les instructions qui permettent à un programme en mode utilisateur de demander un service au noyau.

Lorsqu'un programme appelle une fonction comme `CreateFile()` (via `kernel32.dll`), la chaîne d'appel est la suivante :

```
Application → kernel32.dll → ntdll.dll → syscall → Noyau Windows
```

`ntdll.dll` est donc la dernière étape avant le passage en mode noyau. Elle sera étudiée en détail dans le module suivant.

### 4.5 Examiner les DLL chargées

```powershell
# Lister les DLL (modules) chargées par un processus
Get-Process -Name "explorer" | Select-Object -ExpandProperty Modules

# Avec plus de détails
Get-Process -Name "explorer" | Select-Object -ExpandProperty Modules |
    Format-Table ModuleName, FileName, Size -AutoSize
```

L'outil **Process Explorer** (Sysinternals) permet également de visualiser les DLL chargées par chaque processus en cliquant sur le processus puis en consultant le panneau inférieur (View > Lower Pane View > DLLs).

> **À noter** : le DLL hijacking (étudié dans le module 01) exploite l'ordre de recherche des DLL par Windows. Si un attaquant place une DLL malveillante dans un dossier prioritaire dans l'ordre de recherche, elle sera chargée à la place de la DLL légitime.

---

## 5. Les services Windows

### 5.1 Définition

Un **service Windows** est un type particulier de processus qui s'exécute en arrière-plan, indépendamment de toute session utilisateur. Contrairement à un programme classique, un service :

- Démarre automatiquement au démarrage de la machine (avant même qu'un utilisateur ne se connecte)
- Ne possède pas d'interface graphique
- Continue de fonctionner même après la déconnexion de l'utilisateur
- S'exécute généralement avec des privilèges élevés (compte `SYSTEM` ou `LOCAL SERVICE`)

### 5.2 Le Service Control Manager (SCM)

Le **Service Control Manager** (SCM, gestionnaire de contrôle des services) est un composant du noyau Windows responsable de la gestion du cycle de vie des services. Il est implémenté dans le processus `services.exe`.

Le SCM assure les fonctions suivantes :

| Fonction | Description |
|---|---|
| **Démarrage** | Charge et démarre les services au boot selon leur type de démarrage |
| **Arrêt** | Arrête proprement les services à la demande ou lors de l'arrêt du système |
| **Pause/reprise** | Permet de suspendre temporairement un service |
| **Configuration** | Stocke les paramètres de chaque service dans le registre |
| **Surveillance** | Détecte les échecs et peut relancer automatiquement un service |

Les informations de configuration des services sont stockées dans le registre, sous la clé :

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\
```

### 5.3 Types de démarrage des services

| Type | Description |
|---|---|
| **Automatic** | Le service démarre automatiquement au boot |
| **Automatic (Delayed Start)** | Le service démarre automatiquement, mais après un délai pour ne pas ralentir le boot |
| **Manual** | Le service ne démarre que lorsqu'il est explicitement lancé |
| **Disabled** | Le service est désactivé et ne peut pas être démarré |

### 5.4 Gestion des services en PowerShell

```powershell
# Lister tous les services
Get-Service

# Lister les services en cours d'exécution
Get-Service | Where-Object {$_.Status -eq "Running"}

# Obtenir des détails sur un service spécifique
Get-Service -Name "wuauserv" | Format-List *

# Démarrer / Arrêter / Redémarrer un service
Start-Service -Name "wuauserv"
Stop-Service -Name "wuauserv"
Restart-Service -Name "wuauserv"

# Modifier le type de démarrage
Set-Service -Name "wuauserv" -StartupType Automatic
```

Avec la commande `sc` (Service Control) en ligne de commande classique :

```cmd
sc query wuauserv
sc start wuauserv
sc stop wuauserv
sc config wuauserv start= auto
```

### 5.5 svchost.exe : l'hôte de services générique

**svchost.exe** (Service Host) est un processus générique dont le rôle est d'héberger un ou plusieurs services Windows. Il est situé dans `C:\Windows\System32\svchost.exe`.

Pourquoi ce mécanisme existe-t-il ? De nombreux services Windows sont implémentés sous forme de DLL (et non d'exécutables autonomes). Or une DLL ne peut pas s'exécuter seule : elle a besoin d'un processus hôte. C'est le rôle de `svchost.exe`.

Sur un système Windows typique, on observe plusieurs instances de `svchost.exe` en cours d'exécution, chacune hébergeant un ou plusieurs services :

```powershell
# Voir les services hébergés par chaque instance de svchost.exe
Get-WmiObject Win32_Service | Where-Object {$_.PathName -like "*svchost*"} |
    Format-Table Name, DisplayName, State -AutoSize
```

On peut aussi utiliser la commande :

```cmd
tasklist /svc /fi "imagename eq svchost.exe"
```

Résultat typique (extrait) :

```
Image Name    PID Services
============= === ============================================
svchost.exe   704 RpcSs
svchost.exe   832 DcomLaunch
svchost.exe   928 lsm
svchost.exe  1024 Dhcp, EventLog, lmhosts, Wcmsvc
svchost.exe  1100 AudioSrv, BFE, MpsSvc, WdiServiceHost
```

### 5.6 Risques de sécurité liés aux services

Les services Windows constituent une surface d'attaque importante pour plusieurs raisons :

| Risque | Description |
|---|---|
| **Privilèges élevés** | Les services s'exécutent souvent avec le compte `SYSTEM`, qui dispose de tous les privilèges sur la machine |
| **Persistance** | Un attaquant peut créer un service malveillant pour maintenir un accès permanent |
| **Escalade de privilèges** | Un service mal configuré (permissions trop larges sur l'exécutable ou la clé de registre) peut être détourné |
| **Mouvement latéral** | Certains services (SMB, WinRM, RDP) peuvent être exploités pour se propager sur le réseau |

**Risque spécifique à svchost.exe** : lorsque plusieurs services partagent la même instance de `svchost.exe`, une vulnérabilité dans l'un d'entre eux peut potentiellement permettre à un attaquant d'accéder aux autres services hébergés dans le même processus. C'est pourquoi les versions récentes de Windows tendent à isoler davantage les services dans des instances séparées de `svchost.exe`.

> **Bonne pratique** : lors d'un audit, toujours vérifier les services en cours d'exécution (`Get-Service`), les permissions sur les exécutables des services (`icacls`), et les comptes sous lesquels ils s'exécutent. Un service s'exécutant sous le compte `SYSTEM` avec un exécutable modifiable par un utilisateur standard est un vecteur d'escalade de privilèges classique.

---

## Récapitulatif

| Concept | Définition | Outil d'examen |
|---|---|---|
| **Processus** | Conteneur contenant le code, la mémoire, les DLL et le token d'accès | `Get-Process`, Task Manager, Process Explorer |
| **Thread** | Plus petite unité d'exécution planifiée par le CPU | `(Get-Process).Threads`, Process Explorer |
| **DLL** | Bibliothèque de code réutilisable, chargée par les processus | `Get-Process -Name X \| Select -Expand Modules` |
| **Service** | Processus en arrière-plan, géré par le SCM | `Get-Service`, `sc query`, `services.msc` |
| **svchost.exe** | Processus hôte pour les services implémentés en DLL | `tasklist /svc`, Process Explorer |

---

## Pour aller plus loin

- [Windows Internals, Part 1 (Microsoft Press)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Process Explorer (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [Understanding svchost.exe (Microsoft)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/svchost-exe-high-cpu-usage)
- [MITRE ATT&CK - Create or Modify System Process: Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)
- [DLL Hijacking (OWASP)](https://owasp.org/www-community/vulnerabilities/DLL_Hijacking)
