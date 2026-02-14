# Le noyau Windows : gestion de la mémoire

**Module** : mémoire physique, mémoire virtuelle et analyse forensique

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre la distinction entre mémoire physique (RAM) et mémoire virtuelle
- Connaître le rôle des registres CPU et leur lien avec l'architecture 32/64 bits
- Expliquer le mécanisme de mémoire virtuelle et de table des pages (Page Table)
- Identifier le contenu de la mémoire d'un processus (Stack, Heap, Text, Data)
- Utiliser les outils Windows et Sysinternals pour analyser l'utilisation mémoire
- Réaliser un dump mémoire à des fins d'analyse forensique

---

## Introduction

La mémoire est une ressource critique pour tout système d'exploitation. Windows implémente un système de gestion mémoire sophistiqué qui assure l'isolation entre les processus, optimise l'utilisation de la RAM physique, et offre à chaque programme l'illusion de disposer d'un espace mémoire dédié et continu. Comprendre ce mécanisme est essentiel pour l'analyse forensique, la détection de malwares et la compréhension des techniques d'injection en mémoire.

---

## 1. La mémoire physique (RAM)

### 1.1 Qu'est-ce que la RAM ?

La **RAM** (Random Access Memory) est la mémoire vive de l'ordinateur. C'est un espace de stockage **volatile** (les données sont perdues à l'extinction) et **rapide** (temps d'accès de l'ordre de la nanoseconde), utilisé par le processeur pour stocker les données et les instructions des programmes en cours d'exécution.

Caractéristiques principales :

| Propriété | RAM | Disque dur (HDD/SSD) |
|---|---|---|
| Vitesse d'accès | ~10-100 nanosecondes | ~0,1-10 millisecondes |
| Volatilité | Volatile (perdu à l'extinction) | Persistant |
| Capacité typique | 8-64 Go | 256 Go - 4 To |
| Rôle | Données en cours d'utilisation | Stockage permanent |

### 1.2 Organisation de la mémoire physique

La mémoire est organisée en unités de **1 octet** (byte). Chaque octet possède une **adresse unique** qui permet au processeur de le localiser.

Exemple pour un système avec 4 Go de RAM :

- 4 Go = 4 294 967 296 octets, soit environ 4,3 milliards de conteneurs adressables
- Les adresses vont de `0x00000000` à `0xFFFFFFFF` (en hexadécimal)

```
Adresse       Contenu (1 octet)
0x00000000    [48]        <- premier octet
0x00000001    [65]
0x00000002    [6C]
0x00000003    [6C]
...
0xFFFFFFFF    [00]        <- dernier octet (4 Go)
```

---

## 2. Le processeur et ses registres

### 2.1 Les registres CPU

Les **registres** sont de petits emplacements de stockage **ultra-rapides** situés directement à l'intérieur du processeur. On peut les considérer comme le « bloc-notes » (scratchpad) du CPU : c'est là qu'il place les données sur lesquelles il travaille immédiatement.

Hiérarchie de vitesse du stockage :

```
+------------------+  Plus rapide
|   Registres CPU  |  ~1 cycle CPU (~0,3 ns)
+------------------+
|   Cache L1       |  ~4 cycles CPU
+------------------+
|   Cache L2       |  ~10 cycles CPU
+------------------+
|   Cache L3       |  ~40 cycles CPU
+------------------+
|   RAM            |  ~100-300 cycles CPU
+------------------+
|   SSD            |  ~10 000+ cycles CPU
+------------------+
|   HDD            |  ~10 000 000+ cycles CPU
+------------------+  Plus lent
```

### 2.2 Architecture 32 bits vs 64 bits

La taille des registres détermine l'architecture du processeur et, par conséquent, la version de Windows installée :

| Architecture | Taille des registres | Espace d'adressage | RAM maximale théorique |
|---|---|---|---|
| **x86** (32 bits) | 32 bits | 2^32 adresses | 4 Go |
| **x86-64** (64 bits) | 64 bits | 2^64 adresses | 16 exaoctets (théorique) |

> **À noter** : c'est pour cette raison que Windows 32 bits ne peut pas adresser plus de 4 Go de RAM, même si la machine en dispose physiquement de plus. Windows 64 bits repousse cette limite bien au-delà des besoins actuels.

### 2.3 Registres principaux

Un processeur x86-64 dispose de **16 registres généraux** :

| Registre | Rôle courant |
|---|---|
| `RAX` | Accumulateur, valeur de retour des fonctions |
| `RBX` | Base, usage général |
| `RCX` | Compteur (boucles), 1er argument (convention Windows x64) |
| `RDX` | Données, 2e argument |
| `RSP` | Pointeur de pile (Stack Pointer) |
| `RBP` | Pointeur de base de la pile (Base Pointer) |
| `RSI` | Source pour les opérations sur les chaînes |
| `RDI` | Destination pour les opérations sur les chaînes |
| `R8`-`R15` | Registres supplémentaires (x86-64 uniquement) |
| `RIP` | Pointeur d'instruction (adresse de la prochaine instruction) |

Il existe également des **registres spéciaux** (MSR — Model Specific Registers) :

| Registre | Rôle |
|---|---|
| `IA32_LSTAR` | Stocke l'adresse du gestionnaire d'appels système (syscall handler). Quand un programme fait un `syscall`, le CPU saute à cette adresse |
| `CR3` | Contient l'adresse de la table des pages du processus courant |

> **À noter** : le registre `IA32_LSTAR` est une cible de choix pour les rootkits. En modifiant sa valeur, un attaquant peut rediriger tous les appels système vers son propre code.

### 2.4 Communication CPU-Mémoire

Le processeur communique avec la RAM via des **bus** (circuits de communication). Voici le déroulement simplifié d'une opération d'écriture en mémoire :

Exemple : stocker la chaîne `"hello world"` dans une variable.

```python
# Code de haut niveau
message = "hello world"
```

Ce qui se passe au niveau du CPU :

1. La chaîne `"hello world"` est convertie en **octets ASCII** :

```
h=0x68  e=0x65  l=0x6C  l=0x6C  o=0x6F  (espace)=0x20
w=0x77  o=0x6F  r=0x72  l=0x6C  d=0x64
```

2. Le CPU utilise deux registres pour l'opération :
   - **R1** (registre d'adresse) : contient l'adresse mémoire de destination (ex : `0x7FFE0100`)
   - **R2** (registre de données) : contient la valeur à écrire (les octets de la chaîne)

3. Le **bus d'adresses** transporte l'adresse (R1 vers la RAM)
4. Le **bus de données** transporte la valeur (R2 vers la RAM)
5. Le **bus de contrôle** indique l'opération (lecture ou écriture)

```
CPU                          RAM
+--------+    Bus d'adresses    +------------------+
|  R1    |--------------------->| Adresse: 0x7FFE  |
| 0x7FFE |                     |                  |
+--------+    Bus de données    |                  |
|  R2    |--------------------->| Contenu: "hello" |
| "hello"|                     |                  |
+--------+    Bus de contrôle   |                  |
| WRITE  |--------------------->| Opération: WRITE |
+--------+                     +------------------+
```

---

## 3. Contenu de la mémoire d'un processus

### 3.1 Segments mémoire

Lorsqu'un programme s'exécute, sa mémoire est organisée en plusieurs segments :

| Segment | Contenu | Caractéristiques |
|---|---|---|
| **Text** (Code) | Instructions machine du programme | Lecture seule, partagé entre instances |
| **Data** | Variables globales et statiques initialisées | Lecture/écriture |
| **BSS** | Variables globales non initialisées | Initialisé à zéro au démarrage |
| **Heap** (Tas) | Mémoire allouée dynamiquement (`malloc`, `new`) | Croît vers les adresses hautes |
| **Stack** (Pile) | Variables locales, adresses de retour, paramètres de fonctions | Croît vers les adresses basses |

Organisation en mémoire (simplifié) :

```
Adresses hautes
+------------------+
|      Stack       |  <- Variables locales, adresses de retour
|        |         |     Croît vers le bas
|        v         |
+------------------+
|                  |
|  Espace libre    |
|                  |
+------------------+
|        ^         |
|        |         |     Croît vers le haut
|      Heap        |  <- Allocations dynamiques
+------------------+
|      BSS         |  <- Variables globales non initialisées
+------------------+
|      Data        |  <- Variables globales initialisées
+------------------+
|      Text        |  <- Code du programme (instructions)
+------------------+
Adresses basses
```

### 3.2 Bibliothèques partagées (DLL)

En plus de ses propres segments, chaque processus charge des **DLL** (Dynamic Link Libraries) en mémoire. Ces bibliothèques fournissent des fonctions partagées :

```powershell
# Lister les DLL chargées par un processus
Get-Process notepad | Select-Object -ExpandProperty Modules |
    Select-Object ModuleName, FileName, Size |
    Format-Table -AutoSize
```

Exemples de DLL courantes :

| DLL | Rôle |
|---|---|
| `ntdll.dll` | Interface avec le noyau (appels système) |
| `kernel32.dll` | Fonctions de base Windows (fichiers, processus, mémoire) |
| `user32.dll` | Interface graphique (fenêtres, messages) |
| `advapi32.dll` | Fonctions avancées (registre, sécurité, services) |

---

## 4. La mémoire virtuelle

### 4.1 Problèmes résolus par la mémoire virtuelle

Sans mémoire virtuelle, chaque processus accéderait directement à la mémoire physique. Cela poserait trois problèmes majeurs :

| Problème | Description |
|---|---|
| **Crash par manque de mémoire** | Si la RAM est pleine, impossible de lancer un nouveau programme |
| **Corruption de données** | Un programme mal écrit peut écraser les données d'un autre programme en mémoire |
| **Fragmentation** | La mémoire libre se retrouve morcelée en petits blocs inutilisables |

### 4.2 Principe de la mémoire virtuelle

La mémoire virtuelle offre à chaque processus l'illusion de disposer de son propre espace d'adressage **continu** et **isolé** :

- En **32 bits** : chaque processus voit un espace de 4 Go (dont 2 Go pour le processus et 2 Go réservés au noyau)
- En **64 bits** : chaque processus voit un espace de 128 To (configuration par défaut de Windows)

Les adresses utilisées par un processus sont des **adresses virtuelles**, qui sont traduites en adresses physiques (réelles) par le matériel.

```
Processus A                     Processus B
+------------------+            +------------------+
| Adresse virtuelle|            | Adresse virtuelle|
| 0x00400000       |            | 0x00400000       |
| (son propre code)|            | (son propre code)|
+------------------+            +------------------+
        |                               |
        v                               v
   Adresse physique              Adresse physique
   0x1A3F0000                    0x2B710000
   (emplacement réel             (emplacement réel
    en RAM)                       en RAM, différent)
```

> **À noter** : deux processus peuvent utiliser la même adresse virtuelle (ex : `0x00400000`) sans conflit, car elles correspondent à des emplacements physiques différents en RAM.

### 4.3 La table des pages (Page Table)

La traduction des adresses virtuelles en adresses physiques est réalisée par la **table des pages** (Page Table), en collaboration avec le **MMU** (Memory Management Unit) du processeur.

La mémoire est divisée en blocs de taille fixe appelés **pages** :

| Élément | Taille | Description |
|---|---|---|
| Page (virtuelle) | 4 Ko (par défaut) | Bloc dans l'espace virtuel du processus |
| Cadre de page (physique) | 4 Ko | Bloc correspondant en RAM physique |
| Grande page | 2 Mo | Utilisée pour les grandes allocations (performances) |

Fonctionnement :

```
  Adresse virtuelle
  0x00401234
        |
        v
  +------------------+
  | Numéro de page:  |  0x00401 (20 bits supérieurs)
  | Offset dans page:|  0x234   (12 bits inférieurs)
  +------------------+
        |
        v
  +------------------+
  | TABLE DES PAGES  |
  | Page 0x00401 --> |---> Cadre physique 0x1A3F0
  +------------------+
        |
        v
  Adresse physique
  0x1A3F0234
```

Chaque processus possède sa propre table des pages. Le registre CPU **CR3** contient l'adresse de la table des pages du processus en cours d'exécution. Lors d'un changement de contexte (context switch), le noyau met à jour CR3 pour pointer vers la table du nouveau processus.

### 4.4 Le fichier d'échange (Pagefile)

Lorsque la RAM physique est pleine, Windows déplace les pages mémoire les moins utilisées vers le disque dur dans un fichier spécial appelé **pagefile** :

```
C:\pagefile.sys
```

Ce mécanisme est appelé **pagination** (paging) ou **échange mémoire** (memory swapping).

| Concept | Description |
|---|---|
| **Page-out** | Copier une page de la RAM vers le pagefile (libérer de la RAM) |
| **Page-in** (Page fault) | Recharger une page depuis le pagefile vers la RAM |
| **Working Set** | Ensemble des pages d'un processus actuellement en RAM physique |

```
+------------------+          +------------------+
|   RAM physique   |          |   Pagefile       |
|                  |  Page-out|   (disque)       |
|  Pages actives   |--------->|  Pages inactives |
|                  |<---------|                  |
|                  |  Page-in |  C:\pagefile.sys |
+------------------+          +------------------+
```

> **À noter** : le pagefile est beaucoup plus lent que la RAM (facteur 1000 pour un HDD, facteur 10-100 pour un SSD). Une utilisation intensive du pagefile (thrashing) dégrade considérablement les performances. En forensique, le pagefile peut contenir des données sensibles qui ont été déchargées de la RAM.

### 4.5 Configuration du pagefile

```powershell
# Voir la taille actuelle du pagefile
Get-CimInstance Win32_PageFileUsage |
    Select-Object Name, CurrentUsage, AllocatedBaseSize, PeakUsage

# Interface graphique de configuration
SystemPropertiesAdvanced.exe
# > Performance > Paramètres > Avancé > Mémoire virtuelle > Modifier
```

> **Bonne pratique** : en environnement serveur, définir une taille fixe du pagefile (identique pour la taille initiale et maximale) pour éviter la fragmentation du fichier et les variations de performances.

---

## 5. Outils de surveillance mémoire

### 5.1 PowerShell : Get-Process

```powershell
# Afficher l'utilisation mémoire des processus
Get-Process | Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='WorkingSet (Mo)'; Expression={[math]::Round($_.WorkingSet64/1MB,2)}},
        @{Name='Private (Mo)'; Expression={[math]::Round($_.PrivateMemorySize64/1MB,2)}},
        @{Name='Virtual (Mo)'; Expression={[math]::Round($_.VirtualMemorySize64/1MB,2)}} |
    Format-Table -AutoSize
```

Colonnes importantes :

| Propriété | Signification |
|---|---|
| `WorkingSet64` | Pages actuellement en RAM physique |
| `PrivateMemorySize64` | Mémoire privée allouée (non partagée) |
| `VirtualMemorySize64` | Taille totale de l'espace d'adressage virtuel utilisé |

### 5.2 Moniteur de ressources (Resource Monitor)

```powershell
# Ouvrir le Moniteur de ressources
resmon.exe
```

L'onglet **Mémoire** affiche :

- **En cours d'utilisation** : RAM occupée par les processus
- **En attente** : pages en cache, disponibles mais contenant des données
- **Libre** : RAM réellement inutilisée

### 5.3 RAMMap (Sysinternals)

RAMMap offre une vue détaillée de l'allocation de la RAM physique :

```powershell
# Lancer RAMMap
RAMMap.exe
```

Il permet de voir la répartition entre :

- Process Private : mémoire privée des processus
- Mapped File : fichiers mappés en mémoire
- Page Table : espace occupé par les tables des pages
- Driver Locked : mémoire verrouillée par les pilotes
- Nonpaged Pool / Paged Pool : pools mémoire du noyau

---

## 6. Analyse forensique de la mémoire

### 6.1 Pourquoi analyser la mémoire ?

La mémoire vive contient des informations qui n'existent nulle part ailleurs :

- **Mots de passe en clair** (avant chiffrement)
- **Clés de chiffrement** temporaires
- **Code malveillant** injecté (malware fileless)
- **Connexions réseau** actives
- **Historique de commandes** et données de session
- **Processus cachés** (rootkits)

### 6.2 Créer un dump mémoire avec ProcDump

**ProcDump** (Sysinternals) permet de capturer la mémoire d'un processus dans un fichier `.dmp` :

```powershell
# Dump complet de la mémoire d'un processus
procdump.exe -ma <PID> C:\Temp\dump.dmp

# Dump quand le processus dépasse un seuil CPU
procdump.exe -ma -c 90 -s 5 <PID> C:\Temp\dump.dmp

# Dump d'un processus par son nom
procdump.exe -ma notepad.exe C:\Temp\notepad.dmp
```

Options principales :

| Option | Description |
|---|---|
| `-ma` | Dump complet de la mémoire (full dump) |
| `-c` | Seuil CPU déclencheur (en %) |
| `-s` | Durée pendant laquelle le seuil doit être dépassé (en secondes) |
| `-e` | Dump sur exception non gérée |

### 6.3 Analyser un dump avec Strings

L'outil **Strings** (Sysinternals) extrait toutes les chaînes de caractères lisibles d'un fichier binaire, y compris les dumps mémoire :

```powershell
# Extraire les chaînes ASCII et Unicode
strings.exe C:\Temp\dump.dmp > C:\Temp\strings_output.txt

# Rechercher des patterns spécifiques
strings.exe C:\Temp\dump.dmp | findstr /i "password"
strings.exe C:\Temp\dump.dmp | findstr /i "http://"
strings.exe C:\Temp\dump.dmp | findstr /i "SELECT.*FROM"
```

> **Bonne pratique** : lors d'une investigation, toujours capturer la mémoire **avant** d'éteindre la machine. La RAM étant volatile, son contenu est perdu à l'extinction. Utiliser un outil de capture mémoire complète comme **WinPmem** ou **FTK Imager** pour capturer l'intégralité de la RAM du système.

### 6.4 Outils avancés d'analyse mémoire

Pour une analyse forensique approfondie, des outils spécialisés permettent de reconstruire l'état du système à partir d'un dump mémoire complet :

| Outil | Rôle |
|---|---|
| **Volatility** | Framework open source d'analyse de dumps mémoire. Permet de lister les processus, extraire les DLL, retrouver les connexions réseau, etc. |
| **WinDbg** | Débogueur Microsoft pour l'analyse de dumps noyau et utilisateur |
| **Rekall** | Fork de Volatility avec des fonctionnalités supplémentaires |
| **FTK Imager** | Capture mémoire complète (RAM entière) et analyse forensique |

---

## Pour aller plus loin

- [Microsoft — Gestion de la mémoire virtuelle Windows](https://learn.microsoft.com/fr-fr/windows/win32/memory/about-memory-management)
- [Microsoft — Architecture de la mémoire virtuelle](https://learn.microsoft.com/fr-fr/windows-hardware/drivers/gettingstarted/virtual-address-spaces)
- [Sysinternals — RAMMap](https://learn.microsoft.com/fr-fr/sysinternals/downloads/rammap)
- [Sysinternals — ProcDump](https://learn.microsoft.com/fr-fr/sysinternals/downloads/procdump)
- [Volatility Foundation — Framework d'analyse mémoire](https://www.volatilityfoundation.org/)
- [SANS — Memory Forensics Cheat Sheet](https://www.sans.org/posters/memory-forensics-cheat-sheet/)
