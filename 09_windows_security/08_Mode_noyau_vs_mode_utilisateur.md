# Mode noyau et mode utilisateur

**Module** : comprendre l'architecture du noyau Windows et la séparation des privilèges

---

## Objectifs du module

À l'issue de ce module, les compétences suivantes seront acquises :

- Comprendre le rôle du noyau (kernel) comme couche d'abstraction entre le matériel et les applications
- Distinguer les architectures monolithique, micro-noyau et hybride
- Maîtriser le concept des anneaux de protection du processeur (Protection Rings)
- Identifier les composants du mode utilisateur et du mode noyau
- Comprendre le mécanisme des appels système (syscalls) et leur rôle dans la sécurité

---

## 1. Le noyau Windows (kernel)

### 1.1 Rôle du noyau

Le **noyau** (kernel) est le composant central de tout système d'exploitation. Il constitue la couche d'abstraction entre le matériel physique (processeur, mémoire RAM, disques de stockage, périphériques) et les applications.

Sans noyau, chaque application devrait gérer directement le matériel : écrire sur le disque dur secteur par secteur, adresser la mémoire RAM physiquement, communiquer directement avec la carte réseau. Le noyau fournit une interface unifiée et sécurisée pour toutes ces opérations.

Les responsabilités principales du noyau sont :

| Responsabilité | Description |
|---|---|
| **Gestion de la mémoire** | Allouer et protéger la mémoire pour chaque processus (mémoire virtuelle) |
| **Ordonnancement** | Décider quel thread s'exécute sur quel cœur du processeur, et pendant combien de temps |
| **Gestion des E/S** | Coordonner les lectures et écritures sur les disques, le réseau, les périphériques |
| **Sécurité** | Vérifier les permissions et appliquer les contrôles d'accès |
| **Gestion des pilotes** | Fournir une interface pour les pilotes de périphériques |

### 1.2 Types d'architecture de noyau

Il existe deux architectures classiques de noyau, et une troisième qui combine les deux :

| Architecture | Principe | Exemples |
|---|---|---|
| **Monolithique** | Tout le code du noyau (système de fichiers, pilotes, pile réseau, ordonnanceur) s'exécute dans un seul espace mémoire | Linux, macOS (XNU) |
| **Micro-noyau** | Seules les fonctions minimales (ordonnancement, IPC, gestion mémoire de base) sont dans le noyau. Les pilotes et systèmes de fichiers tournent en mode utilisateur | Minix, QNX, L4 |
| **Hybride** | Combine les deux approches : un noyau relativement petit, mais avec des composants supplémentaires en espace noyau pour des raisons de performance | **Windows NT** |

**Windows** est officiellement décrit comme un **micro-noyau** dans sa conception originale (Windows NT, conçu par Dave Cutler en 1993). En pratique, pour des raisons de performance, de nombreux composants ont été réintégrés dans l'espace noyau au fil des versions. On parle donc d'architecture **hybride**.

> **À noter** : le noyau Windows est écrit principalement en **langage C**, avec des portions en assembleur pour les parties les plus proches du matériel (gestion des interruptions, changement de contexte). Le fichier principal du noyau est `C:\Windows\System32\ntoskrnl.exe` (NT Operating System Kernel).

---

## 2. Les anneaux de protection du processeur (Protection Rings)

### 2.1 Principe

Les processeurs modernes (architecture x86/x64) implémentent un mécanisme de sécurité matériel appelé **Protection Rings** (anneaux de protection). Ce mécanisme définit des niveaux de privilège qui déterminent quelles instructions le code en cours d'exécution est autorisé à utiliser.

L'architecture x86 définit quatre anneaux (Ring 0 à Ring 3), mais en pratique, Windows et la plupart des systèmes d'exploitation n'en utilisent que deux :

| Anneau | Nom | Niveau de privilège | Usage |
|---|---|---|---|
| **Ring 0** | Mode noyau (Kernel mode) | Le plus élevé | Noyau, pilotes de périphériques |
| **Ring 1** | - | Élevé | Non utilisé par Windows |
| **Ring 2** | - | Intermédiaire | Non utilisé par Windows |
| **Ring 3** | Mode utilisateur (User mode) | Le plus faible | Applications, processus utilisateur |

Il existe également un niveau encore plus privilégié :

| Anneau | Nom | Usage |
|---|---|---|
| **Ring -1** | Mode hyperviseur | Réservé à l'hyperviseur (Hyper-V, VMware, VirtualBox) pour la virtualisation |
| **Ring -2** | Mode SMM (System Management Mode) | Firmware UEFI/BIOS, opérations de bas niveau du matériel |

### 2.2 Mode utilisateur (Ring 3)

Le **mode utilisateur** est l'environnement dans lequel s'exécutent toutes les applications classiques. Un programme en mode utilisateur :

- Ne peut pas accéder directement au matériel
- Ne peut pas modifier la mémoire d'un autre processus
- Ne peut pas exécuter les instructions processeur privilégiées
- Dispose d'un espace d'adressage virtuel privé et isolé

Si un programme en mode utilisateur tente d'exécuter une instruction interdite, le processeur déclenche une **exception** et le système d'exploitation termine le processus fautif (c'est l'origine des fameux "écrans bleus" lorsque c'est un pilote noyau qui provoque l'erreur).

### 2.3 Mode noyau (Ring 0)

Le **mode noyau** est l'environnement dans lequel s'exécutent le noyau et les pilotes de périphériques. Le code en mode noyau :

- A un accès complet et illimité au matériel
- Peut lire et écrire dans toute la mémoire physique
- Peut exécuter toutes les instructions du processeur
- Partage un espace d'adressage commun avec les autres composants noyau

> **Bonne pratique** : la séparation entre mode utilisateur et mode noyau est le pilier fondamental de la sécurité du système. Si un attaquant parvient à exécuter du code en mode noyau (par exemple via un pilote vulnérable), il obtient un contrôle total sur la machine. C'est pourquoi les rootkits noyau sont les malwares les plus dangereux et les plus difficiles à détecter.

---

## 3. Composants du mode utilisateur

Le mode utilisateur comprend plusieurs catégories de composants :

### 3.1 Vue d'ensemble

| Composant | Rôle | Exemples |
|---|---|---|
| **Processus utilisateur** | Applications lancées par l'utilisateur | `notepad.exe`, `chrome.exe`, `excel.exe` |
| **Processus système** | Processus critiques démarré par le système | `csrss.exe` (Client/Server Runtime), `smss.exe` (Session Manager) |
| **Processus de services** | Services gérés par le SCM | `svchost.exe`, `spoolsv.exe`, `lsass.exe` |
| **Sous-systèmes d'environnement** | Couches de compatibilité avec les API | Sous-système Windows (Win32), WSL (Windows Subsystem for Linux) |
| **NTDLL.DLL** | Interface vers le noyau | Contient les stubs syscall qui déclenchent la transition vers Ring 0 |

### 3.2 Processus système critiques

Certains processus du mode utilisateur sont indispensables au fonctionnement de Windows :

| Processus | Rôle | Conséquence si terminé |
|---|---|---|
| `smss.exe` | Session Manager : initialise les sessions utilisateur | Écran bleu (BSOD) |
| `csrss.exe` | Client/Server Runtime : gère les fenêtres console et l'arrêt du système | Écran bleu (BSOD) |
| `wininit.exe` | Initialise les services au démarrage | Écran bleu (BSOD) |
| `lsass.exe` | Local Security Authority : gère l'authentification et les tokens de sécurité | Écran bleu (BSOD) |
| `winlogon.exe` | Gère la connexion/déconnexion des utilisateurs | Impossible de se connecter |

> **À noter** : `lsass.exe` est une cible privilégiée des attaquants. Des outils comme **Mimikatz** exploitent ce processus pour extraire les mots de passe et les hashes d'authentification stockés en mémoire. C'est pourquoi Windows propose le mécanisme **Credential Guard** (basé sur la virtualisation) pour protéger les secrets gérés par `lsass.exe`.

---

## 4. Composants du mode noyau

### 4.1 Vue d'ensemble

Le mode noyau est composé de quatre couches principales :

```
┌───────────────────────────────────────────────────┐
│                 Mode utilisateur (Ring 3)          │
│  Applications, Services, NTDLL.DLL                │
├───────────────────────────────────────────────────┤
│                 Mode noyau (Ring 0)                │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │          Executive (ntoskrnl.exe)            │  │
│  │  I/O Manager, Memory Manager, Object        │  │
│  │  Manager, Security Reference Monitor,       │  │
│  │  Process Manager, Configuration Manager     │  │
│  ├─────────────────────────────────────────────┤  │
│  │          Pilotes de périphériques            │  │
│  │  Pilotes disque, réseau, USB, graphiques    │  │
│  ├─────────────────────────────────────────────┤  │
│  │       Windowing & Graphics (win32k.sys)      │  │
│  │  Sous-système graphique, GDI, DirectX       │  │
│  ├─────────────────────────────────────────────┤  │
│  │    Hardware Abstraction Layer (hal.dll)       │  │
│  │  Interface uniforme vers le matériel         │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│              Matériel (CPU, RAM, Disques)          │
└───────────────────────────────────────────────────┘
```

### 4.2 L'Executive

L'**Executive** est le cœur fonctionnel du noyau Windows, implémenté dans `ntoskrnl.exe`. Il regroupe les principaux gestionnaires du système :

| Composant | Rôle |
|---|---|
| **I/O Manager** | Gère toutes les entrées/sorties (fichiers, réseau, périphériques) |
| **Memory Manager** | Gère la mémoire virtuelle, la pagination, l'allocation mémoire |
| **Object Manager** | Gère les objets noyau (fichiers, processus, clés de registre, etc.) |
| **Security Reference Monitor (SRM)** | Vérifie les permissions et applique les contrôles d'accès |
| **Process Manager** | Crée et gère les processus et les threads |
| **Configuration Manager** | Gère le registre Windows |
| **Plug and Play Manager** | Détecte et configure les périphériques automatiquement |
| **Power Manager** | Gère les états d'alimentation et la mise en veille |

Ces composants seront étudiés individuellement dans les modules suivants.

### 4.3 Les pilotes de périphériques

Les **pilotes** (drivers) sont des modules de code qui s'exécutent en mode noyau et permettent au système de communiquer avec le matériel. Ils portent l'extension `.sys` et se trouvent généralement dans `C:\Windows\System32\drivers\`.

| Type de pilote | Exemples |
|---|---|
| **Pilotes de périphérique** | Carte graphique, carte réseau, contrôleur disque |
| **Pilotes de système de fichiers** | NTFS (`ntfs.sys`), FAT32 (`fastfat.sys`) |
| **Pilotes de filtrage** | Antivirus, chiffrement de disque, pare-feu |

> **Bonne pratique** : les pilotes s'exécutant en mode noyau, un pilote malveillant ou défectueux peut compromettre l'intégrité du système entier. C'est pourquoi Windows impose la **signature obligatoire des pilotes** (Driver Signature Enforcement) depuis Windows Vista 64 bits. Cette protection peut toutefois être désactivée, ce que font certains attaquants pour charger des rootkits noyau.

### 4.4 Le Hardware Abstraction Layer (HAL)

Le **HAL** (`hal.dll`) est la couche la plus basse du noyau. Il fournit une interface uniforme entre le noyau et le matériel physique, ce qui permet à Windows de fonctionner sur différentes architectures matérielles sans modifier le code du noyau.

---

## 5. Les appels système (syscalls)

### 5.1 Principe

Un **appel système** (system call, ou **syscall**) est le mécanisme par lequel un programme en mode utilisateur (Ring 3) demande un service au noyau (Ring 0). C'est le seul moyen légitime pour un programme de franchir la frontière entre les deux modes.

Pourquoi cette frontière existe-t-elle ? Sans elle, n'importe quel programme pourrait accéder directement au matériel, modifier la mémoire d'un autre processus, ou désactiver les contrôles de sécurité.

### 5.2 Mécanisme détaillé

Prenons un exemple concret : l'utilisateur appuie sur **CTRL+S** dans Microsoft Word pour sauvegarder un document.

Voici la séquence complète des opérations :

```
1. L'utilisateur appuie sur CTRL+S
          │
          ▼
2. Word détecte l'évènement clavier et appelle
   la fonction WriteFile() de kernel32.dll
          │
          ▼
3. kernel32.dll appelle NtWriteFile() dans ntdll.dll
          │
          ▼
4. ntdll.dll place le numéro du syscall dans le
   registre EAX du processeur (ex: 0x0008 pour NtWriteFile)
          │
          ▼
5. ntdll.dll exécute l'instruction processeur SYSCALL
   (ou SYSENTER sur les processeurs plus anciens)
          │
          ▼
6. Le processeur bascule de Ring 3 à Ring 0
   (changement de contexte de sécurité)
          │
          ▼
7. Le noyau consulte la SSDT (System Service Descriptor Table)
   pour trouver la fonction correspondant au numéro du syscall
          │
          ▼
8. Le gestionnaire de syscall du noyau (KiSystemCall64)
   exécute la fonction NtWriteFile dans le noyau
          │
          ▼
9. L'I/O Manager du noyau transmet la demande d'écriture
   au pilote du système de fichiers (ntfs.sys)
          │
          ▼
10. Le pilote écrit les données sur le disque
          │
          ▼
11. Le noyau place le résultat (succès/échec)
    dans le registre EAX
          │
          ▼
12. Le processeur rebascule de Ring 0 à Ring 3
          │
          ▼
13. Le contrôle retourne à Word, qui affiche
    "Document sauvegardé" à l'utilisateur
```

### 5.3 Fichiers clés

| Fichier | Chemin | Rôle dans le mécanisme syscall |
|---|---|---|
| `ntdll.dll` | `C:\Windows\System32\ntdll.dll` | Contient les stubs syscall (côté mode utilisateur). Chaque fonction Nt* prépare les registres et exécute l'instruction SYSCALL |
| `ntoskrnl.exe` | `C:\Windows\System32\ntoskrnl.exe` | Contient les implémentations réelles des syscalls (côté mode noyau), ainsi que la SSDT |

### 5.4 Numéros de syscall

Chaque syscall est identifié par un **numéro unique**. Ce numéro peut changer entre les versions de Windows, ce qui signifie qu'un programme ne doit jamais appeler directement un syscall par son numéro. Il doit toujours passer par `ntdll.dll`, qui connaît les numéros corrects pour la version en cours.

Exemples de numéros de syscall (Windows 10 21H2, 64 bits) :

| Fonction | Numéro syscall |
|---|---|
| `NtCreateFile` | 0x0055 |
| `NtWriteFile` | 0x0008 |
| `NtReadFile` | 0x0006 |
| `NtClose` | 0x000F |
| `NtOpenProcess` | 0x0026 |

> **À noter** : certains malwares avancés utilisent la technique du **direct syscall** : au lieu de passer par `ntdll.dll` (qui peut être surveillée par les antivirus et les EDR), ils appellent directement les numéros de syscall. Cela leur permet de contourner les hooks (interceptions) placés par les solutions de sécurité sur `ntdll.dll`. C'est pourquoi la connaissance des syscalls est importante pour les analystes en sécurité.

### 5.5 La SSDT (System Service Descriptor Table)

La **SSDT** est une table maintenue par le noyau qui fait correspondre chaque numéro de syscall à l'adresse mémoire de la fonction noyau correspondante. Lorsqu'un syscall arrive, le noyau consulte cette table pour savoir quelle fonction exécuter.

Historiquement, les rootkits modifiaient la SSDT pour rediriger les appels système vers leur propre code malveillant (technique dite de **SSDT hooking**). Les versions modernes de Windows empêchent cette modification grâce à **Kernel Patch Protection (PatchGuard)**.

---

## Récapitulatif

| Concept | Définition |
|---|---|
| **Noyau (kernel)** | Couche d'abstraction entre le matériel et les applications, implémenté dans `ntoskrnl.exe` |
| **Ring 0** | Mode noyau, niveau de privilège le plus élevé, accès complet au matériel |
| **Ring 3** | Mode utilisateur, niveau de privilège le plus faible, accès restreint |
| **Ring -1** | Mode hyperviseur, pour la virtualisation |
| **Executive** | Ensemble des gestionnaires du noyau (I/O, mémoire, objets, sécurité, processus) |
| **HAL** | Couche d'abstraction matérielle (`hal.dll`) |
| **Syscall** | Mécanisme de transition de Ring 3 vers Ring 0 |
| **ntdll.dll** | Contient les stubs syscall (côté utilisateur) |
| **ntoskrnl.exe** | Contient les implémentations syscall (côté noyau) |
| **SSDT** | Table de correspondance entre numéros de syscall et fonctions noyau |

---

## Pour aller plus loin

- [Windows Internals, Part 1 (Microsoft Press)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Windows Architecture (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/overview-of-windows-components)
- [System Call in Windows (j00ru/Windows Syscalls)](https://j00ru.vexillium.org/syscalls/nt/64/)
- [Protection Rings Explained (Wikipedia)](https://en.wikipedia.org/wiki/Protection_ring)
- [MITRE ATT&CK - Rootkit (T1014)](https://attack.mitre.org/techniques/T1014/)
- [Kernel Patch Protection (PatchGuard) Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/kernel-patch-protection)
