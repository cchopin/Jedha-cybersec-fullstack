# Mode noyau et mode utilisateur

**Module** : comprendre l'architecture du noyau Windows et la separation des privileges

---

## Objectifs du module

A l'issue de ce module, les competences suivantes seront acquises :

- Comprendre le role du noyau (kernel) comme couche d'abstraction entre le materiel et les applications
- Distinguer les architectures monolithique, micro-noyau et hybride
- Maitriser le concept des anneaux de protection du processeur (Protection Rings)
- Identifier les composants du mode utilisateur et du mode noyau
- Comprendre le mecanisme des appels systeme (syscalls) et leur role dans la securite

---

## 1. Le noyau Windows (kernel)

### 1.1 Role du noyau

Le **noyau** (kernel) est le composant central de tout systeme d'exploitation. Il constitue la couche d'abstraction entre le materiel physique (processeur, memoire RAM, disques de stockage, peripheriques) et les applications.

Sans noyau, chaque application devrait gerer directement le materiel : ecrire sur le disque dur secteur par secteur, adresser la memoire RAM physiquement, communiquer directement avec la carte reseau. Le noyau fournit une interface unifiee et securisee pour toutes ces operations.

Les responsabilites principales du noyau sont :

| Responsabilite | Description |
|---|---|
| **Gestion de la memoire** | Allouer et proteger la memoire pour chaque processus (memoire virtuelle) |
| **Ordonnancement** | Decider quel thread s'execute sur quel coeur du processeur, et pendant combien de temps |
| **Gestion des E/S** | Coordonner les lectures et ecritures sur les disques, le reseau, les peripheriques |
| **Securite** | Verifier les permissions et appliquer les controles d'acces |
| **Gestion des pilotes** | Fournir une interface pour les pilotes de peripheriques |

### 1.2 Types d'architecture de noyau

Il existe deux architectures classiques de noyau, et une troisieme qui combine les deux :

| Architecture | Principe | Exemples |
|---|---|---|
| **Monolithique** | Tout le code du noyau (systeme de fichiers, pilotes, pile reseau, ordonnanceur) s'execute dans un seul espace memoire | Linux, macOS (XNU) |
| **Micro-noyau** | Seules les fonctions minimales (ordonnancement, IPC, gestion memoire de base) sont dans le noyau. Les pilotes et systemes de fichiers tournent en mode utilisateur | Minix, QNX, L4 |
| **Hybride** | Combine les deux approches : un noyau relativement petit, mais avec des composants supplementaires en espace noyau pour des raisons de performance | **Windows NT** |

**Windows** est officiellement decrit comme un **micro-noyau** dans sa conception originale (Windows NT, concu par Dave Cutler en 1993). En pratique, pour des raisons de performance, de nombreux composants ont ete reintegres dans l'espace noyau au fil des versions. On parle donc d'architecture **hybride**.

> **A noter** : le noyau Windows est ecrit principalement en **langage C**, avec des portions en assembleur pour les parties les plus proches du materiel (gestion des interruptions, changement de contexte). Le fichier principal du noyau est `C:\Windows\System32\ntoskrnl.exe` (NT Operating System Kernel).

---

## 2. Les anneaux de protection du processeur (Protection Rings)

### 2.1 Principe

Les processeurs modernes (architecture x86/x64) implementent un mecanisme de securite materiel appele **Protection Rings** (anneaux de protection). Ce mecanisme definit des niveaux de privilege qui determinent quelles instructions le code en cours d'execution est autorise a utiliser.

L'architecture x86 definit quatre anneaux (Ring 0 a Ring 3), mais en pratique, Windows et la plupart des systemes d'exploitation n'en utilisent que deux :

| Anneau | Nom | Niveau de privilege | Usage |
|---|---|---|---|
| **Ring 0** | Mode noyau (Kernel mode) | Le plus eleve | Noyau, pilotes de peripheriques |
| **Ring 1** | - | Eleve | Non utilise par Windows |
| **Ring 2** | - | Intermediaire | Non utilise par Windows |
| **Ring 3** | Mode utilisateur (User mode) | Le plus faible | Applications, processus utilisateur |

Il existe egalement un niveau encore plus privilegie :

| Anneau | Nom | Usage |
|---|---|---|
| **Ring -1** | Mode hyperviseur | Reserve a l'hyperviseur (Hyper-V, VMware, VirtualBox) pour la virtualisation |
| **Ring -2** | Mode SMM (System Management Mode) | Firmware UEFI/BIOS, operations de bas niveau du materiel |

### 2.2 Mode utilisateur (Ring 3)

Le **mode utilisateur** est l'environnement dans lequel s'executent toutes les applications classiques. Un programme en mode utilisateur :

- Ne peut pas acceder directement au materiel
- Ne peut pas modifier la memoire d'un autre processus
- Ne peut pas executer les instructions processeur privilegiees
- Dispose d'un espace d'adressage virtuel prive et isole

Si un programme en mode utilisateur tente d'executer une instruction interdite, le processeur declenche une **exception** et le systeme d'exploitation termine le processus fautif (c'est l'origine des fameux "ecrans bleus" lorsque c'est un pilote noyau qui provoque l'erreur).

### 2.3 Mode noyau (Ring 0)

Le **mode noyau** est l'environnement dans lequel s'executent le noyau et les pilotes de peripheriques. Le code en mode noyau :

- A un acces complet et illimite au materiel
- Peut lire et ecrire dans toute la memoire physique
- Peut executer toutes les instructions du processeur
- Partage un espace d'adressage commun avec les autres composants noyau

> **Bonne pratique** : la separation entre mode utilisateur et mode noyau est le pilier fondamental de la securite du systeme. Si un attaquant parvient a executer du code en mode noyau (par exemple via un pilote vulnerable), il obtient un controle total sur la machine. C'est pourquoi les rootkits noyau sont les malwares les plus dangereux et les plus difficiles a detecter.

---

## 3. Composants du mode utilisateur

Le mode utilisateur comprend plusieurs categories de composants :

### 3.1 Vue d'ensemble

| Composant | Role | Exemples |
|---|---|---|
| **Processus utilisateur** | Applications lancees par l'utilisateur | `notepad.exe`, `chrome.exe`, `excel.exe` |
| **Processus systeme** | Processus critiques demarre par le systeme | `csrss.exe` (Client/Server Runtime), `smss.exe` (Session Manager) |
| **Processus de services** | Services geres par le SCM | `svchost.exe`, `spoolsv.exe`, `lsass.exe` |
| **Sous-systemes d'environnement** | Couches de compatibilite avec les API | Sous-systeme Windows (Win32), WSL (Windows Subsystem for Linux) |
| **NTDLL.DLL** | Interface vers le noyau | Contient les stubs syscall qui declenchent la transition vers Ring 0 |

### 3.2 Processus systeme critiques

Certains processus du mode utilisateur sont indispensables au fonctionnement de Windows :

| Processus | Role | Consequence si termine |
|---|---|---|
| `smss.exe` | Session Manager : initialise les sessions utilisateur | Ecran bleu (BSOD) |
| `csrss.exe` | Client/Server Runtime : gere les fenetres console et l'arret du systeme | Ecran bleu (BSOD) |
| `wininit.exe` | Initialise les services au demarrage | Ecran bleu (BSOD) |
| `lsass.exe` | Local Security Authority : gere l'authentification et les tokens de securite | Ecran bleu (BSOD) |
| `winlogon.exe` | Gere la connexion/deconnexion des utilisateurs | Impossible de se connecter |

> **A noter** : `lsass.exe` est une cible privilegiee des attaquants. Des outils comme **Mimikatz** exploitent ce processus pour extraire les mots de passe et les hashes d'authentification stockes en memoire. C'est pourquoi Windows propose le mecanisme **Credential Guard** (base sur la virtualisation) pour proteger les secrets geres par `lsass.exe`.

---

## 4. Composants du mode noyau

### 4.1 Vue d'ensemble

Le mode noyau est compose de quatre couches principales :

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
│  │          Pilotes de peripheriques            │  │
│  │  Pilotes disque, reseau, USB, graphiques    │  │
│  ├─────────────────────────────────────────────┤  │
│  │       Windowing & Graphics (win32k.sys)      │  │
│  │  Sous-systeme graphique, GDI, DirectX       │  │
│  ├─────────────────────────────────────────────┤  │
│  │    Hardware Abstraction Layer (hal.dll)       │  │
│  │  Interface uniforme vers le materiel         │  │
│  └─────────────────────────────────────────────┘  │
│                                                   │
│              Materiel (CPU, RAM, Disques)          │
└───────────────────────────────────────────────────┘
```

### 4.2 L'Executive

L'**Executive** est le coeur fonctionnel du noyau Windows, implemente dans `ntoskrnl.exe`. Il regroupe les principaux gestionnaires du systeme :

| Composant | Role |
|---|---|
| **I/O Manager** | Gere toutes les entrees/sorties (fichiers, reseau, peripheriques) |
| **Memory Manager** | Gere la memoire virtuelle, la pagination, l'allocation memoire |
| **Object Manager** | Gere les objets noyau (fichiers, processus, cles de registre, etc.) |
| **Security Reference Monitor (SRM)** | Verifie les permissions et applique les controles d'acces |
| **Process Manager** | Cree et gere les processus et les threads |
| **Configuration Manager** | Gere le registre Windows |
| **Plug and Play Manager** | Detecte et configure les peripheriques automatiquement |
| **Power Manager** | Gere les etats d'alimentation et la mise en veille |

Ces composants seront etudies individuellement dans les modules suivants.

### 4.3 Les pilotes de peripheriques

Les **pilotes** (drivers) sont des modules de code qui s'executent en mode noyau et permettent au systeme de communiquer avec le materiel. Ils portent l'extension `.sys` et se trouvent generalement dans `C:\Windows\System32\drivers\`.

| Type de pilote | Exemples |
|---|---|
| **Pilotes de peripherique** | Carte graphique, carte reseau, controleur disque |
| **Pilotes de systeme de fichiers** | NTFS (`ntfs.sys`), FAT32 (`fastfat.sys`) |
| **Pilotes de filtrage** | Antivirus, chiffrement de disque, pare-feu |

> **Bonne pratique** : les pilotes s'executant en mode noyau, un pilote malveillant ou defectueux peut compromettre l'integrite du systeme entier. C'est pourquoi Windows impose la **signature obligatoire des pilotes** (Driver Signature Enforcement) depuis Windows Vista 64 bits. Cette protection peut toutefois etre desactivee, ce que font certains attaquants pour charger des rootkits noyau.

### 4.4 Le Hardware Abstraction Layer (HAL)

Le **HAL** (`hal.dll`) est la couche la plus basse du noyau. Il fournit une interface uniforme entre le noyau et le materiel physique, ce qui permet a Windows de fonctionner sur differentes architectures materielles sans modifier le code du noyau.

---

## 5. Les appels systeme (syscalls)

### 5.1 Principe

Un **appel systeme** (system call, ou **syscall**) est le mecanisme par lequel un programme en mode utilisateur (Ring 3) demande un service au noyau (Ring 0). C'est le seul moyen legitime pour un programme de franchir la frontiere entre les deux modes.

Pourquoi cette frontiere existe-t-elle ? Sans elle, n'importe quel programme pourrait acceder directement au materiel, modifier la memoire d'un autre processus, ou desactiver les controles de securite.

### 5.2 Mecanisme detaille

Prenons un exemple concret : l'utilisateur appuie sur **CTRL+S** dans Microsoft Word pour sauvegarder un document.

Voici la sequence complete des operations :

```
1. L'utilisateur appuie sur CTRL+S
          │
          ▼
2. Word detecte l'evenement clavier et appelle
   la fonction WriteFile() de kernel32.dll
          │
          ▼
3. kernel32.dll appelle NtWriteFile() dans ntdll.dll
          │
          ▼
4. ntdll.dll place le numero du syscall dans le
   registre EAX du processeur (ex: 0x0008 pour NtWriteFile)
          │
          ▼
5. ntdll.dll execute l'instruction processeur SYSCALL
   (ou SYSENTER sur les processeurs plus anciens)
          │
          ▼
6. Le processeur bascule de Ring 3 a Ring 0
   (changement de contexte de securite)
          │
          ▼
7. Le noyau consulte la SSDT (System Service Descriptor Table)
   pour trouver la fonction correspondant au numero du syscall
          │
          ▼
8. Le gestionnaire de syscall du noyau (KiSystemCall64)
   execute la fonction NtWriteFile dans le noyau
          │
          ▼
9. L'I/O Manager du noyau transmet la demande d'ecriture
   au pilote du systeme de fichiers (ntfs.sys)
          │
          ▼
10. Le pilote ecrit les donnees sur le disque
          │
          ▼
11. Le noyau place le resultat (succes/echec)
    dans le registre EAX
          │
          ▼
12. Le processeur rebascule de Ring 0 a Ring 3
          │
          ▼
13. Le controle retourne a Word, qui affiche
    "Document sauvegarde" a l'utilisateur
```

### 5.3 Fichiers cles

| Fichier | Chemin | Role dans le mecanisme syscall |
|---|---|---|
| `ntdll.dll` | `C:\Windows\System32\ntdll.dll` | Contient les stubs syscall (cote mode utilisateur). Chaque fonction Nt* prepare les registres et execute l'instruction SYSCALL |
| `ntoskrnl.exe` | `C:\Windows\System32\ntoskrnl.exe` | Contient les implementations reelles des syscalls (cote mode noyau), ainsi que la SSDT |

### 5.4 Numeros de syscall

Chaque syscall est identifie par un **numero unique**. Ce numero peut changer entre les versions de Windows, ce qui signifie qu'un programme ne doit jamais appeler directement un syscall par son numero. Il doit toujours passer par `ntdll.dll`, qui connait les numeros corrects pour la version en cours.

Exemples de numeros de syscall (Windows 10 21H2, 64 bits) :

| Fonction | Numero syscall |
|---|---|
| `NtCreateFile` | 0x0055 |
| `NtWriteFile` | 0x0008 |
| `NtReadFile` | 0x0006 |
| `NtClose` | 0x000F |
| `NtOpenProcess` | 0x0026 |

> **A noter** : certains malwares avances utilisent la technique du **direct syscall** : au lieu de passer par `ntdll.dll` (qui peut etre surveillee par les antivirus et les EDR), ils appellent directement les numeros de syscall. Cela leur permet de contourner les hooks (interceptions) places par les solutions de securite sur `ntdll.dll`. C'est pourquoi la connaissance des syscalls est importante pour les analystes en securite.

### 5.5 La SSDT (System Service Descriptor Table)

La **SSDT** est une table maintenue par le noyau qui fait correspondre chaque numero de syscall a l'adresse memoire de la fonction noyau correspondante. Lorsqu'un syscall arrive, le noyau consulte cette table pour savoir quelle fonction executer.

Historiquement, les rootkits modifiaient la SSDT pour rediriger les appels systeme vers leur propre code malveillant (technique dite de **SSDT hooking**). Les versions modernes de Windows empechent cette modification grace a **Kernel Patch Protection (PatchGuard)**.

---

## Recapitulatif

| Concept | Definition |
|---|---|
| **Noyau (kernel)** | Couche d'abstraction entre le materiel et les applications, implemente dans `ntoskrnl.exe` |
| **Ring 0** | Mode noyau, niveau de privilege le plus eleve, acces complet au materiel |
| **Ring 3** | Mode utilisateur, niveau de privilege le plus faible, acces restreint |
| **Ring -1** | Mode hyperviseur, pour la virtualisation |
| **Executive** | Ensemble des gestionnaires du noyau (I/O, memoire, objets, securite, processus) |
| **HAL** | Couche d'abstraction materielle (`hal.dll`) |
| **Syscall** | Mecanisme de transition de Ring 3 vers Ring 0 |
| **ntdll.dll** | Contient les stubs syscall (cote utilisateur) |
| **ntoskrnl.exe** | Contient les implementations syscall (cote noyau) |
| **SSDT** | Table de correspondance entre numeros de syscall et fonctions noyau |

---

## Pour aller plus loin

- [Windows Internals, Part 1 (Microsoft Press)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Windows Architecture (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/overview-of-windows-components)
- [System Call in Windows (j00ru/Windows Syscalls)](https://j00ru.vexillium.org/syscalls/nt/64/)
- [Protection Rings Explained (Wikipedia)](https://en.wikipedia.org/wiki/Protection_ring)
- [MITRE ATT&CK - Rootkit (T1014)](https://attack.mitre.org/techniques/T1014/)
- [Kernel Patch Protection (PatchGuard) Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/kernel-patch-protection)
